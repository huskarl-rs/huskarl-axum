//! Tower middleware that bundles the full login flow.
//!
//! [`LoginLayer`] is a convenience that combines login-route handling,
//! session loading, and unauthenticated-redirect into one layer — equivalent
//! to stacking [`LoginRoutesLayer`](super::LoginRoutesLayer),
//! [`LoadSessionLayer`](super::LoadSessionLayer), and
//! [`RequireSessionLayer`](super::RequireSessionLayer). Use the individual
//! layers when you need finer-grained control (e.g. public routes alongside
//! protected ones, or custom login handlers).

use std::{pin::Pin, sync::Arc};

use axum_core::{
    extract::Request,
    response::{IntoResponse, Response},
};
use http::{Uri, request::Parts};
use huskarl::{
    core::crypto::cipher::AeadSealerUnsealer, grant::authorization_code::AuthorizationCodeGrant,
};
use tower::{Layer, Service};

use huskarl_login::{
    DefaultErrorPage, DefaultPersistFailurePolicy, ErrorPage, LoginConfig, PersistFailurePolicy,
    SessionDriver,
    engine::{
        LoadedSession, LoginEngine, LoginResponse, PendingPersist, error_chain, is_cors_preflight,
    },
};

use super::extractors::LoginSession;
use super::{LoadSessionLayer, LoginRoutesLayer, RequireSessionLayer, UnauthenticatedAction};
use crate::extensions::RequestUrl;

// ── Response conversion ──────────────────────────────────────────────────────

pub(super) fn to_response(resp: LoginResponse) -> Response {
    let (status, headers, body) = resp.into_parts();
    let mut response = http::Response::new(axum_core::body::Body::from(body));
    *response.status_mut() = status;
    for (name, value) in headers {
        response.headers_mut().append(name, value);
    }
    response.into_response()
}

pub(super) fn internal_server_error<SD>(engine: &LoginEngine<SD>, message: &str) -> Response
where
    SD: SessionDriver,
{
    to_response(engine.render_error(http::StatusCode::INTERNAL_SERVER_ERROR, message))
}

/// Appends the `Set-Cookie` headers the engine produced (session-cookie
/// updates from an eager refresh, a post-response re-save, or clears for a
/// torn-down session) to the outgoing response.
///
/// When any cookie is appended, the response is forced to
/// `Cache-Control: no-store`: these cookies ride on the *inner handler's*
/// response, which may have been marked cacheable, and a shared cache storing
/// a refreshed session cookie could replay it to another user (RFC 6749 §5.1).
/// The engine already marks its own redirects and error pages `no-store`. When
/// `cookies` is empty (the steady-state authenticated request) the response's
/// own cache headers are left untouched.
pub(super) fn append_set_cookies(response: &mut Response, cookies: Vec<http::HeaderValue>) {
    if cookies.is_empty() {
        return;
    }
    for c in cookies {
        response.headers_mut().append(http::header::SET_COOKIE, c);
    }
    response.headers_mut().insert(
        http::header::CACHE_CONTROL,
        http::HeaderValue::from_static("no-store"),
    );
}

/// The adapter-facing flattening of a [`LoadedSession`]: which session to serve
/// (as a shared handle), the post-response persist still owed, and the
/// `Set-Cookie` headers that must reach the response regardless.
///
/// Exhaustive over every variant, and lossless: `RefreshUnavailable` is kept
/// distinct from an anonymous request (it must serve a retryable error, not a
/// login redirect), and [`LoadedSession::ActivePending`] carries its
/// [`PendingPersist`] forward so the owed save commits through the merge-safe
/// path rather than being dropped.
pub(super) enum Flattened<S> {
    /// No usable session — an anonymous request. `clears` carries any
    /// `Set-Cookie` clears for stale cookies the engine dropped.
    Anonymous {
        /// Clears for the now-stale session cookies (empty when none).
        clears: Vec<http::HeaderValue>,
    },
    /// Authenticated. Serve `session`; if `pending` is `Some`, commit it after
    /// the inner handler responds. `set_cookies` must reach the response.
    Authenticated {
        /// Shared handle to the loaded session, for the request extension.
        session: Arc<S>,
        /// The owed post-response save, present only for a refreshed session
        /// whose eager persist failed.
        pending: Option<PendingPersist<S>>,
        /// Re-sealed session cookies from an eager refresh (empty otherwise).
        set_cookies: Vec<http::HeaderValue>,
    },
    /// The access token expired and its refresh is transiently unavailable:
    /// authentication can be neither confirmed nor refuted right now. Serve a
    /// retryable error — never treat the request as anonymous.
    RefreshUnavailable,
}

/// Flattens a [`LoadedSession`] into a [`Flattened`] outcome the adapter can
/// act on without re-matching every variant. Exhaustive and lossless — see
/// [`Flattened`].
pub(super) fn flatten_loaded<S>(loaded: LoadedSession<S>) -> Flattened<S> {
    match loaded {
        LoadedSession::Missing => Flattened::Anonymous { clears: Vec::new() },
        LoadedSession::Cleared { clears, .. } => Flattened::Anonymous {
            clears: clears.into_headers(),
        },
        LoadedSession::Active {
            session,
            set_cookies,
        } => Flattened::Authenticated {
            session: Arc::new(session),
            pending: None,
            set_cookies: set_cookies.into_headers(),
        },
        // Serve a shared handle to the pending session while keeping the
        // `PendingPersist` itself for the post-response commit; the commit
        // works on its own copy (`Arc::make_mut`) if a handler stashed one.
        LoadedSession::ActivePending { pending } => Flattened::Authenticated {
            session: pending.session_arc(),
            pending: Some(pending),
            set_cookies: Vec::new(),
        },
        LoadedSession::RefreshUnavailable => Flattened::RefreshUnavailable,
    }
}

/// Returns the URI the engine should treat as the request URL.
///
/// Honours [`RequestUrl`] — the contract for outer middleware sitting behind a
/// reverse proxy — and falls back to the on-the-wire `parts.uri` when absent.
pub(super) fn effective_uri(parts: &Parts) -> Uri {
    parts
        .extensions
        .get::<RequestUrl>()
        .map(|r| r.0.clone())
        .unwrap_or_else(|| parts.uri.clone())
}

/// How [`load_session_and_serve`] answers a request with no session in scope —
/// the one behavioural difference between the bundled [`LoginLayer`] and a
/// bare [`LoadSessionLayer`](super::LoadSessionLayer).
pub(super) enum AnonymousBehavior {
    /// Run the inner service without a session — [`LoadSessionLayer`]'s
    /// contract (loading never gates; stack a
    /// [`RequireSessionLayer`](super::RequireSessionLayer) inside to gate).
    PassThrough,
    /// Redirect to the authorization server to begin login — the bundled
    /// [`LoginLayer`]'s "everything protected" default.
    RedirectToLogin,
}

/// The session-serving path shared by [`LoginService`] and
/// [`LoadSessionService`](super::LoadSessionService).
///
/// Marks the load as attempted, loads the session, and — when one is in
/// scope — injects it as a [`LoginSession`] extension, runs `inner`, appends
/// the owed `Set-Cookie` headers, and commits any pending post-response
/// persist through `persist_failure_policy`. A load failure answers 500, and
/// [`Flattened::RefreshUnavailable`] answers a retryable 503; anonymous
/// requests follow `anonymous`.
pub(super) async fn load_session_and_serve<SD, S>(
    engine: &LoginEngine<SD>,
    persist_failure_policy: &dyn PersistFailurePolicy,
    anonymous: AnonymousBehavior,
    req: Request,
    inner: &mut S,
) -> Result<Response, S::Error>
where
    SD: SessionDriver,
    // `PendingPersist::commit` on the owed save requires an owned session.
    SD::SessionType: Clone,
    S: Service<Request, Response = Response>,
{
    let (mut parts, body) = req.into_parts();
    parts.extensions.insert(super::SessionLoadAttempted);

    let loaded = match engine.load_session(&parts.headers).await {
        Ok(l) => l,
        Err(e) => {
            log::error!("failed to load session: {}", error_chain(&e));
            return Ok(internal_server_error(engine, "failed to load session"));
        }
    };

    let (session, pending, set_cookies) = match flatten_loaded(loaded) {
        Flattened::RefreshUnavailable => {
            return Ok(to_response(engine.render_error(
                http::StatusCode::SERVICE_UNAVAILABLE,
                "session refresh temporarily unavailable",
            )));
        }
        Flattened::Anonymous { clears } => {
            let mut response = match anonymous {
                AnonymousBehavior::PassThrough => {
                    inner.call(Request::from_parts(parts, body)).await?
                }
                AnonymousBehavior::RedirectToLogin => {
                    let uri = effective_uri(&parts);
                    to_response(engine.redirect_to_login(&parts.headers, &uri).await)
                }
            };
            append_set_cookies(&mut response, clears);
            return Ok(response);
        }
        Flattened::Authenticated {
            session,
            pending,
            set_cookies,
        } => (session, pending, set_cookies),
    };

    parts.extensions.insert(LoginSession(session));

    let request_headers = parts.headers.clone();
    let mut response = inner.call(Request::from_parts(parts, body)).await?;
    append_set_cookies(&mut response, set_cookies);

    let Some(pending) = pending else {
        return Ok(response);
    };
    match pending.commit(engine, &request_headers).await {
        Ok(cookies) => {
            append_set_cookies(&mut response, cookies.into_headers());
            Ok(response)
        }
        Err(e) => {
            log::error!("failed to persist session: {}", error_chain(&e));
            Ok(match persist_failure_policy.handle(&e) {
                Some(replacement) => to_response(replacement),
                None => response,
            })
        }
    }
}

// ── LoginLayer ───────────────────────────────────────────────────────────────

/// Bundled Tower [`Layer`] for the OAuth 2.0 Authorization Code Grant.
///
/// Wraps a router so that every request goes through login-route handling,
/// session loading, and (for non-authenticated requests) an authorize
/// redirect — preserving the "everything is protected" default. For
/// per-route public/protected composition, use the individual layers
/// exposed by [`load_session`](Self::load_session),
/// [`login_routes`](Self::login_routes), and
/// [`require_session`](Self::require_session).
///
/// ```ignore
/// let login = LoginLayer::builder()
///     .config(config)
///     .grant(grant)
///     .session_store(session_store)
///     .cipher(cipher)
///     .build();
/// ```
pub struct LoginLayer<SD> {
    engine: Arc<LoginEngine<SD>>,
    persist_failure_policy: Arc<dyn PersistFailurePolicy>,
}

#[bon::bon]
impl<SD> LoginLayer<SD>
where
    SD: SessionDriver,
{
    /// Creates a new `LoginLayer`.
    ///
    /// The `grant` drives the OAuth flow (PAR, JAR, `DPoP`, PKCE) from its own
    /// configuration and carries its own HTTP client.
    ///
    /// `cipher` is the cipher for the short-lived login-state cookie (CSRF
    /// protection during the flow) — a *separate* concern from session
    /// persistence, which the session store handles with its own cipher. It is
    /// **optional**: when omitted it defaults to the session store's cipher,
    /// which is the common single-key setup (the two seals are AAD-domain-
    /// separated, so sharing one key is safe). Pass it explicitly only to use a
    /// distinct key for login-state vs. sessions — e.g. a KMS-backed
    /// login-state key alongside a local per-request session key.
    #[builder]
    pub fn new(
        config: LoginConfig,
        grant: AuthorizationCodeGrant,
        session_store: SD,
        #[builder(with = |cipher: impl AeadSealerUnsealer + 'static| Arc::new(cipher) as Arc<dyn AeadSealerUnsealer>)]
        sealer: Arc<dyn AeadSealerUnsealer>,
        /// Custom error page renderer. Defaults to [`DefaultErrorPage`].
        #[builder(default = Box::new(DefaultErrorPage) as Box<dyn ErrorPage>)]
        error_page: Box<dyn ErrorPage>,
        /// Policy for responding when session persistence fails after the
        /// inner handler has run. Defaults to [`DefaultPersistFailurePolicy`].
        #[builder(default = Arc::new(DefaultPersistFailurePolicy) as Arc<dyn PersistFailurePolicy>)]
        persist_failure_policy: Arc<dyn PersistFailurePolicy>,
    ) -> Self {
        // An omitted login-state cipher defaults to the store's own inside
        // `LoginEngine::builder()` (the seals are AAD-domain-separated), so the
        // adapter just forwards the optional cipher through.
        let engine = LoginEngine::builder()
            .config(config)
            .grant(grant)
            .session_store(session_store)
            .sealer(sealer)
            .error_page(error_page)
            .build();
        Self {
            engine: Arc::new(engine),
            persist_failure_policy,
        }
    }
}

impl<SD> LoginLayer<SD> {
    /// Layer that handles `/callback` and `/logout` only. Pass-through for
    /// every other path.
    pub fn login_routes(&self) -> LoginRoutesLayer<SD> {
        LoginRoutesLayer::new(self.engine.clone())
    }

    /// Layer that loads and persists the session if a cookie is present.
    /// Never redirects on absence — for that, stack a
    /// [`RequireSessionLayer`] inside.
    pub fn load_session(&self) -> LoadSessionLayer<SD> {
        LoadSessionLayer::new(self.engine.clone(), self.persist_failure_policy.clone())
    }

    /// Layer that gates inner routes on an authenticated session. Returns
    /// 302 (navigation) or 401 (XHR) when no session is in scope.
    pub fn require_session(&self) -> RequireSessionLayer<SD> {
        RequireSessionLayer::new(self.engine.clone(), UnauthenticatedAction::LoginOrReject)
    }

    /// Like [`require_session`](Self::require_session) but configurable.
    pub fn require_session_with(&self, action: UnauthenticatedAction) -> RequireSessionLayer<SD> {
        RequireSessionLayer::new(self.engine.clone(), action)
    }
}

impl<SD> Clone for LoginLayer<SD> {
    fn clone(&self) -> Self {
        Self {
            engine: self.engine.clone(),
            persist_failure_policy: self.persist_failure_policy.clone(),
        }
    }
}

impl<SD, S> Layer<S> for LoginLayer<SD>
where
    SD: SessionDriver + 'static,
    S: Clone,
{
    type Service = LoginService<SD, S>;

    fn layer(&self, inner: S) -> Self::Service {
        LoginService {
            inner,
            engine: self.engine.clone(),
            persist_failure_policy: self.persist_failure_policy.clone(),
        }
    }
}

// ── LoginService ─────────────────────────────────────────────────────────────

/// The Tower [`Service`] produced by [`LoginLayer`].
///
/// Handles the login routes, loads the session, runs the inner handler, then
/// redirects unauthenticated requests to begin login.
pub struct LoginService<SD, S> {
    inner: S,
    engine: Arc<LoginEngine<SD>>,
    persist_failure_policy: Arc<dyn PersistFailurePolicy>,
}

impl<SD, S: Clone> Clone for LoginService<SD, S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            engine: self.engine.clone(),
            persist_failure_policy: self.persist_failure_policy.clone(),
        }
    }
}

impl<SD, S> Service<Request> for LoginService<SD, S>
where
    SD: SessionDriver + 'static,
    // `PendingPersist::commit` on the owed save requires an owned session.
    SD::SessionType: Clone,
    S: Service<Request, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request) -> Self::Future {
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let engine = self.engine.clone();
        let persist_failure_policy = self.persist_failure_policy.clone();

        Box::pin(async move {
            if is_cors_preflight(req.method(), req.headers()) {
                return inner.call(req).await;
            }

            let (parts, body) = req.into_parts();
            let uri = effective_uri(&parts);

            if let Some(resp) = engine
                .try_handle_login_route(&parts.method, &parts.headers, &uri)
                .await
            {
                return Ok(to_response(resp));
            }

            load_session_and_serve(
                &engine,
                persist_failure_policy.as_ref(),
                AnonymousBehavior::RedirectToLogin,
                Request::from_parts(parts, body),
                &mut inner,
            )
            .await
        })
    }
}
