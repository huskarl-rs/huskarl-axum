//! Integration tests for the axum login adapter.
//!
//! These drive the Tower services the login layers produce — session loading,
//! gating, persistence, and route handling — against a mock `SessionDriver`.
//! The OAuth flow itself (callback exchange, token refresh, expiry policy) is
//! covered by `huskarl-login`'s engine tests; here we verify the axum wiring:
//! that `LoadedSession` is threaded through Tower correctly, that the session
//! reaches the handler, that persistence runs after the response, and that the
//! `Set-Cookie` headers (and their `Cache-Control: no-store`) reach the client.

// Test fixtures unwrap freely on known-good inputs; the crate-wide
// `deny(clippy::unwrap_used)` is a production-code policy.
#![allow(clippy::unwrap_used)]

use std::{
    convert::Infallible,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime},
};

use axum_core::{body::Body, extract::Request, response::Response};
use bytes::Bytes;
use http::{HeaderValue, StatusCode, header};
use huskarl::{
    core::{
        Error, RetryAdvice,
        client_auth::NoAuth,
        crypto::seal::{AeadSealerUnsealer, AeadV1Sealer},
        http::{HttpClient, HttpResponse, Idempotency},
        jwk::OctBytes,
        platform::MaybeSendBoxFuture,
        secrets::{Secret, SecretBytes, SecretOutput, SecretString},
    },
    grant::authorization_code::AuthorizationCodeGrant,
    token::RefreshToken,
};
use huskarl_crypto_native::aead::AesGcmKey;
use huskarl_login::{
    CompletedLogin, ConfigError, DefaultPersistFailurePolicy, DriverLoad, LoginConfig,
    LogoutConfig, PersistFailurePolicy, Session, SessionDriver, SessionError, SessionErrorKind,
    SessionLifetime, SessionPolicy, SessionState, engine::LoginEngine,
};
use tower::{Layer, Service, ServiceExt};

use super::extractors::LoginSession;
use super::{
    LoadSessionLayer, LoginLayer, LoginRoutesLayer, RequireSessionLayer, SessionLoadAttempted,
    SessionTermination, UnauthenticatedAction,
};

// ── Mock session ──────────────────────────────────────────────────────────

#[derive(Clone)]
struct MockSession {
    state: SessionState,
}

impl Session for MockSession {
    fn state(&self) -> &SessionState {
        &self.state
    }
    fn set_state(&mut self, state: SessionState) {
        self.state = state;
    }
}

/// A session whose access token is valid for another hour and which holds no
/// refresh token, so `load_session` returns it as `Active` with nothing owed
/// after the handler (the steady-state authenticated request).
fn fresh_session() -> MockSession {
    let now = SystemTime::now();
    MockSession {
        state: SessionState::builder()
            .token_expiry(now + Duration::from_hours(1))
            .created_at(now)
            .build(),
    }
}

#[test]
fn login_session_can_be_constructed_for_custom_middleware_and_tests() {
    let session = LoginSession::new(fresh_session());
    assert_eq!(session.token_expiry(), session.state().token_expiry);

    let shared = session.clone().into_arc();
    assert!(Arc::ptr_eq(
        &shared,
        &LoginSession::from_arc(shared.clone()).into_arc()
    ));
}

/// A session whose access token expired a minute ago and which holds a refresh
/// token — so `load_session` enters the refresh path. With a working token
/// endpoint the refresh succeeds; whether the result is `Active` or
/// `ActivePending` then depends on whether the eager save succeeds.
fn refreshable_session() -> MockSession {
    let now = SystemTime::now();
    MockSession {
        state: SessionState::builder()
            .token_expiry(now - Duration::from_mins(1))
            .refresh_token(RefreshToken::new(SecretString::new("test_refresh"), None))
            .created_at(now)
            .build(),
    }
}

// ── Mock session store ────────────────────────────────────────────────────

struct MockStore {
    load: Mutex<Option<MockSession>>,
    save_calls: AtomicUsize,
    revoke_calls: AtomicUsize,
    /// When set, the first `save` (the engine's eager refresh persist) fails,
    /// forcing `load_session` to return `ActivePending`; the second `save`
    /// (the adapter's post-response persist) then succeeds. This is the only
    /// path that yields an owed post-response save now.
    fail_first_save: bool,
    fail_revoke: bool,
    /// `Set-Cookie` values returned by a successful `save`, used to exercise the
    /// post-persist header path (including the no-store cache fix).
    persist_cookies: Vec<HeaderValue>,
    clear_cookies: Vec<HeaderValue>,
}

impl MockStore {
    fn new(session: Option<MockSession>) -> Self {
        Self {
            load: Mutex::new(session),
            save_calls: AtomicUsize::new(0),
            revoke_calls: AtomicUsize::new(0),
            fail_first_save: false,
            fail_revoke: false,
            persist_cookies: Vec::new(),
            clear_cookies: Vec::new(),
        }
    }

    /// A store whose eager save fails once (→ `ActivePending`) and whose
    /// post-response save then succeeds, returning `cookies`.
    fn deferred_save(session: MockSession, cookies: Vec<HeaderValue>) -> Self {
        let mut s = Self::new(Some(session));
        s.fail_first_save = true;
        s.persist_cookies = cookies;
        s
    }

    fn save_count(&self) -> usize {
        self.save_calls.load(Ordering::Relaxed)
    }

    fn with_termination(mut self, fail_revoke: bool) -> Self {
        self.fail_revoke = fail_revoke;
        self.clear_cookies = vec![HeaderValue::from_static(
            "__Host-session=; Secure; HttpOnly; Path=/; Max-Age=0",
        )];
        self
    }

    fn revoke_count(&self) -> usize {
        self.revoke_calls.load(Ordering::Relaxed)
    }
}

impl huskarl_login::session::sealed::Sealed for MockStore {}

#[allow(clippy::unused_async_trait_impl)]
impl SessionDriver for MockStore {
    type SessionType = MockSession;
    type LoadError = Infallible;

    fn apply_session_policy(&mut self, _: &SessionPolicy) -> Result<(), ConfigError> {
        Ok(())
    }

    fn session_sealer(&self) -> Arc<dyn AeadSealerUnsealer> {
        unimplemented!("tests always configure an explicit login-state sealer")
    }

    fn clear_session_cookies(&self, _: &http::HeaderMap) -> Vec<HeaderValue> {
        self.clear_cookies.clone()
    }

    fn strip_session_credentials(&self, _headers: &mut http::HeaderMap) {}

    async fn create(
        &self,
        _: CompletedLogin,
        _: Duration,
        _: &http::HeaderMap,
    ) -> Result<(MockSession, Vec<HeaderValue>), SessionError> {
        unimplemented!("callback exchange is covered by engine tests")
    }

    async fn load(&self, _: &http::HeaderMap) -> Result<DriverLoad<MockSession>, Infallible> {
        Ok(self
            .load
            .lock()
            .unwrap()
            .clone()
            .map_or(DriverLoad::Absent, DriverLoad::Valid))
    }

    async fn save(
        &self,
        _: &MockSession,
        _: &http::HeaderMap,
    ) -> Result<Vec<HeaderValue>, SessionError> {
        let n = self.save_calls.fetch_add(1, Ordering::Relaxed);
        if self.fail_first_save && n == 0 {
            return Err(SessionError::new(
                SessionErrorKind::Unavailable,
                "eager save failed",
            ));
        }
        Ok(self.persist_cookies.clone())
    }

    async fn revoke(&self, _: &MockSession) -> Result<(), SessionError> {
        self.revoke_calls.fetch_add(1, Ordering::Relaxed);
        if self.fail_revoke {
            Err(SessionError::new(
                SessionErrorKind::Unavailable,
                "revoke failed",
            ))
        } else {
            Ok(())
        }
    }
}

// ── Fixtures ──────────────────────────────────────────────────────────────

#[derive(Clone)]
struct TestSecret(SecretBytes);

impl Secret for TestSecret {
    type Output = SecretBytes;
    fn get_secret_value(&self) -> MaybeSendBoxFuture<'_, Result<SecretOutput<SecretBytes>, Error>> {
        let out = SecretOutput {
            value: self.0.clone(),
            identity: None,
        };
        Box::pin(async move { Ok(out) })
    }
}

async fn test_sealer() -> impl AeadSealerUnsealer {
    AeadV1Sealer::new(
        AesGcmKey::from_secret(
            TestSecret(SecretBytes::new(vec![0u8; 32])).mapped(OctBytes::new("A256GCM")),
        )
        .await
        .unwrap(),
    )
}

/// HTTP double for the token endpoint. `redirect_to_login` (direct delivery)
/// makes no HTTP call; the only requests this sees are refresh-token grants,
/// which it answers with a fresh access token so the refresh path succeeds.
struct MockHttpClient;

impl HttpClient for MockHttpClient {
    fn execute(
        &self,
        _: http::Request<Bytes>,
        _: Idempotency,
    ) -> MaybeSendBoxFuture<'_, Result<HttpResponse, Error>> {
        Box::pin(async {
            let mut headers = http::HeaderMap::new();
            headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            Ok(HttpResponse {
                status: StatusCode::OK,
                headers,
                body: Bytes::from_static(
                    br#"{"access_token":"at","token_type":"Bearer","expires_in":3600}"#,
                ),
            })
        })
    }
}

/// Token-endpoint double whose every call fails with a *retryable* transport
/// error. Drives the refresh path past its retries to a transient failure, so
/// an expired-but-refreshable session surfaces as
/// [`LoadedSession::RefreshUnavailable`](huskarl_login::engine::LoadedSession::RefreshUnavailable)
/// rather than being torn down.
struct RefreshUnavailableClient;

impl HttpClient for RefreshUnavailableClient {
    fn execute(
        &self,
        _: http::Request<Bytes>,
        _: Idempotency,
    ) -> MaybeSendBoxFuture<'_, Result<HttpResponse, Error>> {
        Box::pin(async { Err(Error::new(RetryAdvice::RETRY, "transport unavailable")) })
    }
}

/// A real `AuthorizationCodeGrant` over `client`. `start()` (used by
/// `redirect_to_login`) performs no HTTP with direct delivery; refresh-token
/// grants hit the supplied client.
async fn test_grant_with(client: impl HttpClient + 'static) -> AuthorizationCodeGrant {
    AuthorizationCodeGrant::builder()
        .client_id("client")
        .http_client(client)
        .client_auth(NoAuth)
        .token_endpoint("https://auth.example.com/token".parse().unwrap())
        .authorization_endpoint("https://auth.example.com/authorize".parse().unwrap())
        .redirect_uri("https://app.example.com/callback")
        .build()
        .await
        .unwrap()
}

/// A grant over the always-succeeding [`MockHttpClient`].
async fn test_grant() -> AuthorizationCodeGrant {
    test_grant_with(MockHttpClient).await
}

fn config() -> LoginConfig {
    LoginConfig::builder()
        .callback_path("/callback")
        .scope(bon::vec![])
        .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
        .build()
        .unwrap()
}

fn config_with_logout() -> LoginConfig {
    LoginConfig::builder()
        .callback_path("/callback")
        .scope(bon::vec![])
        .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
        .logout(LogoutConfig::builder().path("/logout").build().unwrap())
        .build()
        .unwrap()
}

async fn engine(store: MockStore) -> Arc<LoginEngine<MockStore>> {
    engine_with_config(store, config()).await
}

async fn engine_with_config(store: MockStore, cfg: LoginConfig) -> Arc<LoginEngine<MockStore>> {
    engine_with_grant(store, cfg, test_grant().await).await
}

async fn engine_with_grant(
    store: MockStore,
    cfg: LoginConfig,
    grant: AuthorizationCodeGrant,
) -> Arc<LoginEngine<MockStore>> {
    Arc::new(
        LoginEngine::builder()
            .config(cfg)
            .grant(grant)
            .session_store(store)
            .sealer(test_sealer().await)
            .build()
            .unwrap(),
    )
}

fn policy() -> Arc<dyn PersistFailurePolicy> {
    Arc::new(DefaultPersistFailurePolicy)
}

// ── Inner handler double ──────────────────────────────────────────────────

/// A stand-in inner service: records whether a [`LoginSession`] reached the
/// handler, and returns `200` with an optional `Cache-Control` so tests can
/// assert the adapter's caching behavior.
#[derive(Clone)]
struct Inner {
    saw_session: Arc<AtomicBool>,
    calls: Arc<AtomicUsize>,
    cache_control: Option<&'static str>,
}

impl Inner {
    fn new() -> Self {
        Self {
            saw_session: Arc::new(AtomicBool::new(false)),
            calls: Arc::new(AtomicUsize::new(0)),
            cache_control: None,
        }
    }
    fn cacheable() -> Self {
        Self {
            saw_session: Arc::new(AtomicBool::new(false)),
            calls: Arc::new(AtomicUsize::new(0)),
            cache_control: Some("max-age=600"),
        }
    }
    fn saw_session(&self) -> bool {
        self.saw_session.load(Ordering::Relaxed)
    }

    fn call_count(&self) -> usize {
        self.calls.load(Ordering::Relaxed)
    }
}

impl Service<Request> for Inner {
    type Response = Response;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Response, Infallible>> + Send>>;

    fn poll_ready(
        &mut self,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Infallible>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request) -> Self::Future {
        let saw = self.saw_session.clone();
        let calls = self.calls.clone();
        let cc = self.cache_control;
        Box::pin(async move {
            calls.fetch_add(1, Ordering::Relaxed);
            if req
                .extensions()
                .get::<LoginSession<MockSession>>()
                .is_some()
            {
                saw.store(true, Ordering::Relaxed);
            }
            let mut builder = http::Response::builder().status(StatusCode::OK);
            if let Some(cc) = cc {
                builder = builder.header(header::CACHE_CONTROL, cc);
            }
            Ok(builder.body(Body::empty()).unwrap())
        })
    }
}

fn req(method: &str, uri: &str, extra: &[(&str, &str)]) -> Request {
    let mut b = http::Request::builder().method(method).uri(uri);
    for (k, v) in extra {
        b = b.header(*k, *v);
    }
    b.body(Body::empty()).unwrap()
}

/// A request as it looks after `LoadSessionLayer` ran but found no session —
/// the marker is present, the session is not. Used to drive
/// `RequireSessionLayer` standalone without stacking a real loader.
fn loaded_req(method: &str, uri: &str, extra: &[(&str, &str)]) -> Request {
    let mut request = req(method, uri, extra);
    request.extensions_mut().insert(SessionLoadAttempted);
    request
}

async fn terminate_current_session(termination: SessionTermination) -> StatusCode {
    termination.request();
    StatusCode::ACCEPTED
}

// ── LoadSessionLayer ──────────────────────────────────────────────────────

#[tokio::test]
async fn load_session_injects_session_and_forwards() {
    let eng = engine(MockStore::new(Some(fresh_session()))).await;
    let inner = Inner::new();
    let svc = LoadSessionLayer::new(eng.clone(), policy()).layer(inner.clone());

    let resp = svc.oneshot(req("GET", "/", &[])).await.unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        inner.saw_session(),
        "handler must see the loaded LoginSession"
    );
}

#[tokio::test]
async fn load_session_absent_passes_through_without_session() {
    let eng = engine(MockStore::new(None)).await;
    let inner = Inner::new();
    let svc = LoadSessionLayer::new(eng.clone(), policy()).layer(inner.clone());

    let resp = svc.oneshot(req("GET", "/", &[])).await.unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        !inner.saw_session(),
        "no session present, none should be injected"
    );
}

#[tokio::test]
async fn active_pending_persists_after_handler() {
    // Refresh succeeds but the engine's eager save fails → `ActivePending`.
    // The adapter must run the inner handler, then retry the save once
    // post-response (two save calls total: the failed eager one + this retry).
    let store = MockStore::deferred_save(refreshable_session(), Vec::new());
    let eng = engine(store).await;
    let svc = LoadSessionLayer::new(eng.clone(), policy()).layer(Inner::new());

    let resp = svc.oneshot(req("GET", "/", &[])).await.unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        eng.session_store().save_count(),
        2,
        "eager save failed → owes one post-response persist",
    );
}

// `start_paused` fast-forwards the refresh retry backoff so the test doesn't
// sleep through it in real time.
#[tokio::test(start_paused = true)]
async fn refresh_unavailable_serves_503_and_retains_session() {
    // Access token expired, refresh token present, but the token endpoint is
    // transiently down. The refresh can be neither confirmed nor refuted, so
    // the adapter must serve a retryable 503 — not run the handler, not tear
    // the session down — leaving it to resume on a later request.
    let store = MockStore::new(Some(refreshable_session()));
    let eng = engine_with_grant(
        store,
        config(),
        test_grant_with(RefreshUnavailableClient).await,
    )
    .await;
    let inner = Inner::new();
    let svc = LoadSessionLayer::new(eng.clone(), policy()).layer(inner.clone());

    let resp = svc.oneshot(req("GET", "/", &[])).await.unwrap();

    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        !inner.saw_session(),
        "the inner handler must not run when refresh is unavailable",
    );
    assert!(
        resp.headers().get(header::SET_COOKIE).is_none(),
        "the session is retained, so no cookie clears are emitted",
    );
    assert_eq!(
        eng.session_store().save_count(),
        0,
        "a transient refresh failure persists nothing",
    );
}

#[tokio::test]
async fn persisted_session_cookie_forces_no_store() {
    // The post-response persist returns a re-emitted session cookie. Riding on a
    // handler response the upstream marked cacheable, it must force `no-store`
    // (RFC 6749 §5.1) so a shared cache can't store and replay it to another user.
    let cookie = HeaderValue::from_static("__Host-session.0=abc; Secure; HttpOnly; Path=/");
    let store = MockStore::deferred_save(refreshable_session(), vec![cookie]);
    let eng = engine(store).await;
    let svc = LoadSessionLayer::new(eng.clone(), policy()).layer(Inner::cacheable());

    let resp = svc.oneshot(req("GET", "/", &[])).await.unwrap();

    assert_eq!(eng.session_store().save_count(), 2);
    assert!(
        resp.headers().get(header::SET_COOKIE).is_some(),
        "the persist's Set-Cookie must reach the response",
    );
    assert_eq!(
        resp.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store",
        "a session Set-Cookie must override the handler's cache header",
    );
}

#[tokio::test]
async fn steady_state_request_preserves_handler_cache_control() {
    // Fresh session: nothing owed, no session cookie emitted — the handler's
    // own cache header must be left untouched.
    let eng = engine(MockStore::new(Some(fresh_session()))).await;
    let svc = LoadSessionLayer::new(eng.clone(), policy()).layer(Inner::cacheable());

    let resp = svc.oneshot(req("GET", "/", &[])).await.unwrap();

    assert_eq!(eng.session_store().save_count(), 0);
    assert!(resp.headers().get(header::SET_COOKIE).is_none());
    assert_eq!(
        resp.headers().get(header::CACHE_CONTROL).unwrap(),
        "max-age=600",
        "no session cookie appended → keep the handler's cache header",
    );
}

#[tokio::test]
async fn programmatic_termination_revokes_session_and_clears_browser_cookie() {
    use axum::{Router, routing::post};

    let store = MockStore::new(Some(fresh_session())).with_termination(false);
    let engine = engine(store).await;
    let app = Router::new()
        .route("/", post(terminate_current_session))
        .layer(LoadSessionLayer::new(engine.clone(), policy()));

    let response = app.oneshot(req("POST", "/", &[])).await.unwrap();

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(engine.session_store().revoke_count(), 1);
    assert_eq!(
        response.headers()[header::SET_COOKIE],
        "__Host-session=; Secure; HttpOnly; Path=/; Max-Age=0"
    );
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
}

#[tokio::test]
async fn programmatic_termination_preserves_response_and_clears_when_revoke_fails() {
    use axum::{Router, routing::post};

    let store = MockStore::new(Some(fresh_session())).with_termination(true);
    let engine = engine(store).await;
    let app = Router::new()
        .route("/", post(terminate_current_session))
        .layer(LoadSessionLayer::new(engine.clone(), policy()));

    let response = app.oneshot(req("POST", "/", &[])).await.unwrap();

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(engine.session_store().revoke_count(), 1);
    assert_eq!(
        response.headers()[header::SET_COOKIE],
        "__Host-session=; Secure; HttpOnly; Path=/; Max-Age=0"
    );
}

#[tokio::test]
async fn programmatic_termination_abandons_pending_refresh_persist() {
    use axum::{Router, routing::post};

    let store = MockStore::deferred_save(refreshable_session(), Vec::new()).with_termination(false);
    let engine = engine(store).await;
    let app = Router::new()
        .route("/", post(terminate_current_session))
        .layer(LoadSessionLayer::new(engine.clone(), policy()));

    let response = app.oneshot(req("POST", "/", &[])).await.unwrap();

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(engine.session_store().revoke_count(), 1);
    assert_eq!(
        engine.session_store().save_count(),
        1,
        "the failed eager save must not be retried after termination"
    );
}

// ── RequireSessionLayer ───────────────────────────────────────────────────

#[tokio::test]
async fn require_session_rejects_without_session() {
    let eng = engine(MockStore::new(None)).await;
    let svc =
        RequireSessionLayer::new(eng.clone(), UnauthenticatedAction::Reject).layer(Inner::new());

    let resp = svc
        .oneshot(loaded_req("GET", "/dashboard", &[]))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn require_session_without_loader_fails_closed() {
    // No LoadSessionLayer ran (no SessionLoadAttempted marker): the gate must
    // fail closed with 500 rather than redirect — without a loader no request
    // could ever carry a session, so LoginOrReject would send every request
    // to the authorization server in an endless login loop.
    let eng = engine(MockStore::new(None)).await;
    let inner = Inner::new();
    let svc = RequireSessionLayer::new(eng.clone(), UnauthenticatedAction::LoginOrReject)
        .layer(inner.clone());

    let resp = svc
        .oneshot(req("GET", "/dashboard", &[("sec-fetch-mode", "navigate")]))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(!inner.saw_session());
}

#[tokio::test]
async fn require_session_passes_when_session_in_extensions() {
    let eng = engine(MockStore::new(None)).await;
    let inner = Inner::new();
    let svc =
        RequireSessionLayer::new(eng.clone(), UnauthenticatedAction::Reject).layer(inner.clone());

    let mut request = req("GET", "/dashboard", &[]);
    request
        .extensions_mut()
        .insert(LoginSession(Arc::new(fresh_session())));
    let resp = svc.oneshot(request).await.unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert!(inner.saw_session());
}

#[tokio::test]
async fn require_session_navigation_redirects_to_authorization_server() {
    let eng = engine(MockStore::new(None)).await;
    let svc = RequireSessionLayer::new(eng.clone(), UnauthenticatedAction::LoginOrReject)
        .layer(Inner::new());

    let resp = svc
        .oneshot(loaded_req(
            "GET",
            "/dashboard",
            &[("sec-fetch-mode", "navigate")],
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::FOUND);
    let loc = resp
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        loc.starts_with("https://auth.example.com/authorize"),
        "navigation should redirect to the AS, got {loc}",
    );
}

#[tokio::test]
async fn require_session_xhr_returns_401() {
    let eng = engine(MockStore::new(None)).await;
    let svc = RequireSessionLayer::new(eng.clone(), UnauthenticatedAction::LoginOrReject)
        .layer(Inner::new());

    let resp = svc
        .oneshot(loaded_req("GET", "/api", &[("accept", "application/json")]))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn require_session_passes_cors_preflight_without_a_loaded_session() {
    let eng = engine(MockStore::new(None)).await;
    let inner = Inner::new();
    let svc =
        RequireSessionLayer::new(eng, UnauthenticatedAction::LoginOrReject).layer(inner.clone());

    let response = svc
        .oneshot(req(
            "OPTIONS",
            "/api",
            &[
                ("origin", "https://client.example"),
                ("access-control-request-method", "GET"),
            ],
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(inner.call_count(), 1);
}

#[tokio::test]
async fn cors_preflight_passthrough_can_be_disabled() {
    let login = LoginLayer::builder()
        .config(config())
        .grant(test_grant().await)
        .session_store(MockStore::new(None))
        .sealer(test_sealer().await)
        .cors_passthrough(false)
        .build()
        .unwrap();
    let inner = Inner::new();
    let service = login.layer(inner.clone());

    let response = service
        .oneshot(req(
            "OPTIONS",
            "/api",
            &[
                ("origin", "https://client.example"),
                ("access-control-request-method", "GET"),
            ],
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(inner.call_count(), 0);
}

#[tokio::test]
async fn cors_preflight_setting_propagates_to_component_layers() {
    let login = LoginLayer::builder()
        .config(config())
        .grant(test_grant().await)
        .session_store(MockStore::new(Some(fresh_session())))
        .sealer(test_sealer().await)
        .cors_passthrough(false)
        .build()
        .unwrap();
    let preflight = || {
        req(
            "OPTIONS",
            "/api",
            &[
                ("origin", "https://client.example"),
                ("access-control-request-method", "GET"),
            ],
        )
    };

    let load_inner = Inner::new();
    let response = login
        .load_session()
        .layer(load_inner.clone())
        .oneshot(preflight())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        load_inner.saw_session(),
        "disabled passthrough must run session loading"
    );

    let gate_inner = Inner::new();
    let mut request = preflight();
    request.extensions_mut().insert(SessionLoadAttempted);
    let response = login
        .require_session_with(UnauthenticatedAction::Reject)
        .layer(gate_inner.clone())
        .oneshot(request)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(gate_inner.call_count(), 0);
}

// ── LoginRoutesLayer ──────────────────────────────────────────────────────

#[tokio::test]
async fn login_routes_handles_callback_without_reaching_inner() {
    let eng = engine(MockStore::new(None)).await;
    let inner = Inner::new();
    let svc = LoginRoutesLayer::new(eng.clone()).layer(inner.clone());

    // Missing code/state → engine answers 400; the inner handler never runs.
    let resp = svc.oneshot(req("GET", "/callback", &[])).await.unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(!inner.saw_session());
}

#[tokio::test]
async fn login_routes_passes_through_unrelated_paths() {
    let eng = engine(MockStore::new(None)).await;
    let svc = LoginRoutesLayer::new(eng.clone()).layer(Inner::new());

    let resp = svc.oneshot(req("GET", "/other", &[])).await.unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn login_routes_logout_is_post_only() {
    let eng = engine_with_config(MockStore::new(Some(fresh_session())), config_with_logout()).await;
    let layer = LoginRoutesLayer::new(eng.clone());

    // POST is accepted → 303 See Other to the post-logout target (pins the
    // follow-up request to GET).
    let post = layer
        .layer(Inner::new())
        .oneshot(req(
            "POST",
            "/logout",
            &[("origin", "https://app.example.com")],
        ))
        .await
        .unwrap();
    assert_eq!(post.status(), StatusCode::SEE_OTHER);

    // GET is rejected → 405 advertising the allowed method.
    let get = layer
        .layer(Inner::new())
        .oneshot(req("GET", "/logout", &[]))
        .await
        .unwrap();
    assert_eq!(get.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(get.headers().get(header::ALLOW).unwrap(), "POST");
}

// ── End-to-end: bundled LoginLayer on a real axum Router ──────────────────

#[tokio::test]
async fn end_to_end_bundle_protects_router_and_extracts_session() {
    use axum::{Router, body::to_bytes, routing::get};

    // A handler that uses the `LoginSession` extractor — its success proves the
    // bundle injected the session *and* the axum `FromRequestParts` impl read it.
    async fn protected(session: LoginSession<MockSession>) -> String {
        format!("expires={:?}", session.token_expiry())
    }

    // Authenticated: the whole composition (login routes → load → require →
    // handler) runs and the extractor resolves the session → 200.
    let login = LoginLayer::builder()
        .config(config())
        .grant(test_grant().await)
        .session_store(MockStore::new(Some(fresh_session())))
        .sealer(test_sealer().await)
        .build()
        .unwrap();
    let app = Router::new().route("/", get(protected)).layer(login);

    let resp = app.oneshot(req("GET", "/", &[])).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    assert!(
        body.starts_with(b"expires="),
        "the protected handler must run with the extracted session",
    );

    // Unauthenticated navigation: the bundle gates with a 302 to the AS before
    // the handler is ever reached — the "everything protected" default.
    let login = LoginLayer::builder()
        .config(config())
        .grant(test_grant().await)
        .session_store(MockStore::new(None))
        .sealer(test_sealer().await)
        .build()
        .unwrap();
    let app = Router::new().route("/", get(protected)).layer(login);

    let resp = app
        .oneshot(req("GET", "/", &[("sec-fetch-mode", "navigate")]))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FOUND);
    assert!(
        resp.headers().get(header::LOCATION).is_some(),
        "gated navigation must redirect to the authorization server",
    );
}

/// Exercise both the bundled and composed login layers inside two nests,
/// including the actual sealed return URL and browser cookie scope.
#[tokio::test]
async fn nested_login_preserves_routes_and_return_url() {
    use axum::{Router, routing::get};
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use huskarl::core::crypto::seal::AeadUnsealer as _;

    #[derive(serde::Deserialize)]
    struct LoginState {
        original_url: String,
    }

    for bundled in [false, true] {
        for proxy_prefix in [None, Some("/gateway")] {
            let cfg = LoginConfig::builder()
                .callback_path("/app/v1/callback")
                .scope(vec![])
                .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
                .maybe_base_path(proxy_prefix.map(str::to_owned))
                .logout(
                    LogoutConfig::builder()
                        .path("/app/v1/logout")
                        .build()
                        .unwrap(),
                )
                .build()
                .unwrap();
            let prefix = proxy_prefix.unwrap_or("");
            let redirect_uri = format!("https://app.example.com{prefix}/app/v1/callback");
            let grant = AuthorizationCodeGrant::builder()
                .client_id("client")
                .http_client(MockHttpClient)
                .client_auth(NoAuth)
                .token_endpoint("https://auth.example.com/token".parse().unwrap())
                .authorization_endpoint("https://auth.example.com/authorize".parse().unwrap())
                .redirect_uri(redirect_uri.clone())
                .build()
                .await
                .unwrap();
            let login = LoginLayer::builder()
                .config(cfg)
                .grant(grant)
                .session_store(MockStore::new(None))
                .sealer(test_sealer().await)
                .build()
                .unwrap();
            let inner = Router::new()
                .route("/dashboard", get(|| async { "dashboard" }))
                .route("/callback", get(|| async { "missed callback" }))
                .route("/logout", get(|| async { "missed logout" }));
            let inner = if bundled {
                inner.layer(login)
            } else {
                inner
                    .layer(login.require_session())
                    .layer(login.load_session())
                    .layer(login.login_routes())
            };
            let app = Router::new().nest("/app", Router::new().nest("/v1", inner));
            let response = app
                .clone()
                .oneshot(req("GET", "/app/v1/callback", &[]))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            let response = app
                .clone()
                .oneshot(req("GET", "/app/v1/logout", &[]))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
            assert_eq!(response.headers()[header::ALLOW], "POST");

            let response = app
                .oneshot(req(
                    "GET",
                    "/app/v1/dashboard?tab=one%20two",
                    &[("sec-fetch-mode", "navigate")],
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::FOUND);
            let location =
                url::Url::parse(response.headers()[header::LOCATION].to_str().unwrap()).unwrap();
            let params: std::collections::HashMap<_, _> = location.query_pairs().collect();
            assert_eq!(params["redirect_uri"], redirect_uri);
            let state = &params["state"];
            let cookie = response.headers()[header::SET_COOKIE].to_str().unwrap();
            assert!(
                cookie.contains(&format!("Path={prefix}/app/v1/callback;")),
                "{cookie}"
            );
            let (_, value) = cookie.split(';').next().unwrap().split_once('=').unwrap();
            let bundle = URL_SAFE_NO_PAD.decode(value).unwrap();
            let plaintext = test_sealer()
                .await
                .unseal(&bundle, format!("login_state:{state}").as_bytes(), None)
                .await
                .unwrap();
            let saved: LoginState = ciborium::from_reader(plaintext.as_slice()).unwrap();
            assert_eq!(
                saved.original_url,
                format!("https://app.example.com{prefix}/app/v1/dashboard?tab=one%20two")
            );
        }
    }
}

#[tokio::test]
async fn nested_login_honours_request_url_override() {
    use crate::extensions::RequestUrl;
    use axum::{Router, routing::get};

    let eng = engine(MockStore::new(None)).await;
    let inner = Router::new()
        .route("/callback", get(|| async { "missed callback" }))
        .layer(LoginRoutesLayer::new(eng));
    let app = Router::new().nest("/app", inner);
    let mut request = req("GET", "/app/callback", &[]);
    request.extensions_mut().insert(RequestUrl(
        "https://app.example.com/callback".parse().unwrap(),
    ));
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
