//! Axum extractors for the login session.
//!
//! [`LoginSession`] extracts the authenticated session from a request,
//! rejecting with 401 if no session is present. For routes that should
//! handle both authenticated and unauthenticated requests, use
//! `Option<LoginSession<S>>` — backed by the
//! [`OptionalFromRequestParts`] impl below it never rejects, returning
//! `None` when no session is in scope.

use std::convert::Infallible;
use std::ops::Deref;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::SystemTime;

use axum_core::extract::{FromRequestParts, OptionalFromRequestParts};
use axum_core::response::{IntoResponse, Response};
use http::request::Parts;

use huskarl_login::{Session, SessionState};

/// Names the session type for the app's router state — the login analogue of
/// [`HasClaims`](crate::extractors::HasClaims).
///
/// Implement this on your `State` type so handlers can extract
/// [`SessionFor<AppState>`] without naming the concrete session type. Apps
/// without meaningful router state (e.g. everything behind the bundled
/// [`LoginLayer`](super::LoginLayer) on a `Router<()>`) can keep extracting
/// [`LoginSession`] with the session type named directly.
///
/// ```
/// use huskarl_axum::login::{CookieSession, HasSession, SessionFor};
///
/// #[derive(Clone)]
/// struct AppState;
///
/// impl HasSession for AppState {
///     type Session = CookieSession;
/// }
///
/// async fn dashboard(session: SessionFor<AppState>) -> String {
///     format!("Token expires: {:?}", session.token_expiry())
/// }
/// ```
pub trait HasSession: Send + Sync + 'static {
    /// The session type produced by the app's session store.
    type Session: Session + Send + Sync + 'static;
}

/// Forwards to the inner state, so `Arc<MyState>` works as router state
/// without a separate `HasSession` impl.
impl<T: HasSession> HasSession for Arc<T> {
    type Session = T::Session;
}

/// The login-session extractor for a given app state's session type.
///
/// `SessionFor<AppState>` is [`LoginSession`] of `AppState`'s
/// [`HasSession::Session`], so handlers name the state instead of repeating
/// the session type. `Option<SessionFor<AppState>>` never rejects, like the
/// underlying extractor.
pub type SessionFor<S> = LoginSession<<S as HasSession>::Session>;

/// Request-scoped handle for terminating the current login session.
///
/// Extract this alongside [`LoginSession`] and call [`request`](Self::request)
/// after the application operation that should end the session succeeds. The
/// outer [`LoginLayer`](super::LoginLayer) or
/// [`LoadSessionLayer`](super::LoadSessionLayer) observes the request after the
/// handler returns, abandons any pending session save, clears the browser's
/// session cookies, and attempts authoritative server-side revocation.
///
/// Revocation failure does not discard the cookie clears or replace the
/// handler's response; it is logged so the current browser is still signed
/// out. This terminates the current application session only—it does not invoke
/// an `OpenID` Provider end-session endpoint.
///
/// ```ignore
/// async fn delete_account(
///     session: LoginSession<MySession>,
///     termination: SessionTermination,
/// ) {
///     delete_account_for(&session).await;
///     termination.request();
/// }
/// ```
#[derive(Debug, Clone)]
pub struct SessionTermination(Arc<AtomicBool>);

impl SessionTermination {
    pub(crate) fn new() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }

    /// Requests termination of the current session after the handler returns.
    pub fn request(&self) {
        self.0.store(true, Ordering::Release);
    }

    /// Returns whether termination has been requested.
    #[must_use]
    pub fn is_requested(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// Rejects with `401 Unauthorized` when no authenticated session is in scope.
impl<AppState> FromRequestParts<AppState> for SessionTermination
where
    AppState: Send + Sync,
{
    type Rejection = Response;

    #[allow(clippy::unused_async_trait_impl)]
    async fn from_request_parts(
        parts: &mut Parts,
        _state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        parts.extensions.get::<Self>().cloned().ok_or_else(|| {
            let mut response = http::Response::new(axum_core::body::Body::empty());
            *response.status_mut() = http::StatusCode::UNAUTHORIZED;
            response.into_response()
        })
    }
}

/// Supports `Option<SessionTermination>` on routes that also accept anonymous
/// requests.
impl<AppState> OptionalFromRequestParts<AppState> for SessionTermination
where
    AppState: Send + Sync,
{
    type Rejection = Infallible;

    #[allow(clippy::unused_async_trait_impl)]
    async fn from_request_parts(
        parts: &mut Parts,
        _state: &AppState,
    ) -> Result<Option<Self>, Self::Rejection> {
        Ok(parts.extensions.get::<Self>().cloned())
    }
}

/// A read-only session handle for Axum handlers.
///
/// Wraps `Arc<S>` for cheap cloning. Extracted from request extensions where
/// the login middleware inserts it after successful session validation.
///
/// Use this as an extractor in your handlers:
///
/// ```ignore
/// async fn index(session: LoginSession<CookieSession>) -> String {
///     format!("Token expires: {:?}", session.token_expiry())
/// }
/// ```
///
/// For optional session access (never rejects), use `Option<LoginSession<S>>`.
pub struct LoginSession<S>(pub(super) Arc<S>);

impl<S> LoginSession<S> {
    /// Creates a session handle from an owned session.
    ///
    /// This is useful in handler unit tests and in custom session-loading
    /// middleware that inserts the handle into request extensions.
    pub fn new(session: S) -> Self {
        Self(Arc::new(session))
    }

    /// Creates a session handle from an existing shared session.
    #[must_use]
    pub fn from_arc(session: Arc<S>) -> Self {
        Self(session)
    }

    /// Returns the shared session allocation.
    #[must_use]
    pub fn into_arc(self) -> Arc<S> {
        self.0
    }
}

impl<S> From<S> for LoginSession<S> {
    fn from(session: S) -> Self {
        Self::new(session)
    }
}

impl<S> AsRef<S> for LoginSession<S> {
    fn as_ref(&self) -> &S {
        &self.0
    }
}

impl<S> Deref for LoginSession<S> {
    type Target = S;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// Manual Clone impl to avoid requiring `S: Clone` (Arc is always Clone).
impl<S> Clone for LoginSession<S> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<S: Session> LoginSession<S> {
    /// Returns the embedded [`SessionState`].
    #[must_use]
    pub fn state(&self) -> &SessionState {
        self.0.state()
    }

    /// Returns a reference to the underlying session.
    #[must_use]
    pub fn session(&self) -> &S {
        &self.0
    }

    /// Absolute expiry of the access token.
    #[must_use]
    pub fn token_expiry(&self) -> SystemTime {
        self.0.token_expiry()
    }

    /// The refresh token, if present.
    #[must_use]
    pub fn refresh_token(&self) -> Option<&huskarl::token::RefreshToken> {
        self.0.refresh_token()
    }

    /// The ID token, if present.
    #[must_use]
    pub fn id_token(&self) -> Option<&huskarl::token::IdToken> {
        self.0.id_token()
    }

    /// When the session was created.
    #[must_use]
    pub fn created_at(&self) -> SystemTime {
        self.0.created_at()
    }
}

/// Rejects with 401 Unauthorized if no session is present.
impl<S, AppState> FromRequestParts<AppState> for LoginSession<S>
where
    S: Session + Send + Sync + 'static,
    AppState: Send + Sync,
{
    type Rejection = Response;

    #[allow(clippy::unused_async_trait_impl)]
    async fn from_request_parts(
        parts: &mut Parts,
        _state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<LoginSession<S>>()
            .cloned()
            .ok_or_else(|| {
                let mut resp = http::Response::new(axum_core::body::Body::empty());
                *resp.status_mut() = http::StatusCode::UNAUTHORIZED;
                resp.into_response()
            })
    }
}

/// Supports `Option<LoginSession<S>>` as an extractor: returns `Some(session)`
/// when one was loaded into request extensions and `None` otherwise — never
/// rejects.
impl<S, AppState> OptionalFromRequestParts<AppState> for LoginSession<S>
where
    S: Session + Send + Sync + 'static,
    AppState: Send + Sync,
{
    type Rejection = Infallible;

    #[allow(clippy::unused_async_trait_impl)]
    async fn from_request_parts(
        parts: &mut Parts,
        _state: &AppState,
    ) -> Result<Option<Self>, Self::Rejection> {
        Ok(parts.extensions.get::<LoginSession<S>>().cloned())
    }
}
