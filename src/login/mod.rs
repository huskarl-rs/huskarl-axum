//! OAuth 2.0 Authorization Code Grant login middleware for Axum.
//!
//! [`LoginLayer`] is the convenience bundle — wraps an entire router so every
//! request goes through callback/logout handling, session loading, and an
//! authorize redirect when no session is in scope. For mixed public/protected
//! apps, compose [`LoginRoutesLayer`], [`LoadSessionLayer`], and
//! [`RequireSessionLayer`] yourself via the factory methods on `LoginLayer`.
//!
//! Follow [Sign in to an Axum application](self::tutorial) for a complete
//! browser walkthrough with the runnable `login` example. Before rollout, read
//! [Deploy browser login](self::deployment) for HTTPS, refresh concurrency,
//! session storage, and middleware response-delivery limits.
//! See [Customize authentication error responses](crate::response::guide) for
//! shared login-page rendering and resource-server error bodies.
//!
//! # Quick start (everything protected)
//!
//! ```ignore
//! let login = LoginLayer::builder()
//!     .config(config)
//!     .grant(grant)
//!     .session_store(session_store)
//!     .build()?;
//!
//! let app = Router::new()
//!     .route("/", get(index))
//!     .layer(login);
//!
//! async fn index(session: LoginSession<CookieSession>) -> String {
//!     format!("Hello! Token expires: {:?}", session.token_expiry())
//! }
//! ```
//!
//! # Mixed public/protected
//!
//! ```ignore
//! let login = LoginLayer::builder()/* ... */.build()?;
//!
//! let app = Router::new()
//!     .route("/dashboard", get(dashboard))
//!     .layer(login.require_session())      // gate
//!     .route("/", get(public_home))         // public (sees session if present)
//!     .layer(login.load_session())          // loader
//!     .layer(login.login_routes());         // /callback, /logout
//! ```
//!
//! # Nested routers and reverse proxies
//!
//! Login layers use Axum's `OriginalUri`, preserving all `Router::nest`
//! prefixes. Configure callback and logout paths relative to the application
//! root: for a router nested at `/app`, use `/app/callback` and `/app/logout`.
//! The grant's redirect URI is then `https://example.com/app/callback`.
//! Register the inner Axum routes as `/callback` and `/logout` (or install a
//! fallback) so requests reach the login layer.
//!
//! `LoginConfig::base_path` adds a public prefix removed by a reverse proxy;
//! `strip_prefix` removes a prefix added by that proxy. Neither is needed for
//! Axum nesting itself. For example, if the proxy strips `/gateway`, configure
//! `base_path = "/gateway"` while keeping `callback_path = "/app/callback"`.
//! The public callback and login-state cookie path become
//! `/gateway/app/callback`. Applications that previously used `base_path` to
//! compensate for Axum nesting must instead include that prefix in callback
//! and logout paths.
//!
//! A trusted [`RequestUrl`](crate::extensions::RequestUrl) overrides
//! `OriginalUri`. Its path is passed to the login engine for route matching
//! and the configured `base_path`/`strip_prefix` mapping; keep those settings
//! consistent with the URI supplied by that middleware.
//!
//! # Programmatic session termination
//!
//! An authenticated handler can request termination of its current session
//! without redirecting through the configured browser logout route:
//!
//! ```ignore
//! async fn delete_account(
//!     session: LoginSession<MySession>,
//!     termination: SessionTermination,
//! ) {
//!     delete_account_for(&session).await;
//!     termination.request();
//! }
//! ```
//!
//! After the handler returns, the login middleware clears the browser cookies
//! and attempts server-side revocation. Cookie clearing is preserved even if
//! the backing store cannot be reached.

mod extractors;
mod layer;
mod load_session;
mod login_routes;
mod require_session;

#[cfg(test)]
mod tests;

// ── Re-exports from huskarl-login ───────────────────────────────────────────

pub use huskarl_login::{
    CompletedLogin, ConfigError, CookieSession, CookieSessionStore, DefaultErrorPage,
    DefaultPersistFailurePolicy, ErrorPage, ErrorPageResponse, ExternalSessionStore, LoginConfig,
    LogoutConfig, PersistFailurePolicy, PersistedSession, PersistedSessionState, Session,
    SessionDriver, SessionEnricher, SessionError, SessionLifetime, SessionState,
    StoreBackedSessionStore, TeardownReason,
};

pub use huskarl_login::cookie;
pub use huskarl_login::engine::{
    LoadedSession, LoginEngine, LoginResponse, error_chain, is_cors_preflight,
    is_navigation_request,
};

// ── Axum-specific public API ────────────────────────────────────────────────

pub use extractors::{HasSession, LoginSession, SessionFor, SessionTermination};
pub use layer::{LoginLayer, LoginService};
pub use load_session::{LoadSessionLayer, LoadSessionService, SessionLoadAttempted};
pub use login_routes::{LoginRoutesLayer, LoginRoutesService};
pub use require_session::{RequireSessionLayer, RequireSessionService, UnauthenticatedAction};

/// Sign in, inspect a session, and sign out using the runnable Axum example.
#[cfg(any(doc, doctest))]
#[doc = include_str!("../../docs/tutorial/browser_login.md")]
pub mod tutorial {}

/// Deploy browser login with explicit storage, concurrency, and response-delivery limits.
#[cfg(any(doc, doctest))]
#[doc = include_str!("../../docs/how_to/deployment.md")]
pub mod deployment {}
