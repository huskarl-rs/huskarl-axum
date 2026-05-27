//! OAuth 2.0 Authorization Code Grant login middleware for Axum.
//!
//! [`LoginLayer`] is the convenience bundle — wraps an entire router so every
//! request goes through callback/logout handling, session loading, and an
//! authorize redirect when no session is in scope. For mixed public/protected
//! apps, compose [`LoginRoutesLayer`], [`LoadSessionLayer`], and
//! [`RequireSessionLayer`] yourself via the factory methods on `LoginLayer`.
//!
//! # Quick start (everything protected)
//!
//! ```ignore
//! let login = LoginLayer::builder()
//!     .config(config)
//!     .grant(grant)
//!     .session_store(session_store)
//!     .build();
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
//! let login = LoginLayer::builder()/* ... */.build();
//!
//! let app = Router::new()
//!     .route("/dashboard", get(dashboard))
//!     .layer(login.require_session())      // gate
//!     .route("/", get(public_home))         // public (sees session if present)
//!     .layer(login.load_session())          // loader
//!     .layer(login.login_routes());         // /callback, /logout
//! ```

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
    LogoutConfig, PersistFailurePolicy, Session, SessionDriver, SessionError, SessionLifetime,
    SessionState, StoreBackedSessionStore, TeardownReason,
};

pub use huskarl_login::cookie;
pub use huskarl_login::engine::{
    LoadedSession, LoginEngine, LoginResponse, error_chain, is_cors_preflight,
    is_navigation_request,
};

// ── Axum-specific public API ────────────────────────────────────────────────

pub use extractors::{HasSession, LoginSession, SessionFor};
pub use layer::{LoginLayer, LoginService};
pub use load_session::{LoadSessionLayer, LoadSessionService, SessionLoadAttempted};
pub use login_routes::{LoginRoutesLayer, LoginRoutesService};
pub use require_session::{RequireSessionLayer, RequireSessionService, UnauthenticatedAction};
