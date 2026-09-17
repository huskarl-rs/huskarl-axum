//! Common traits and types for working with `huskarl-axum`.
//!
//! ```
//! use huskarl_axum::prelude::*;
//! ```
//!
//! [`TokenFor`] (the state-derived form) and [`ValidatedToken`] are the
//! extractors you name in handler signatures. Traits you *implement*
//! (`HasClaims` on your app state, `HasScopes` on your claims, `ErrorBody`
//! for custom error responses) are exported by name, along with
//! [`ErrorDetails`], the input to `ErrorBody`.

pub use crate::extractors::{HasClaims, TokenFor, ValidatedToken};
pub use crate::layers::{AuthorizationError, HasScopes};
pub use crate::response::{ErrorBody, ErrorDetails};

#[cfg(feature = "login")]
pub use crate::login::{HasSession, LoginSession, SessionFor, SessionTermination};
