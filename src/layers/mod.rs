//! Tower `Layer`/`Service` middleware: access-token validation and scope
//! enforcement.
//!
//! [`ValidatorLayer`] validates the bearer/DPoP/mTLS token and injects the
//! claims; scope-enforcement layers ([`RequireScopesLayer`]) must nest *inside*
//! it. Use [`ValidatorLayer::claims_context_for`] (compiler-checked against
//! the app state's claims type) or [`ValidatorLayer::claims_context`] to
//! bridge from the validator layer to typed scope middleware.

use std::marker::PhantomData;

pub use require_authenticated::{RequireAuthenticatedLayer, RequireAuthenticatedService};
pub use require_scopes::{HasScopes, RequireScopesLayer, RequireScopesService};
pub use validator::{ValidatorLayer, ValidatorService};

use crate::response::ErrorBody;

mod require_authenticated;
mod require_scopes;
mod validator;

#[cfg(test)]
mod tests;

/// A typed bridge from a [`ValidatorLayer`] to scope-enforcement middleware.
///
/// Returned by [`ValidatorLayer::claims_context_for`] (compiler-checked) and
/// [`ValidatorLayer::claims_context`]; binds the claims type `C` so scopes are
/// read from the right type, and carries the layer's configured [`ErrorBody`]
/// into [`require_scopes`](Self::require_scopes) — so validator failures and
/// scope failures render their bodies the same way.
pub struct ClaimsContext<C, E: ErrorBody = ()> {
    pub(crate) error_body: Option<E>,
    pub(crate) phantom: PhantomData<C>,
}

impl<C, E: ErrorBody> ClaimsContext<C, E> {
    /// Builds a [`RequireScopesLayer`] requiring every scope in
    /// `required_scopes` (AND-combined).
    pub fn require_scopes(&self, required_scopes: Vec<String>) -> RequireScopesLayer<C, E>
    where
        C: HasScopes,
    {
        RequireScopesLayer::with_options(required_scopes, self.error_body.clone())
    }
}
