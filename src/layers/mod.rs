//! Tower `Layer`/`Service` middleware: access-token validation and
//! authorization enforcement.
//!
//! [`ValidatorLayer`] validates bearer/DPoP/mTLS tokens and injects their
//! claims. Use [`ValidatorLayer::authenticated`] or
//! [`ValidatorLayer::require_scopes`], [`ValidatorLayer::require_audience`], or
//! [`ValidatorLayer::authorize`] for order-safe protection in one layer. The
//! individual enforcement layers remain available for advanced compositions.

use huskarl_resource_server::validator::ValidatedRequest;
use tower::Layer;

pub use require_audience::{RequireAudienceLayer, RequireAudienceService};
pub use require_authenticated::{RequireAuthenticatedLayer, RequireAuthenticatedService};
pub use require_scopes::{HasScopes, RequireScopesLayer, RequireScopesService};
pub use validator::{InvalidBaseUrl, InvalidResourceIdentifier, ValidatorLayer, ValidatorService};

pub use authorize::{AuthorizationError, AuthorizeLayer, AuthorizeService};

mod authorize;
mod require_audience;
mod require_authenticated;
mod require_scopes;
mod validator;

#[cfg(test)]
mod tests;

/// Order-safe composition of token validation and authentication enforcement.
///
/// Construct this with [`ValidatorLayer::authenticated`] or
/// [`ValidatorLayer::with_protected_resource`]. Router placement determines
/// which endpoints it protects; a configured resource URL does not filter paths.
pub struct AuthenticatedLayer<C> {
    validator: ValidatorLayer<C>,
}

impl<C: Send + Sync + 'static> AuthenticatedLayer<C> {
    pub(crate) fn new(validator: ValidatorLayer<C>) -> Self {
        Self { validator }
    }

    /// Requires every supplied scope in addition to authentication and any
    /// configured resource audience binding.
    #[must_use]
    pub fn require_scopes<I, T>(&self, required_scopes: I) -> ScopedLayer<C>
    where
        C: HasScopes,
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        self.validator.require_scopes(required_scopes)
    }

    /// Applies a custom permission check after token and resource audience
    /// validation. Requests without a token are rejected before the check.
    #[must_use]
    pub fn authorize<F>(&self, check: F) -> AuthorizedLayer<C>
    where
        F: Fn(&ValidatedRequest<C>) -> Result<(), AuthorizationError> + Send + Sync + 'static,
    {
        self.validator.authorize(check)
    }
}

impl<C> Clone for AuthenticatedLayer<C> {
    fn clone(&self) -> Self {
        Self {
            validator: self.validator.clone(),
        }
    }
}

impl<C: Send + Sync + 'static, S> Layer<S> for AuthenticatedLayer<C> {
    type Service = ValidatorService<C, RequireAuthenticatedService<S>>;

    fn layer(&self, inner: S) -> Self::Service {
        self.validator
            .layer(self.validator.require_authenticated().layer(inner))
    }
}

/// Order-safe composition of token validation and audience enforcement.
///
/// Construct this with [`ValidatorLayer::require_audience`] or
/// [`ValidatorLayer::require_any_audience`].
pub struct AudienceLayer<C> {
    validator: ValidatorLayer<C>,
    accepted_audiences: Vec<String>,
}

impl<C> AudienceLayer<C> {
    pub(crate) fn new(validator: ValidatorLayer<C>, accepted_audiences: Vec<String>) -> Self {
        Self {
            validator,
            accepted_audiences,
        }
    }
}

impl<C> Clone for AudienceLayer<C> {
    fn clone(&self) -> Self {
        Self {
            validator: self.validator.clone(),
            accepted_audiences: self.accepted_audiences.clone(),
        }
    }
}

impl<C: Send + Sync + 'static, S> Layer<S> for AudienceLayer<C> {
    type Service = ValidatorService<C, RequireAudienceService<C, S>>;

    fn layer(&self, inner: S) -> Self::Service {
        self.validator.layer(
            self.validator
                .audience_layer(self.accepted_audiences.clone())
                .layer(inner),
        )
    }
}

/// Order-safe composition of token validation and a custom authorization
/// check.
///
/// Construct this with [`ValidatorLayer::authorize`]. The check receives the
/// validator's normalized [`ValidatedRequest`],
/// including its issuer and audience fields.
pub struct AuthorizedLayer<C> {
    validator: ValidatorLayer<C>,
    authorization: AuthorizeLayer<C>,
}

impl<C> AuthorizedLayer<C> {
    pub(crate) fn new(validator: ValidatorLayer<C>, authorization: AuthorizeLayer<C>) -> Self {
        Self {
            validator,
            authorization,
        }
    }
}

impl<C> Clone for AuthorizedLayer<C> {
    fn clone(&self) -> Self {
        Self {
            validator: self.validator.clone(),
            authorization: self.authorization.clone(),
        }
    }
}

impl<C, S> Layer<S> for AuthorizedLayer<C> {
    type Service = ValidatorService<C, AuthorizeService<C, S>>;

    fn layer(&self, inner: S) -> Self::Service {
        self.validator.layer(self.authorization.layer(inner))
    }
}

/// Order-safe composition of token validation and scope enforcement.
///
/// Construct this with [`ValidatorLayer::require_scopes`]. The claims type is
/// derived from the validator, preventing a mismatched scope layer.
pub struct ScopedLayer<C> {
    validator: ValidatorLayer<C>,
    required_scopes: Vec<String>,
}

impl<C> ScopedLayer<C> {
    pub(crate) fn new(validator: ValidatorLayer<C>, required_scopes: Vec<String>) -> Self {
        Self {
            validator,
            required_scopes,
        }
    }
}

impl<C> Clone for ScopedLayer<C> {
    fn clone(&self) -> Self {
        Self {
            validator: self.validator.clone(),
            required_scopes: self.required_scopes.clone(),
        }
    }
}

impl<C: HasScopes + Send + Sync + 'static, S> Layer<S> for ScopedLayer<C> {
    type Service = ValidatorService<C, RequireScopesService<C, S>>;

    fn layer(&self, inner: S) -> Self::Service {
        self.validator.layer(
            self.validator
                .scope_layer(self.required_scopes.clone())
                .layer(inner),
        )
    }
}
