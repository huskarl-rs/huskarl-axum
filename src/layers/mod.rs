//! Tower `Layer`/`Service` middleware: access-token validation and
//! authorization enforcement.
//!
//! [`ValidatorLayer`] validates bearer/DPoP/mTLS tokens and injects their
//! claims. Use [`ValidatorLayer::authenticated`] or
//! [`ValidatorLayer::require_scopes`], [`ValidatorLayer::require_audience`], or
//! [`ValidatorLayer::authorize`] for order-safe protection in one layer. The
//! individual enforcement layers remain available for advanced compositions.

use huskarl_resource_server::validator::{
    AccessTokenValidator, metadata::ProvideValidatorMetadata,
};
use tower::Layer;

pub use require_audience::{RequireAudienceLayer, RequireAudienceService};
pub use require_authenticated::{RequireAuthenticatedLayer, RequireAuthenticatedService};
pub use require_scopes::{HasScopes, RequireScopesLayer, RequireScopesService};
pub use validator::{InvalidBaseUrl, InvalidResourceIdentifier, ValidatorLayer, ValidatorService};

pub use authorize::{AuthorizationError, AuthorizeLayer, AuthorizeService};

use crate::response::ErrorBody;

mod authorize;
mod require_audience;
mod require_authenticated;
mod require_scopes;
mod validator;

#[cfg(test)]
mod tests;

/// Order-safe composition of token validation and authentication enforcement.
///
/// Construct this with [`ValidatorLayer::authenticated`].
pub struct AuthenticatedLayer<V: ProvideValidatorMetadata, E: ErrorBody = ()> {
    validator: ValidatorLayer<V, E>,
}

impl<V: ProvideValidatorMetadata, E: ErrorBody> AuthenticatedLayer<V, E> {
    pub(crate) fn new(validator: ValidatorLayer<V, E>) -> Self {
        Self { validator }
    }
}

impl<V: ProvideValidatorMetadata, E: ErrorBody> Clone for AuthenticatedLayer<V, E> {
    fn clone(&self) -> Self {
        Self {
            validator: self.validator.clone(),
        }
    }
}

impl<V, E, S> Layer<S> for AuthenticatedLayer<V, E>
where
    V: AccessTokenValidator + ProvideValidatorMetadata,
    E: ErrorBody,
    S: Clone,
{
    type Service = ValidatorService<V, E, RequireAuthenticatedService<E, S>>;

    fn layer(&self, inner: S) -> Self::Service {
        self.validator
            .layer(self.validator.require_authenticated().layer(inner))
    }
}

/// Order-safe composition of token validation and audience enforcement.
///
/// Construct this with [`ValidatorLayer::require_audience`] or
/// [`ValidatorLayer::require_any_audience`].
pub struct AudienceLayer<V: ProvideValidatorMetadata, E: ErrorBody = ()> {
    validator: ValidatorLayer<V, E>,
    accepted_audiences: Vec<String>,
}

impl<V: ProvideValidatorMetadata, E: ErrorBody> AudienceLayer<V, E> {
    pub(crate) fn new(validator: ValidatorLayer<V, E>, accepted_audiences: Vec<String>) -> Self {
        Self {
            validator,
            accepted_audiences,
        }
    }
}

impl<V: ProvideValidatorMetadata, E: ErrorBody> Clone for AudienceLayer<V, E> {
    fn clone(&self) -> Self {
        Self {
            validator: self.validator.clone(),
            accepted_audiences: self.accepted_audiences.clone(),
        }
    }
}

impl<V, E, S> Layer<S> for AudienceLayer<V, E>
where
    V: AccessTokenValidator + ProvideValidatorMetadata,
    E: ErrorBody,
    S: Clone,
{
    type Service = ValidatorService<V, E, RequireAudienceService<V::Claims, E, S>>;

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
/// validator's normalized [`ValidatedRequest`](huskarl_resource_server::validator::ValidatedRequest),
/// including its issuer and audience fields.
pub struct AuthorizedLayer<V: AccessTokenValidator + ProvideValidatorMetadata, F, E: ErrorBody = ()>
{
    validator: ValidatorLayer<V, E>,
    authorization: AuthorizeLayer<V::Claims, F, E>,
}

impl<V: AccessTokenValidator + ProvideValidatorMetadata, F, E: ErrorBody> AuthorizedLayer<V, F, E> {
    pub(crate) fn new(
        validator: ValidatorLayer<V, E>,
        authorization: AuthorizeLayer<V::Claims, F, E>,
    ) -> Self {
        Self {
            validator,
            authorization,
        }
    }
}

impl<V: AccessTokenValidator + ProvideValidatorMetadata, F, E: ErrorBody> Clone
    for AuthorizedLayer<V, F, E>
{
    fn clone(&self) -> Self {
        Self {
            validator: self.validator.clone(),
            authorization: self.authorization.clone(),
        }
    }
}

impl<V, F, E, S> Layer<S> for AuthorizedLayer<V, F, E>
where
    V: AccessTokenValidator + ProvideValidatorMetadata,
    F: Fn(
            &huskarl_resource_server::validator::ValidatedRequest<V::Claims>,
        ) -> Result<(), AuthorizationError>
        + Send
        + Sync
        + 'static,
    E: ErrorBody,
    S: Clone,
{
    type Service = ValidatorService<V, E, AuthorizeService<V::Claims, F, E, S>>;

    fn layer(&self, inner: S) -> Self::Service {
        self.validator.layer(self.authorization.layer(inner))
    }
}

/// Order-safe composition of token validation and scope enforcement.
///
/// Construct this with [`ValidatorLayer::require_scopes`]. The claims type is
/// derived from the validator, preventing a mismatched scope layer.
pub struct ScopedLayer<V: ProvideValidatorMetadata, E: ErrorBody = ()> {
    validator: ValidatorLayer<V, E>,
    required_scopes: Vec<String>,
}

impl<V: ProvideValidatorMetadata, E: ErrorBody> ScopedLayer<V, E> {
    pub(crate) fn new(validator: ValidatorLayer<V, E>, required_scopes: Vec<String>) -> Self {
        Self {
            validator,
            required_scopes,
        }
    }
}

impl<V: ProvideValidatorMetadata, E: ErrorBody> Clone for ScopedLayer<V, E> {
    fn clone(&self) -> Self {
        Self {
            validator: self.validator.clone(),
            required_scopes: self.required_scopes.clone(),
        }
    }
}

impl<V, E, S> Layer<S> for ScopedLayer<V, E>
where
    V: AccessTokenValidator + ProvideValidatorMetadata,
    V::Claims: HasScopes,
    E: ErrorBody,
    S: Clone,
{
    type Service = ValidatorService<V, E, RequireScopesService<V::Claims, E, S>>;

    fn layer(&self, inner: S) -> Self::Service {
        self.validator.layer(
            self.validator
                .scope_layer(self.required_scopes.clone())
                .layer(inner),
        )
    }
}
