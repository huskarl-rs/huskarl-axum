use std::{marker::PhantomData, pin::Pin, sync::Arc};

use axum_core::{
    extract::Request,
    response::{IntoResponse, Response},
};
use http::StatusCode;
use huskarl_resource_server::{
    error::{Challenge, TokenErrorCode, TokenValidationError},
    validator::ValidatedRequest,
};
use tower::{Layer, Service};

use crate::extensions::ValidatorData;
use crate::extractors::ValidatedToken;
use crate::layers::validator::{FailureDetails, challenge_response};
use crate::response::ErrorBody;

/// A denial returned by a custom authorization check.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthorizationError {
    /// The token is valid but does not grant access to this resource.
    ///
    /// Produces `403 Forbidden` and RFC 6750 `insufficient_scope`.
    Forbidden(String),
    /// The token is not suitable for this resource.
    ///
    /// Produces `401 Unauthorized` and RFC 6750 `invalid_token`.
    InvalidToken(String),
}

impl std::fmt::Display for AuthorizationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Forbidden(description) | Self::InvalidToken(description) => {
                f.write_str(description)
            }
        }
    }
}

impl std::error::Error for AuthorizationError {}

/// Applies a custom authorization check to a validated token.
///
/// The check receives the complete normalized [`ValidatedRequest`], including
/// issuer and audience as well as custom claims. It therefore works across
/// heterogeneous token sources and can make source-aware decisions without
/// depending on a concrete validator implementation.
///
/// This layer must be stacked inside a [`ValidatorLayer`](super::ValidatorLayer).
/// Prefer [`ValidatorLayer::authorize`](super::ValidatorLayer::authorize),
/// which guarantees the ordering.
pub struct AuthorizeLayer<C, F, E: ErrorBody = ()> {
    check: Arc<F>,
    error_body: Option<E>,
    phantom: PhantomData<fn() -> C>,
}

impl<C, F> AuthorizeLayer<C, F> {
    /// Creates a custom authorization layer.
    #[must_use]
    pub fn new(check: F) -> Self {
        Self::with_options(check, None)
    }
}

impl<C, F, E: ErrorBody> AuthorizeLayer<C, F, E> {
    pub(crate) fn with_options(check: F, error_body: Option<E>) -> Self {
        Self {
            check: Arc::new(check),
            error_body,
            phantom: PhantomData,
        }
    }
}

impl<C, F, E: ErrorBody> Clone for AuthorizeLayer<C, F, E> {
    fn clone(&self) -> Self {
        Self {
            check: self.check.clone(),
            error_body: self.error_body.clone(),
            phantom: PhantomData,
        }
    }
}

impl<C, F, E: ErrorBody, S> Layer<S> for AuthorizeLayer<C, F, E> {
    type Service = AuthorizeService<C, F, E, S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthorizeService {
            inner,
            check: self.check.clone(),
            error_body: self.error_body.clone(),
            phantom: PhantomData,
        }
    }
}

/// The [`Service`] produced by [`AuthorizeLayer`].
pub struct AuthorizeService<C, F, E: ErrorBody, S> {
    inner: S,
    check: Arc<F>,
    error_body: Option<E>,
    phantom: PhantomData<fn() -> C>,
}

impl<C, F, E: ErrorBody, S: Clone> Clone for AuthorizeService<C, F, E, S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            check: self.check.clone(),
            error_body: self.error_body.clone(),
            phantom: PhantomData,
        }
    }
}

impl<C, F, E, S> Service<Request> for AuthorizeService<C, F, E, S>
where
    C: Send + Sync + 'static,
    E: ErrorBody,
    F: Fn(&ValidatedRequest<C>) -> Result<(), AuthorizationError> + Send + Sync + 'static,
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
        let check = self.check.clone();
        let error_body = self.error_body.clone();

        Box::pin(async move {
            let Some(validator_data) = req.extensions().get::<ValidatorData>() else {
                let mut response = http::Response::new(axum_core::body::Body::empty());
                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                return Ok(response.into_response());
            };

            let Some(token) = req.extensions().get::<ValidatedToken<C>>() else {
                return Ok(challenge_response(
                    &error_body,
                    StatusCode::UNAUTHORIZED,
                    &FailureDetails::unauthenticated(),
                    validator_data.inner.unauthenticated_challenges(None),
                    None,
                    None,
                ));
            };

            let denial = match check(token) {
                Ok(()) => return inner.call(req).await,
                Err(denial) => denial,
            };
            let (status, error_code, description) = match denial {
                AuthorizationError::Forbidden(description) => (
                    StatusCode::FORBIDDEN,
                    TokenErrorCode::InsufficientScope,
                    description,
                ),
                AuthorizationError::InvalidToken(description) => (
                    StatusCode::UNAUTHORIZED,
                    TokenErrorCode::InvalidToken,
                    description,
                ),
            };
            let challenge = Challenge::new(TokenValidationError::Client(error_code))
                .with_description(description);
            let challenges =
                validator_data
                    .inner
                    .challenges_from(None, Some(&challenge), None, None);
            let details = FailureDetails {
                error_code: Some(error_code),
                error_description: challenge.description,
                required_scopes: None,
            };
            Ok(challenge_response(
                &error_body,
                status,
                &details,
                challenges,
                None,
                None,
            ))
        })
    }
}
