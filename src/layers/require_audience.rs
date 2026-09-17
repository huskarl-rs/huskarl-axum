use std::{marker::PhantomData, pin::Pin, sync::Arc};

use axum_core::{
    extract::Request,
    response::{IntoResponse, Response},
};
use http::StatusCode;
use huskarl_resource_server::error::{Challenge, TokenErrorCode, TokenValidationError};
use tower::{Layer, Service};

use crate::extensions::ValidatorData;
use crate::extractors::ValidatedToken;
use crate::layers::validator::{FailureDetails, challenge_response};
use crate::response::ErrorBody;

/// Requires a validated token whose audience matches at least one accepted
/// value.
///
/// This layer operates on the validator-independent [`ValidatedToken`]
/// extension, so it works with single-issuer, multi-issuer, JWT, and opaque
/// token validators alike. A mismatch is `401 Unauthorized` with the RFC 6750
/// `invalid_token` error.
///
/// It must be stacked inside a [`ValidatorLayer`](super::ValidatorLayer).
/// Prefer [`ValidatorLayer::require_audience`](super::ValidatorLayer::require_audience)
/// or [`ValidatorLayer::require_any_audience`](super::ValidatorLayer::require_any_audience),
/// which guarantee the ordering.
pub struct RequireAudienceLayer<C, E: ErrorBody = ()> {
    accepted_audiences: Arc<Vec<String>>,
    error_body: Option<E>,
    phantom: PhantomData<fn() -> C>,
}

impl<C, E: ErrorBody> Clone for RequireAudienceLayer<C, E> {
    fn clone(&self) -> Self {
        Self {
            accepted_audiences: self.accepted_audiences.clone(),
            error_body: self.error_body.clone(),
            phantom: PhantomData,
        }
    }
}

impl<C> RequireAudienceLayer<C> {
    /// Creates a layer accepting any one of the supplied audiences.
    ///
    /// An empty collection still requires a valid token, but cannot match any
    /// token audience.
    #[must_use]
    pub fn new<I, T>(accepted_audiences: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        Self::with_options(
            accepted_audiences.into_iter().map(Into::into).collect(),
            None,
        )
    }
}

impl<C, E: ErrorBody> RequireAudienceLayer<C, E> {
    pub(crate) fn with_options(accepted_audiences: Vec<String>, error_body: Option<E>) -> Self {
        Self {
            accepted_audiences: Arc::new(accepted_audiences),
            error_body,
            phantom: PhantomData,
        }
    }
}

impl<C, E: ErrorBody, S> Layer<S> for RequireAudienceLayer<C, E> {
    type Service = RequireAudienceService<C, E, S>;

    fn layer(&self, inner: S) -> Self::Service {
        RequireAudienceService {
            inner,
            accepted_audiences: self.accepted_audiences.clone(),
            error_body: self.error_body.clone(),
            phantom: PhantomData,
        }
    }
}

/// The [`Service`] produced by [`RequireAudienceLayer`].
pub struct RequireAudienceService<C, E: ErrorBody, S> {
    inner: S,
    accepted_audiences: Arc<Vec<String>>,
    error_body: Option<E>,
    phantom: PhantomData<fn() -> C>,
}

impl<C, E: ErrorBody, S: Clone> Clone for RequireAudienceService<C, E, S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            accepted_audiences: self.accepted_audiences.clone(),
            error_body: self.error_body.clone(),
            phantom: PhantomData,
        }
    }
}

impl<C, E, S> Service<Request> for RequireAudienceService<C, E, S>
where
    C: Send + Sync + 'static,
    E: ErrorBody,
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
        let accepted_audiences = self.accepted_audiences.clone();
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

            let matches = accepted_audiences
                .iter()
                .any(|accepted| token.aud.contains(accepted));
            if !matches {
                let challenge =
                    Challenge::new(TokenValidationError::Client(TokenErrorCode::InvalidToken))
                        .with_description("The access token audience does not match");
                let challenges =
                    validator_data
                        .inner
                        .challenges_from(None, Some(&challenge), None, None);
                let details = FailureDetails {
                    error_code: Some(TokenErrorCode::InvalidToken),
                    error_description: challenge.description,
                    required_scopes: None,
                };
                return Ok(challenge_response(
                    &error_body,
                    StatusCode::UNAUTHORIZED,
                    &details,
                    challenges,
                    None,
                    None,
                ));
            }

            inner.call(req).await
        })
    }
}
