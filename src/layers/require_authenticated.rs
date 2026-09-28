use std::pin::Pin;

use axum_core::{
    extract::Request,
    response::{IntoResponse, Response},
};
use http::StatusCode;
use tower::{Layer, Service};

use crate::extensions::{HasValidToken, ValidatorData};
use crate::layers::validator::{FailureDetails, challenge_response};
use crate::response::ErrorBodyRenderer;

/// Rejects any request that did not arrive with a valid access token — a
/// layer-level authentication gate.
///
/// A [`ValidatorLayer`](super::ValidatorLayer) alone validates a token *when one
/// is present* but, by design, lets an **unauthenticated** request (no
/// `Authorization` header) reach the inner handler — leaving the decision to a
/// [`ValidatedToken`](crate::extractors::ValidatedToken) extractor in the
/// handler signature. That is flexible, but it means a handler that forgets to
/// extract the token is silently public. Stack this layer inside the validator
/// to make "a valid token is required" enforced by the middleware instead: an
/// unauthenticated request gets a `401 Unauthorized` with the appropriate
/// `WWW-Authenticate` challenge and never reaches the handler.
///
/// Unlike [`RequireScopesLayer`](super::RequireScopesLayer) it is not generic
/// over the claims type — it only checks that validation succeeded, so it can
/// guard routes regardless of their claims shape.
///
/// Must be stacked **inside** a [`ValidatorLayer`](super::ValidatorLayer): it
/// reads `ValidatorData` from the request extensions. If that is missing (the
/// layer is stacked outside, or without, a validator) the request short-circuits
/// with `500 Internal Server Error` rather than panicking — almost always a
/// middleware-ordering bug. Prefer
/// [`ValidatorLayer::authenticated`](super::ValidatorLayer::authenticated),
/// which returns an order-safe composite layer.
#[derive(Clone)]
pub struct RequireAuthenticatedLayer {
    error_body: Option<ErrorBodyRenderer>,
}

impl RequireAuthenticatedLayer {
    /// Creates a layer that rejects requests without a valid token.
    ///
    /// Must sit inside a [`ValidatorLayer`](super::ValidatorLayer); prefer
    /// [`ValidatorLayer::authenticated`](super::ValidatorLayer::authenticated),
    /// which guarantees the ordering and reuses the validator's error body.
    #[must_use]
    pub fn new() -> Self {
        Self { error_body: None }
    }
}

impl Default for RequireAuthenticatedLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl RequireAuthenticatedLayer {
    pub(crate) fn with_options(error_body: Option<ErrorBodyRenderer>) -> Self {
        Self { error_body }
    }
}

impl<S> Layer<S> for RequireAuthenticatedLayer {
    type Service = RequireAuthenticatedService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RequireAuthenticatedService {
            inner,
            error_body: self.error_body.clone(),
        }
    }
}

/// The [`Service`] produced by [`RequireAuthenticatedLayer`]; you don't normally
/// name this directly.
#[derive(Clone)]
pub struct RequireAuthenticatedService<S> {
    inner: S,
    error_body: Option<ErrorBodyRenderer>,
}

impl<S> Service<Request> for RequireAuthenticatedService<S>
where
    S: Service<Request, Response = Response> + Send + Clone + 'static,
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
        let error_body = self.error_body.clone();

        Box::pin(async move {
            if req.extensions().get::<ValidatorData>().is_none() {
                // ValidatorData is only inserted by ValidatorLayer. Missing it means
                // this layer is stacked outside (or without) a validator — a config
                // bug. Fail closed with 500 rather than panicking so a single
                // misconfigured route can't take the whole server down.
                let mut resp = http::Response::new(axum_core::body::Body::empty());
                *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                return Ok(resp.into_response());
            }

            // `HasValidToken` is inserted by ValidatorLayer only when a token was
            // present AND validated. Its absence means the request was
            // unauthenticated (the validator returned `Ok(None)`); reject it here
            // rather than relying on a downstream extractor.
            if req.extensions().get::<HasValidToken>().is_none() {
                let challenges = req
                    .extensions()
                    .get::<ValidatorData>()
                    .map(|vd| vd.inner.unauthenticated_challenges(None))
                    .unwrap_or_default();
                return Ok(challenge_response(
                    error_body.as_ref(),
                    StatusCode::UNAUTHORIZED,
                    &FailureDetails::unauthenticated(),
                    challenges,
                    None,
                    None,
                ));
            }

            inner.call(req).await
        })
    }
}
