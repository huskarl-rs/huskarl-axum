//! Error/challenge response types for the auth middleware.
//!
//! [`ChallengeResponse`] renders RFC 6750 `WWW-Authenticate` challenges (with an
//! optional `DPoP-Nonce`); [`ErrorBody`] lets you attach a custom body to those
//! responses, built from the structured failure details in [`ErrorDetails`].
//!
//! Follow [Customize authentication error responses](self::guide) for JSON and
//! browser-login examples.

use std::sync::Arc;

use axum_core::response::{IntoResponse, Response};
use http::{
    HeaderValue, StatusCode,
    header::{CACHE_CONTROL, RETRY_AFTER, WWW_AUTHENTICATE},
};
use huskarl_resource_server::core::platform::Duration;

pub use huskarl_resource_server::error::TokenErrorCode;

pub(crate) static DPOP_NONCE: http::HeaderName = http::HeaderName::from_static("dpop-nonce");

/// The structured details of an authentication/authorization failure, passed
/// to [`ErrorBody::error_body`].
///
/// Carries the same information the middleware renders into the
/// `WWW-Authenticate` challenge, in structured form — so a body implementation
/// (e.g. an RFC 6750-style JSON payload of `error` / `error_description` /
/// `scope`) reads fields instead of parsing the challenge strings back apart.
///
/// Construct one (outside this crate, e.g. to unit-test an [`ErrorBody`]
/// implementation) with [`builder`](Self::builder).
#[derive(Debug, Clone, bon::Builder)]
#[non_exhaustive]
pub struct ErrorDetails<'a> {
    /// The HTTP status of the response (`401`, `403`, …).
    pub status: StatusCode,
    /// The RFC 6750 / RFC 9449 error code (`invalid_token`,
    /// `insufficient_scope`, …). `None` for an unauthenticated request —
    /// RFC 6750 §3.1 challenges a request that carried no token without an
    /// `error` attribute — and for server-side validation failures, which
    /// deliberately reveal no error details.
    pub error_code: Option<TokenErrorCode>,
    /// A human-readable description of the failure (the `error_description`
    /// challenge attribute), when the rejecting middleware provides one.
    pub error_description: Option<&'a str>,
    /// Every scope the route requires (the `scope` challenge attribute),
    /// when known — provided by the scope-enforcement middleware.
    pub required_scopes: Option<&'a [String]>,
    /// The raw `WWW-Authenticate` challenge values accompanying the response.
    pub challenges: &'a [String],
}

/// Builds the response body for a `WWW-Authenticate` challenge.
///
/// Implement this trait to customize the body of the challenge responses
/// returned by the validator, scope/authentication middleware, and the
/// [`ValidatedToken`](crate::extractors::ValidatedToken) extractor. The
/// default implementation (`()`) returns an empty body.
pub trait ErrorBody: Clone + Send + Sync + 'static {
    /// The response body type produced for a challenge.
    type Body: IntoResponse;
    /// Builds the body for a challenge from the structured failure details.
    fn error_body(&self, details: &ErrorDetails<'_>) -> Self::Body;
}

impl ErrorBody for () {
    type Body = ();
    fn error_body(&self, _: &ErrorDetails<'_>) -> Self::Body {}
}

/// Type-erased error-body renderer carried in request extensions so extractor
/// rejections use the same body configuration as their validator layer.
#[derive(Clone)]
pub(crate) struct ErrorBodyRenderer(Arc<dyn RenderErrorBody>);

impl ErrorBodyRenderer {
    pub(crate) fn new<E: ErrorBody>(error_body: E) -> Self {
        Self(Arc::new(error_body))
    }

    pub(crate) fn render(&self, details: &ErrorDetails<'_>) -> Response {
        self.0.render(details)
    }
}

trait RenderErrorBody: Send + Sync {
    fn render(&self, details: &ErrorDetails<'_>) -> Response;
}

impl<E: ErrorBody> RenderErrorBody for E {
    fn render(&self, details: &ErrorDetails<'_>) -> Response {
        self.error_body(details).into_response()
    }
}

/// An RFC 6750 challenge response with authentication-related headers.
///
/// The body type `B` defaults to `()` (empty body). Pass any [`IntoResponse`] type
/// to include a response body — for example, `axum::Json<T>` for a JSON error payload.
#[non_exhaustive]
pub struct ChallengeResponse<B = ()> {
    /// The HTTP status (e.g. `401` or `403`).
    pub status: StatusCode,
    /// The raw `WWW-Authenticate` challenge header values.
    pub challenges: Vec<String>,
    /// A `DPoP-Nonce` to return, if the server is issuing one (RFC 9449 §8).
    pub dpop_nonce: Option<String>,
    /// How long the client should wait before retrying a server-side failure.
    ///
    /// Rendered as RFC 9110 delta-seconds, rounding a non-zero fractional
    /// second up so an active cooldown is never advertised as zero.
    pub retry_after: Option<Duration>,
    /// The response body.
    pub body: B,
}

impl<B: IntoResponse> IntoResponse for ChallengeResponse<B> {
    fn into_response(self) -> axum_core::response::Response {
        let mut response = self.body.into_response();
        *response.status_mut() = self.status;
        for challenge in &self.challenges {
            if let Ok(value) = HeaderValue::try_from(challenge) {
                response.headers_mut().append(WWW_AUTHENTICATE, value);
            }
        }
        if let Some(nonce) = self.dpop_nonce.as_deref()
            && let Ok(value) = HeaderValue::try_from(nonce)
        {
            response.headers_mut().insert(DPOP_NONCE.clone(), value);
        }
        if let Some(after) = self.retry_after {
            let seconds = after
                .as_secs()
                .saturating_add(u64::from(after.subsec_nanos() > 0));
            response
                .headers_mut()
                .insert(RETRY_AFTER, HeaderValue::from(seconds));
        }
        // Authentication failures and their application-defined bodies must
        // not be stored by shared or private caches.
        response
            .headers_mut()
            .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response
    }
}

/// Configure resource-error bodies and shared browser-login error pages.
#[cfg(any(doc, doctest))]
#[doc = include_str!("../docs/how_to/error_responses.md")]
pub mod guide {}
