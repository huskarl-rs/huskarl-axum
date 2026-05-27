//! Error/challenge response types for the auth middleware.
//!
//! [`ChallengeResponse`] renders RFC 6750 `WWW-Authenticate` challenges (with an
//! optional `DPoP-Nonce`); [`ErrorBody`] lets you attach a custom body to those
//! responses, built from the structured failure details in [`ErrorDetails`].

use axum_core::response::IntoResponse;
use http::{HeaderValue, StatusCode, header::WWW_AUTHENTICATE};

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
/// returned by the validator and scope-enforcement middleware. The default
/// implementation (`()`) returns an empty body.
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

/// An RFC 6750 challenge response with `WWW-Authenticate` headers.
///
/// The body type `B` defaults to `()` (empty body). Pass any [`IntoResponse`] type
/// to include a response body — for example, `axum::Json<T>` for a JSON error payload.
pub struct ChallengeResponse<B = ()> {
    /// The HTTP status (e.g. `401` or `403`).
    pub status: StatusCode,
    /// The raw `WWW-Authenticate` challenge header values.
    pub challenges: Vec<String>,
    /// A `DPoP-Nonce` to return, if the server is issuing one (RFC 9449 §8).
    pub dpop_nonce: Option<String>,
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
        response
    }
}
