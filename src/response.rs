use axum_core::response::IntoResponse;
use http::{HeaderValue, StatusCode, header::WWW_AUTHENTICATE};

/// Produces a response body for error responses.
///
/// Implement this trait to customize the body of `WWW-Authenticate` challenge responses
/// returned by the validator and scope enforcement middleware. The default implementation
/// (`()`) returns an empty body.
pub trait ErrorBody: Clone + Send + Sync + 'static {
    type Body: IntoResponse;
    fn error_body(&self, status: StatusCode, challenges: &[String]) -> Self::Body;
}

impl ErrorBody for () {
    type Body = ();
    fn error_body(&self, _: StatusCode, _: &[String]) -> Self::Body {}
}

/// An RFC 6750 challenge response with `WWW-Authenticate` headers.
///
/// The body type `B` defaults to `()` (empty body). Pass any [`IntoResponse`] type
/// to include a response body — for example, `axum::Json<T>` for a JSON error payload.
pub struct ChallengeResponse<B = ()> {
    pub status: StatusCode,
    pub challenges: Vec<String>,
    pub dpop_nonce: Option<String>,
    pub body: B,
}

impl<B: IntoResponse> IntoResponse for ChallengeResponse<B> {
    fn into_response(self) -> axum_core::response::Response {
        let mut response = self.body.into_response();
        *response.status_mut() = self.status;
        for challenge in &self.challenges {
            let value = HeaderValue::from_str(challenge)
                .expect("challenge string must be a valid header value");
            response.headers_mut().append(WWW_AUTHENTICATE, value);
        }
        if let Some(nonce) = &self.dpop_nonce {
            let value = HeaderValue::from_str(nonce)
                .expect("DPoP nonce must be a valid header value");
            response.headers_mut().insert(DPOP_NONCE.clone(), value);
        }
        response
    }
}

static DPOP_NONCE: http::HeaderName = http::HeaderName::from_static("dpop-nonce");
