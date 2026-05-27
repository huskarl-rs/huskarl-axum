//! Request-extension types passed between the auth middleware layers.
//!
//! [`ValidatorLayer`](crate::layers::ValidatorLayer) inserts these into the
//! request's extensions; downstream layers and the reverse-proxy/mTLS helpers
//! read them back out. The extractor you name in handler signatures,
//! [`ValidatedToken`](crate::extractors::ValidatedToken), lives in
//! [`extractors`](crate::extractors).

use std::sync::Arc;

use http::Uri;
use huskarl_resource_server::validator::metadata::ValidatorMetadata;

/// Request extension carrying the validator's metadata, used to build the
/// `WWW-Authenticate` challenges when a token is missing or rejected.
#[derive(Debug, Clone)]
pub struct ValidatorData {
    /// The validator metadata (issuer, supported schemes, …).
    pub inner: Arc<ValidatorMetadata>,
}

/// Request-extension marker set by the
/// [`ValidatorLayer`](crate::layers::ValidatorLayer) when the request carried a
/// valid token, for downstream middleware to check.
#[derive(Debug, Clone, Copy)]
pub struct HasValidToken;

/// Client certificate DER bytes, injected by the TLS acceptor layer for mTLS connections.
pub struct ClientCertDer(pub Vec<u8>);

/// The effective request URL (scheme + authority + path) the auth layers should treat
/// as the request target, injected by an outer middleware when the server sits behind a
/// reverse proxy that rewrites the URI. Takes precedence over the validator layer's
/// `base_url` for DPoP `htu` reconstruction.
///
/// # Security
///
/// This value is trusted verbatim for DPoP `htu` binding, so the middleware that
/// sets it MUST derive it from a source the client cannot spoof: a configured
/// origin, or forwarded headers a proxy you control sets (overwriting any
/// client-supplied copy) and that clients cannot bypass. Deriving it straight
/// from the inbound `Host` / `X-Forwarded-Host` / `Forwarded` header lets an
/// attacker spoof it to match a captured proof's `htu`. When a single static
/// origin suffices, prefer the validator layer's `base_url`.
pub struct RequestUrl(pub Uri);

/// Passes scopes already required and validated, so nested middleware can fail with the right
/// set of required scopes.
#[derive(Clone)]
pub(crate) struct AncestorRequiredScopes(pub Arc<Vec<String>>);
