use std::{ops::Deref, sync::Arc};

use http::Uri;
use huskarl_resource_server::validator::{ValidatedRequest, metadata::ValidatorMetadata};

pub struct ValidatedToken<Claims>(pub Arc<ValidatedRequest<Claims>>);

impl<Claims> Deref for ValidatedToken<Claims> {
    type Target = ValidatedRequest<Claims>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<Claims: std::fmt::Debug> std::fmt::Debug for ValidatedToken<Claims> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.0, f)
    }
}

impl<Claims> Clone for ValidatedToken<Claims> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

#[derive(Debug, Clone)]
pub struct ValidatorData {
    pub inner: Arc<ValidatorMetadata>,
}

#[derive(Debug, Clone, Copy)]
pub struct HasValidToken;

/// Client certificate DER bytes, injected by the TLS acceptor layer for mTLS connections.
pub struct ClientCertDer(pub Vec<u8>);

/// The effective request URL (scheme + host + path), injected by an outer middleware when the
/// server sits behind a reverse proxy that may rewrite the URI.
pub struct RequestUrl(pub Uri);

/// Passes scopes already required and validated, so nested middleware can fail with the right
/// set of required scopes.
#[derive(Clone)]
pub(crate) struct AncestorRequiredScopes(pub Arc<Vec<String>>);
