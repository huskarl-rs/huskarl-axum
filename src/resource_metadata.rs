//! RFC 9728 Protected Resource Metadata endpoint support.
//!
//! [`ResourceMetadataService`] is produced together with a configured
//! [`ValidatorLayer`](crate::layers::ValidatorLayer) by
//! [`ValidatorLayer::with_protected_resource`](crate::layers::ValidatorLayer::with_protected_resource).
//! Mount every returned service at its [`path`](ResourceMetadataService::path)
//! on the application root with Axum's `Router::route_service`. This collects
//! independently configured MCP resources into the one deterministic
//! well-known hierarchy. The corresponding validator layer applies only to the
//! MCP server router or route subtree on which the application installs it.

use std::{convert::Infallible, future::Ready, sync::Arc, task::Poll};

use axum_core::{
    body::Body,
    extract::Request,
    response::{IntoResponse as _, Response},
};
use http::{Method, StatusCode, Uri, header};
use tower::Service;

/// How an RFC 8707 resource identifier maps to access-token audience values.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AudienceBinding {
    /// The token's `aud` claim must contain the protected-resource identifier
    /// exactly as configured.
    ResourceIdentifier,
    /// The authorization server maps the resource identifier to one of these
    /// token audience values.
    Mapped(Vec<String>),
}

impl AudienceBinding {
    /// Declares audience values produced by an authorization server that maps
    /// the resource identifier to another URI or opaque identifier.
    pub fn mapped<I, T>(audiences: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        Self::Mapped(audiences.into_iter().map(Into::into).collect())
    }

    pub(crate) fn into_audiences(self, resource: &str) -> Vec<String> {
        match self {
            Self::ResourceIdentifier => vec![resource.to_owned()],
            Self::Mapped(audiences) => audiences,
        }
    }
}

/// Error configuring the RFC 9728 metadata endpoint.
#[derive(Debug)]
#[non_exhaustive]
pub enum ResourceMetadataError {
    /// Protected-resource metadata requires the integration's public base URL.
    MissingBaseUrl,
    /// The supplied protected-resource subpath is invalid.
    InvalidResourcePath {
        /// The offending subpath.
        path: String,
    },
    /// The protected-resource identifier derived from the base and subpath is
    /// invalid.
    InvalidResourceIdentifier(crate::layers::InvalidResourceIdentifier),
    /// The protected resource has no acceptable token audiences.
    EmptyAudiences,
    /// This validator layer was already bound to a protected resource.
    ProtectedResourceAlreadyConfigured,
    /// Validator metadata unexpectedly could not produce a resource document.
    DocumentUnavailable,
    /// The validator advertises a different metadata URL than the local
    /// endpoint derived from the layer's resource identifier.
    MetadataUrlMismatch {
        /// URL supplied by the validator.
        configured: String,
        /// URL derived from the layer's resource identifier.
        derived: String,
    },
    /// The RFC 9728 well-known URL could not be derived.
    WellKnownUrl(huskarl_resource_server::core::error::Error),
    /// The metadata document could not be encoded as JSON.
    Serialization(serde_json::Error),
}

impl std::fmt::Display for ResourceMetadataError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingBaseUrl => {
                f.write_str("protected-resource metadata requires a public base URL")
            }
            Self::InvalidResourcePath { path } => {
                write!(f, "invalid protected-resource subpath {path:?}")
            }
            Self::InvalidResourceIdentifier(_) => {
                f.write_str("invalid RFC 9728 protected-resource identifier")
            }
            Self::EmptyAudiences => {
                f.write_str("a protected resource must accept at least one token audience")
            }
            Self::ProtectedResourceAlreadyConfigured => {
                f.write_str("this validator layer already has a protected resource")
            }
            Self::DocumentUnavailable => {
                f.write_str("validator metadata could not produce an RFC 9728 document")
            }
            Self::MetadataUrlMismatch {
                configured,
                derived,
            } => write!(
                f,
                "validator metadata URL {configured:?} does not match local endpoint {derived:?}",
            ),
            Self::WellKnownUrl(_) => f.write_str("could not derive RFC 9728 metadata URL"),
            Self::Serialization(_) => f.write_str("could not serialize RFC 9728 metadata"),
        }
    }
}

impl std::error::Error for ResourceMetadataError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidResourceIdentifier(source) => Some(source),
            Self::WellKnownUrl(source) => Some(source),
            Self::Serialization(source) => Some(source),
            Self::MissingBaseUrl
            | Self::InvalidResourcePath { .. }
            | Self::EmptyAudiences
            | Self::ProtectedResourceAlreadyConfigured
            | Self::DocumentUnavailable
            | Self::MetadataUrlMismatch { .. } => None,
        }
    }
}

/// A cloneable Tower service serving an RFC 9728 metadata document.
///
/// The service accepts `GET` and `HEAD`. Other methods receive `405 Method Not
/// Allowed` with `Allow: GET, HEAD`. Successful responses are JSON and may be
/// cached for one hour. Mount it at [`path`](Self::path):
///
/// ```no_run
/// # use axum::Router;
/// # use huskarl_axum::layers::ValidatorLayer;
/// # fn app<V>(validator: V) -> Result<Router, Box<dyn std::error::Error>>
/// # where
/// #     V: huskarl_axum::resource_server::validator::AccessTokenValidator
/// #         + huskarl_axum::resource_server::validator::metadata::ProvideValidatorMetadata
/// #         + 'static,
/// # {
/// let validator = ValidatorLayer::builder()
///     .validator(validator)
///     .base_url("https://api.example.com")?
///     .build();
/// let (validator, metadata) = validator.with_protected_resource(
///     "/mcp",
///     huskarl_axum::resource_metadata::AudienceBinding::ResourceIdentifier,
///     ["profile.read", "profile.write"],
/// )?;
///
/// let protected = Router::new().layer(validator.authenticated());
/// let app = Router::new()
///     .route_service(metadata.path(), metadata.clone())
///     .merge(protected);
/// # Ok(app)
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct ResourceMetadataService {
    resource: Uri,
    uri: Uri,
    body: Arc<[u8]>,
}

impl ResourceMetadataService {
    pub(crate) fn new(resource: Uri, uri: Uri, body: Vec<u8>) -> Self {
        Self {
            resource,
            uri,
            body: body.into(),
        }
    }

    /// Returns the absolute protected-resource identifier derived from the
    /// integration's base URL and configured subpath.
    #[must_use]
    pub fn resource(&self) -> &Uri {
        &self.resource
    }

    /// Returns the absolute canonical URL advertised for this document.
    #[must_use]
    pub fn uri(&self) -> &Uri {
        &self.uri
    }

    /// Returns the well-known path at which this service must be mounted.
    ///
    /// If the resource identifier contains a query, RFC 9728 preserves it in
    /// the advertised metadata URL. Axum routes only on the path component, so
    /// that query is intentionally not included here; requests carrying it are
    /// still routed to this service.
    #[must_use]
    pub fn path(&self) -> &str {
        self.uri.path()
    }

    fn response(&self, include_body: bool) -> Response {
        let body = if include_body {
            Body::from(self.body.as_ref().to_vec())
        } else {
            Body::empty()
        };
        let mut response = body.into_response();
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/json"),
        );
        response.headers_mut().insert(
            header::CONTENT_LENGTH,
            http::HeaderValue::from(self.body.len()),
        );
        response.headers_mut().insert(
            header::CACHE_CONTROL,
            http::HeaderValue::from_static("max-age=3600"),
        );
        response
    }

    fn method_not_allowed() -> Response {
        let mut response = StatusCode::METHOD_NOT_ALLOWED.into_response();
        response
            .headers_mut()
            .insert(header::ALLOW, http::HeaderValue::from_static("GET, HEAD"));
        response.headers_mut().insert(
            header::CACHE_CONTROL,
            http::HeaderValue::from_static("no-store"),
        );
        response
            .headers_mut()
            .insert(header::CONTENT_LENGTH, http::HeaderValue::from_static("0"));
        response
    }
}

impl Service<Request> for ResourceMetadataService {
    type Response = Response;
    type Error = Infallible;
    type Future = Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut std::task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request) -> Self::Future {
        let response = match *request.method() {
            Method::GET => self.response(true),
            Method::HEAD => self.response(false),
            _ => Self::method_not_allowed(),
        };
        std::future::ready(Ok(response))
    }
}
