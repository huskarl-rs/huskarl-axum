use std::{collections::BTreeSet, pin::Pin, sync::Arc};

use axum_core::{extract::Request, response::IntoResponse, response::Response};
use http::Uri;
use huskarl_resource_server::{
    core::resource_metadata::well_known_url,
    error::{ToRfc6750Error as _, TokenErrorCode, TokenValidationError},
    validator::{AccessTokenValidator, metadata::ProvideValidatorMetadata},
};
use tower::{Layer, Service};

use crate::extensions::{ClientCertDer, HasValidToken, RequestUrl, ValidatorData};
use crate::extractors::ValidatedToken;
use crate::layers::{
    AudienceLayer, AuthenticatedLayer, AuthorizationError, AuthorizeLayer, AuthorizedLayer,
    HasScopes, RequireAudienceLayer, RequireScopesLayer, ScopedLayer,
};
use crate::resource_metadata::{AudienceBinding, ResourceMetadataError, ResourceMetadataService};
use crate::response::{ChallengeResponse, DPOP_NONCE, ErrorBody, ErrorBodyRenderer, ErrorDetails};

/// Error returned by the `base_url` setter on
/// [`ValidatorLayer::builder`] when it receives an invalid externally-visible
/// resource-server base URL.
///
/// The URL must be an absolute `http` or `https` URI with no query. Its path is
/// the externally visible prefix prepended to incoming request paths and
/// protected-resource subpaths.
#[derive(Debug)]
#[non_exhaustive]
pub struct InvalidBaseUrl {
    value: String,
    reason: &'static str,
    source: Option<http::uri::InvalidUri>,
}

/// Error returned when [`ValidatorLayer::with_protected_resource`] derives an
/// invalid RFC 9728 protected-resource identifier.
///
/// Resource identifiers are preserved byte-for-byte for RFC 9728's identity
/// check. They must be absolute `https` URLs. Local metadata endpoints support
/// paths, but reject queries and fragments.
#[derive(Debug)]
#[non_exhaustive]
pub struct InvalidResourceIdentifier {
    value: String,
    reason: &'static str,
    source: Option<http::uri::InvalidUri>,
}

impl std::fmt::Display for InvalidResourceIdentifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "invalid protected-resource identifier {:?}: {}",
            self.value, self.reason
        )
    }
}

impl std::error::Error for InvalidResourceIdentifier {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_ref()
            .map(|source| source as &(dyn std::error::Error + 'static))
    }
}

impl std::fmt::Display for InvalidBaseUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid base URL {:?}: {}", self.value, self.reason)
    }
}

impl std::error::Error for InvalidBaseUrl {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_ref()
            .map(|source| source as &(dyn std::error::Error + 'static))
    }
}

fn parse_base_url(value: &str) -> Result<Uri, InvalidBaseUrl> {
    let uri = value.parse::<Uri>().map_err(|source| InvalidBaseUrl {
        value: value.to_owned(),
        reason: "not a valid URI",
        source: Some(source),
    })?;

    if !matches!(uri.scheme_str(), Some("http" | "https")) || uri.authority().is_none() {
        return Err(InvalidBaseUrl {
            value: value.to_owned(),
            reason: "expected an absolute http(s) URL with an authority",
            source: None,
        });
    }
    if uri.query().is_some() {
        return Err(InvalidBaseUrl {
            value: value.to_owned(),
            reason: "queries are not allowed",
            source: None,
        });
    }

    Ok(uri)
}

fn join_base_url(base: &Uri, path_and_query: &http::uri::PathAndQuery) -> Option<Uri> {
    let base_path = base.path().trim_end_matches('/');
    let suffix = path_and_query.path();
    let path = if suffix.starts_with('/') {
        format!("{base_path}{suffix}")
    } else {
        format!("{base_path}/{suffix}")
    };
    let joined = match path_and_query.query() {
        Some(query) => format!("{path}?{query}"),
        None => path,
    };

    let path_and_query = joined.parse().ok()?;
    let mut parts = base.clone().into_parts();
    parts.path_and_query = Some(path_and_query);
    Uri::from_parts(parts).ok()
}

fn parse_resource_identifier(value: &str) -> Result<String, InvalidResourceIdentifier> {
    if value.contains('#') {
        return Err(InvalidResourceIdentifier {
            value: value.to_owned(),
            reason: "fragments are not allowed",
            source: None,
        });
    }

    let uri = value
        .parse::<Uri>()
        .map_err(|source| InvalidResourceIdentifier {
            value: value.to_owned(),
            reason: "not a valid URI",
            source: Some(source),
        })?;

    if uri.scheme_str() != Some("https") || uri.authority().is_none() {
        return Err(InvalidResourceIdentifier {
            value: value.to_owned(),
            reason: "expected an absolute https URL with an authority",
            source: None,
        });
    }
    if well_known_url(value).is_err() {
        return Err(InvalidResourceIdentifier {
            value: value.to_owned(),
            reason: "cannot derive an RFC 9728 metadata URL",
            source: None,
        });
    }

    // Keep the caller's exact spelling: RFC 9728 §3.3 compares this value
    // byte-for-byte with the document's `resource` member.
    Ok(value.to_owned())
}

/// Tower [`Layer`] that validates the access token on each request
/// and injects the claims for extractors.
///
/// Validates bearer/DPoP/mTLS tokens via the wrapped [`AccessTokenValidator`],
/// inserts a [`ValidatedToken`] (plus DPoP/metadata extensions) on success, and
/// returns an RFC 6750 `WWW-Authenticate` challenge on failure. Build one with
/// [`builder`](Self::builder); it must be the outermost auth layer, with any
/// [`RequireScopesLayer`] nested inside. Prefer the
/// order-safe [`authenticated`](Self::authenticated) and
/// [`require_scopes`](Self::require_scopes) composite layers for protected
/// routes.
///
/// When no token is present, this layer by itself passes the request through so
/// handlers can use `Option<ValidatedToken<_>>`. Use one of the composite
/// layers whenever authentication is required.
pub struct ValidatorLayer<V: ProvideValidatorMetadata, E: ErrorBody = ()> {
    config: Arc<ValidatorConfig<V>>,
    validator_data: ValidatorData,
    error_body: Option<E>,
    extractor_error_body: Option<ErrorBodyRenderer>,
    resource_audiences: Option<Arc<Vec<String>>>,
}

#[bon::bon]
impl<V: ProvideValidatorMetadata, E: ErrorBody> ValidatorLayer<V, E> {
    #[builder(
        start_fn(vis = "", name = __builder),
        generics(setters(name = "set_{}", vis = "")),
    )]
    /// Builds a [`ValidatorLayer`]; invoked via [`builder`](Self::builder).
    ///
    /// `validator` performs the actual token validation; a custom `error_body`
    /// attaches a body to challenge responses.
    ///
    /// `base_url` is this integration's externally visible mount URL, e.g.
    /// `https://api.example.com/gateway`. Its path is the public prefix prepended
    /// to request paths and protected-resource subpaths. Request paths include
    /// all `Router::nest` prefixes, using Axum's `OriginalUri`. Only include
    /// a prefix in `base_url` when a reverse proxy removes it before the request
    /// reaches Axum; do not repeat an Axum nesting prefix here. It is required for
    /// **`DPoP` `htu` binding** and by [`with_protected_resource`](Self::with_protected_resource),
    /// but may be omitted by a bearer-only integration without local protected
    /// resource metadata.
    ///
    /// The generated `base_url` setter validates the origin immediately and
    /// returns `Result<_, InvalidBaseUrl>`; use
    /// `.base_url("https://api.example.com/gateway")?`.
    ///
    /// # Security
    ///
    /// The origin used for `htu` must be one the client cannot spoof:
    /// a static `base_url` you configure, or a [`RequestUrl`] injected by trusted
    /// middleware when the proxy rewrite cannot be represented by one prefix.
    /// Never derive either from the raw `Host` header or an untrusted forwarded
    /// header: a request could set it to match a captured proof's `htu` and pass
    /// the check. With neither configured the request URL is origin-form and the
    /// validator fails closed with an integration error rather than checking
    /// `htu`. See the huskarl-resource-server `DPoP` how-to guide for
    /// reconstructing the public URL behind a proxy.
    pub fn new(
        validator: V,
        #[builder(with = |base_url: impl AsRef<str>| -> Result<_, InvalidBaseUrl> {
            parse_base_url(base_url.as_ref())
        })]
        base_url: Option<Uri>,
        #[builder(setters(name = error_body_internal, vis = ""))] error_body: Option<E>,
    ) -> Self {
        let validator_metadata = validator.validator_metadata(None);

        let extractor_error_body = error_body.clone().map(ErrorBodyRenderer::new);

        Self {
            config: Arc::new(ValidatorConfig {
                validator,
                base_url,
            }),
            validator_data: ValidatorData {
                inner: Arc::new(validator_metadata),
            },
            error_body,
            extractor_error_body,
            resource_audiences: None,
        }
    }
}

/// Public builder start — always begins with `E = ()`.
impl<V: ProvideValidatorMetadata> ValidatorLayer<V> {
    /// Begins building a [`ValidatorLayer`], starting with the default (empty)
    /// error body.
    pub fn builder() -> ValidatorLayerBuilder<V, ()> {
        ValidatorLayer::<V, ()>::__builder()
    }
}

// Glob-import the bon-generated builder state module by design.
#[allow(clippy::wildcard_imports)]
use validator_layer_builder::*;

/// Custom `error_body` setter that transitions `E` to the provided type.
impl<V: ProvideValidatorMetadata, E: ErrorBody, S: State> ValidatorLayerBuilder<V, E, S> {
    pub fn error_body<NewE: ErrorBody>(
        self,
        error_body: NewE,
    ) -> ValidatorLayerBuilder<V, NewE, SetErrorBody<S>>
    where
        S::ErrorBody: IsUnset,
    {
        self.set_e().error_body_internal(error_body)
    }
}

impl<V: ProvideValidatorMetadata, E: ErrorBody> ValidatorLayer<V, E> {
    /// Configures an RFC 9728 resource and requires an audience-matching token.
    ///
    /// Returns a complete authentication layer and the metadata service. Install
    /// the layer directly on the router containing this resource's endpoints.
    /// Mount the metadata service separately at [`ResourceMetadataService::path`]
    /// on the root router so discovery remains accessible without a token.
    /// Requests without a token or with the wrong audience receive `401`.
    /// All authentication challenges advertise the metadata endpoint.
    ///
    /// `scopes_supported` advertises capabilities only. Use
    /// [`AuthenticatedLayer::require_scopes`] or [`AuthenticatedLayer::authorize`]
    /// to enforce operation-specific permissions. For intentionally public
    /// endpoints accepting optional tokens, use
    /// [`with_optional_authentication_resource`](Self::with_optional_authentication_resource).
    ///
    /// One configured layer represents one protected resource. Its audience
    /// and challenge metadata apply to every request routed through that
    /// layer; Axum's router determines the protected path set. Those routes are
    /// endpoints of one logical resource and share one document; the library
    /// does not generate a document for every descendant URL. To host multiple
    /// MCP servers, configure a separate layer and metadata service for each
    /// server and mount each layer on that server's router or route subtree.
    ///
    /// The document is built from the validator's capabilities and the
    /// protected-resource identifier derived from `base_url` and the supplied
    /// subpath. Supplied scopes are sorted and deduplicated. The endpoint and
    /// challenge URL are derived together, so they cannot drift.
    ///
    /// `resource_path` is relative to this integration's configured `base_url`
    /// and must begin with `/`. The base URL's path is the public rewritten
    /// prefix. For example, base URL `https://api.example.com/gateway` plus
    /// resource path `/mcp/inventory` identifies
    /// `https://api.example.com/gateway/mcp/inventory`. Queries are rejected
    /// because Axum cannot distinguish metadata routes by query. This restriction
    /// applies to resource identifiers, not to incoming requests.
    ///
    /// Behind a path-rewriting proxy, an outer trusted middleware may provide
    /// [`RequestUrl`] with the complete public request URL used for `DPoP`.
    /// Route the canonical public metadata URL to the returned service through
    /// the same deployment's router or front-proxy mapping.
    ///
    /// # Errors
    ///
    /// Rejects a missing base URL, an already-bound layer, invalid resource
    /// subpaths or identifiers, empty mapped audience sets, and validators that
    /// explicitly advertise a different metadata URL. URL derivation and JSON
    /// encoding failures are also reported.
    pub fn with_protected_resource<I, T>(
        self,
        resource_path: impl AsRef<str>,
        audience_binding: AudienceBinding,
        scopes_supported: I,
    ) -> Result<(AuthenticatedLayer<V, E>, ResourceMetadataService), ResourceMetadataError>
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        let (validator, metadata) = self.with_optional_authentication_resource(
            resource_path,
            audience_binding,
            scopes_supported,
        )?;
        Ok((AuthenticatedLayer::new(validator), metadata))
    }

    /// Configures resource metadata and audience validation with optional authentication.
    ///
    /// Requests without a token pass through to the handler. Presented tokens
    /// must be valid and match the audience binding. Use
    /// [`with_protected_resource`](Self::with_protected_resource) when a token
    /// must be required. The same resource URL, router placement, and metadata
    /// mounting rules apply to both methods. Advertised scopes are not enforced.
    ///
    /// # Errors
    ///
    /// Returns the same configuration errors as
    /// [`with_protected_resource`](Self::with_protected_resource), including
    /// rejection of query-bearing resource identifiers.
    pub fn with_optional_authentication_resource<I, T>(
        mut self,
        resource_path: impl AsRef<str>,
        audience_binding: AudienceBinding,
        scopes_supported: I,
    ) -> Result<(Self, ResourceMetadataService), ResourceMetadataError>
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        if self.resource_audiences.is_some() {
            return Err(ResourceMetadataError::ProtectedResourceAlreadyConfigured);
        }
        let base_url = self
            .config
            .base_url
            .as_ref()
            .ok_or(ResourceMetadataError::MissingBaseUrl)?;
        let resource_path = resource_path.as_ref();
        if !resource_path.starts_with('/')
            || resource_path.contains('#')
            || resource_path.contains('?')
        {
            return Err(ResourceMetadataError::InvalidResourcePath {
                path: resource_path.to_owned(),
            });
        }
        let relative = resource_path.parse::<Uri>().map_err(|_| {
            ResourceMetadataError::InvalidResourcePath {
                path: resource_path.to_owned(),
            }
        })?;
        if relative.scheme().is_some() || relative.authority().is_some() {
            return Err(ResourceMetadataError::InvalidResourcePath {
                path: resource_path.to_owned(),
            });
        }
        let Some(path_and_query) = relative.path_and_query() else {
            return Err(ResourceMetadataError::InvalidResourcePath {
                path: resource_path.to_owned(),
            });
        };
        let resource_uri = join_base_url(base_url, path_and_query).ok_or_else(|| {
            ResourceMetadataError::InvalidResourcePath {
                path: resource_path.to_owned(),
            }
        })?;
        let resource = parse_resource_identifier(&resource_uri.to_string())
            .map_err(ResourceMetadataError::InvalidResourceIdentifier)?;
        let audiences = audience_binding.into_audiences(&resource);
        if audiences.is_empty() {
            return Err(ResourceMetadataError::EmptyAudiences);
        }
        let metadata_url =
            well_known_url(&resource).map_err(ResourceMetadataError::WellKnownUrl)?;
        let derived = metadata_url.to_string();

        let mut metadata = self.config.validator.validator_metadata(Some(&resource));
        if let Some(configured) = metadata.resource_metadata.as_ref()
            && configured != &derived
        {
            return Err(ResourceMetadataError::MetadataUrlMismatch {
                configured: configured.clone(),
                derived,
            });
        }

        // `resource` is the deployment's source of truth. A custom metadata
        // provider may omit `resource`; fill it here so the emitted document
        // and the endpoint derived above always describe the same resource.
        metadata.resource = Some(resource);
        metadata.resource_metadata = Some(derived);

        let Some(mut document) = metadata.to_resource_metadata() else {
            return Err(ResourceMetadataError::DocumentUnavailable);
        };
        let scopes = scopes_supported
            .into_iter()
            .map(Into::into)
            .collect::<BTreeSet<_>>();
        if !scopes.is_empty() {
            document.scopes_supported = Some(scopes.into_iter().collect());
        }
        let body = serde_json::to_vec(&document).map_err(ResourceMetadataError::Serialization)?;
        let endpoint_uri = metadata_url.as_uri().clone();

        self.validator_data = ValidatorData {
            inner: Arc::new(metadata),
        };
        self.resource_audiences = Some(Arc::new(audiences));
        Ok((
            self,
            ResourceMetadataService::new(resource_uri, endpoint_uri, body),
        ))
    }

    /// Returns one order-safe layer that validates and requires a token.
    ///
    /// Unlike manually stacking [`ValidatorLayer`] and
    /// [`RequireAuthenticatedLayer`](super::RequireAuthenticatedLayer), this
    /// composite cannot be put in the wrong order.
    #[must_use]
    pub fn authenticated(&self) -> AuthenticatedLayer<V, E> {
        AuthenticatedLayer::new(self.clone())
    }

    /// Returns an order-safe layer requiring one exact audience value.
    ///
    /// Audience enforcement runs against the normalized `aud` values in
    /// [`ValidatedToken`], so this works the same way for JWT, opaque, and
    /// multi-source validators. A mismatch returns `401 invalid_token`.
    #[must_use]
    pub fn require_audience(&self, accepted_audience: impl Into<String>) -> AudienceLayer<V, E>
    where
        V: AccessTokenValidator,
    {
        AudienceLayer::new(self.clone(), vec![accepted_audience.into()])
    }

    /// Returns an order-safe layer accepting a token that contains at least
    /// one of the supplied audience values (OR-combined).
    #[must_use]
    pub fn require_any_audience<I, T>(&self, accepted_audiences: I) -> AudienceLayer<V, E>
    where
        V: AccessTokenValidator,
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        AudienceLayer::new(
            self.clone(),
            accepted_audiences.into_iter().map(Into::into).collect(),
        )
    }

    /// Builds only the inner audience-enforcement layer.
    ///
    /// It must be placed inside this validator layer. Most applications should
    /// prefer [`require_audience`](Self::require_audience) or
    /// [`require_any_audience`](Self::require_any_audience), which guarantee
    /// the ordering.
    #[must_use]
    pub fn audience_layer<I, T>(&self, accepted_audiences: I) -> RequireAudienceLayer<V::Claims, E>
    where
        V: AccessTokenValidator,
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        RequireAudienceLayer::with_options(
            accepted_audiences.into_iter().map(Into::into).collect(),
            self.error_body.clone(),
        )
    }

    /// Returns an order-safe layer applying a custom authorization check.
    ///
    /// The check receives the validator-independent normalized request,
    /// including `iss`, `aud`, and the source's claims. This permits
    /// source-aware policy while remaining compatible with multi-source
    /// validators. Return [`AuthorizationError::Forbidden`] for a `403` or
    /// [`AuthorizationError::InvalidToken`] for a `401`.
    #[must_use]
    pub fn authorize<F>(&self, check: F) -> AuthorizedLayer<V, F, E>
    where
        V: AccessTokenValidator,
        F: Fn(
                &huskarl_resource_server::validator::ValidatedRequest<V::Claims>,
            ) -> Result<(), AuthorizationError>
            + Send
            + Sync
            + 'static,
    {
        AuthorizedLayer::new(
            self.clone(),
            AuthorizeLayer::with_options(check, self.error_body.clone()),
        )
    }

    /// Builds only the inner custom-authorization layer.
    ///
    /// It must be placed inside this validator layer; prefer
    /// [`authorize`](Self::authorize) for an order-safe composition.
    #[must_use]
    pub fn authorization_layer<F>(&self, check: F) -> AuthorizeLayer<V::Claims, F, E>
    where
        V: AccessTokenValidator,
        F: Fn(
                &huskarl_resource_server::validator::ValidatedRequest<V::Claims>,
            ) -> Result<(), AuthorizationError>
            + Send
            + Sync
            + 'static,
    {
        AuthorizeLayer::with_options(check, self.error_body.clone())
    }

    /// Returns one order-safe layer that validates a token and requires every
    /// supplied scope (AND-combined).
    ///
    /// The claims type is derived from the validator itself, so scope
    /// middleware cannot accidentally inspect a different claims type.
    #[must_use]
    pub fn require_scopes<I, T>(&self, required_scopes: I) -> ScopedLayer<V, E>
    where
        V: AccessTokenValidator,
        V::Claims: HasScopes,
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        ScopedLayer::new(
            self.clone(),
            required_scopes.into_iter().map(Into::into).collect(),
        )
    }

    /// Builds only the inner scope-enforcement layer.
    ///
    /// This is useful for advanced nested middleware compositions. It must be
    /// placed inside this validator layer; most applications should prefer
    /// [`require_scopes`](Self::require_scopes), which guarantees the order.
    #[must_use]
    pub fn scope_layer<I, T>(&self, required_scopes: I) -> RequireScopesLayer<V::Claims, E>
    where
        V: AccessTokenValidator,
        V::Claims: HasScopes,
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        RequireScopesLayer::with_options(
            required_scopes.into_iter().map(Into::into).collect(),
            self.error_body.clone(),
        )
    }

    /// Returns the low-level
    /// [`RequireAuthenticatedLayer`](super::RequireAuthenticatedLayer)
    /// carrying this layer's error body.
    ///
    /// Stack it inside this [`ValidatorLayer`] to reject any request that did not
    /// present a valid token with `401 Unauthorized`, rather than letting an
    /// unauthenticated request reach the handler and relying on a
    /// [`ValidatedToken`] extractor to gate it. Prefer
    /// [`authenticated`](Self::authenticated) unless manually composing nested
    /// auth middleware.
    #[must_use]
    pub fn require_authenticated(&self) -> super::RequireAuthenticatedLayer<E> {
        super::RequireAuthenticatedLayer::with_options(self.error_body.clone())
    }
}

impl<V: ProvideValidatorMetadata, E: ErrorBody> Clone for ValidatorLayer<V, E> {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            validator_data: self.validator_data.clone(),
            error_body: self.error_body.clone(),
            extractor_error_body: self.extractor_error_body.clone(),
            resource_audiences: self.resource_audiences.clone(),
        }
    }
}

/// Shared, immutable validator state, held in an `Arc` by the layer and service.
#[derive(Debug)]
struct ValidatorConfig<V: ProvideValidatorMetadata> {
    validator: V,
    base_url: Option<Uri>,
}

impl<V, E, S> Layer<S> for ValidatorLayer<V, E>
where
    V: AccessTokenValidator + ProvideValidatorMetadata,
    E: ErrorBody,
    S: Clone,
{
    type Service = ValidatorService<V, E, S>;

    fn layer(&self, inner: S) -> Self::Service {
        ValidatorService::new(
            inner,
            self.config.clone(),
            self.validator_data.clone(),
            self.error_body.clone(),
            self.extractor_error_body.clone(),
            self.resource_audiences.clone(),
        )
    }
}

/// The [`Service`] produced by [`ValidatorLayer`]; you don't
/// normally name this directly.
pub struct ValidatorService<V, E, S>
where
    V: AccessTokenValidator + ProvideValidatorMetadata,
    E: ErrorBody,
    S: Clone,
{
    inner: S,
    config: Arc<ValidatorConfig<V>>,
    validator_data: ValidatorData,
    error_body: Option<E>,
    extractor_error_body: Option<ErrorBodyRenderer>,
    resource_audiences: Option<Arc<Vec<String>>>,
}

impl<V, E, S> Clone for ValidatorService<V, E, S>
where
    V: AccessTokenValidator + ProvideValidatorMetadata,
    E: ErrorBody,
    S: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            config: self.config.clone(),
            validator_data: self.validator_data.clone(),
            error_body: self.error_body.clone(),
            extractor_error_body: self.extractor_error_body.clone(),
            resource_audiences: self.resource_audiences.clone(),
        }
    }
}

impl<V, E, S> ValidatorService<V, E, S>
where
    V: AccessTokenValidator + ProvideValidatorMetadata,
    E: ErrorBody,
    S: Clone,
{
    /// Constructs the service for [`ValidatorLayer`]'s [`Layer`] implementation.
    fn new(
        inner: S,
        config: Arc<ValidatorConfig<V>>,
        validator_data: ValidatorData,
        error_body: Option<E>,
        extractor_error_body: Option<ErrorBodyRenderer>,
        resource_audiences: Option<Arc<Vec<String>>>,
    ) -> Self {
        Self {
            inner,
            config,
            validator_data,
            error_body,
            extractor_error_body,
            resource_audiences,
        }
    }
}

impl<V, E, S> Service<Request> for ValidatorService<V, E, S>
where
    V: AccessTokenValidator + ProvideValidatorMetadata + 'static,
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

    fn call(&mut self, mut req: Request) -> Self::Future {
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let config = self.config.clone();
        let validator_data = self.validator_data.clone();
        let error_body = self.error_body.clone();
        let extractor_error_body = self.extractor_error_body.clone();
        let resource_audiences = self.resource_audiences.clone();

        Box::pin(async move {
            let Some(uri) = get_request_uri(&config, &req) else {
                // The configured base URL was validated when the layer was
                // built, so this can only reflect an unexpected URI component
                // combination. Fail closed rather than validating a DPoP proof
                // against a different origin-form URI.
                let mut response = http::Response::new(axum_core::body::Body::empty());
                *response.status_mut() = http::StatusCode::INTERNAL_SERVER_ERROR;
                return Ok(response.into_response());
            };

            req.extensions_mut().insert(validator_data.clone());
            if let Some(renderer) = extractor_error_body {
                req.extensions_mut().insert(renderer);
            }

            let cert = req
                .extensions()
                .get::<ClientCertDer>()
                .map(|c| c.0.as_slice());

            let validation_result = config
                .validator
                .validate_request(req.headers(), req.method(), &uri, cert)
                .await;

            let dpop_nonce = validation_result.dpop_nonce;

            match validation_result.outcome {
                Ok(Some(validated_request)) => {
                    if let Some(accepted_audiences) = resource_audiences
                        && !accepted_audiences
                            .iter()
                            .any(|accepted| validated_request.aud.contains(accepted))
                    {
                        let challenge = huskarl_resource_server::error::Challenge::new(
                            TokenValidationError::Client(TokenErrorCode::InvalidToken),
                        )
                        .with_description(
                            "The access token audience does not match the protected resource",
                        );
                        let challenges = validator_data.inner.challenges_from(
                            None,
                            Some(&challenge),
                            None,
                            None,
                        );
                        let details = FailureDetails {
                            error_code: Some(TokenErrorCode::InvalidToken),
                            error_description: challenge.description,
                            required_scopes: None,
                        };
                        return Ok(challenge_response(
                            &error_body,
                            http::StatusCode::UNAUTHORIZED,
                            &details,
                            challenges,
                            dpop_nonce,
                            None,
                        ));
                    }
                    req.extensions_mut().insert(HasValidToken);
                    req.extensions_mut()
                        .insert(ValidatedToken(Arc::new(validated_request)));
                }
                Ok(None) => {}
                Err(err) => {
                    let challenge = err.challenge();
                    let mut rejection = validator_data.inner.rejection_from(&err, &challenge, None);
                    rejection.dpop_nonce = dpop_nonce;
                    // Server-side failures deliberately reveal no error details
                    // (see `TokenValidationError`); pass none to the body either.
                    let details = match &challenge.error {
                        TokenValidationError::Client(code) => FailureDetails {
                            error_code: Some(*code),
                            error_description: challenge.description.clone(),
                            required_scopes: None,
                        },
                        TokenValidationError::Server { .. } => FailureDetails::unauthenticated(),
                    };
                    return Ok(challenge_response(
                        &error_body,
                        rejection.status,
                        &details,
                        rejection.www_authenticate,
                        rejection.dpop_nonce,
                        rejection.retry_after,
                    ));
                }
            }

            let mut response = inner.call(req).await?;

            if let Some(nonce) = dpop_nonce
                && let Ok(value) = http::HeaderValue::try_from(&nonce)
            {
                response.headers_mut().insert(DPOP_NONCE.clone(), value);
            }

            Ok(response)
        })
    }
}

/// The owned failure details a rejection site hands to [`challenge_response`],
/// borrowed into the [`ErrorDetails`] the [`ErrorBody`] sees (alongside the
/// final challenge strings).
pub(crate) struct FailureDetails {
    pub error_code: Option<TokenErrorCode>,
    pub error_description: Option<String>,
    pub required_scopes: Option<Arc<Vec<String>>>,
}

impl FailureDetails {
    /// An unauthenticated request: per RFC 6750 §3.1 the challenge carries no
    /// `error` attribute, so there are no details to pass.
    pub(crate) fn unauthenticated() -> Self {
        Self {
            error_code: None,
            error_description: None,
            required_scopes: None,
        }
    }
}

// `&Option<E>` matches how callers hold `error_body`; no need to map to `Option<&E>`.
#[allow(clippy::ref_option)]
pub(crate) fn challenge_response<E: ErrorBody>(
    error_body: &Option<E>,
    status: http::StatusCode,
    details: &FailureDetails,
    challenges: Vec<String>,
    dpop_nonce: Option<String>,
    retry_after: Option<huskarl_resource_server::core::platform::Duration>,
) -> Response {
    match error_body {
        Some(eb) => {
            let body = eb.error_body(&ErrorDetails {
                status,
                error_code: details.error_code,
                error_description: details.error_description.as_deref(),
                required_scopes: details.required_scopes.as_deref().map(Vec::as_slice),
                challenges: &challenges,
            });
            ChallengeResponse {
                status,
                challenges,
                dpop_nonce,
                retry_after,
                body,
            }
            .into_response()
        }
        None => ChallengeResponse {
            status,
            challenges,
            dpop_nonce,
            retry_after,
            body: (),
        }
        .into_response(),
    }
}

fn get_request_uri<V: ProvideValidatorMetadata>(
    config: &ValidatorConfig<V>,
    req: &Request,
) -> Option<Uri> {
    if let Some(request_url) = req.extensions().get::<RequestUrl>() {
        return Some(request_url.0.clone());
    }

    let uri = crate::extensions::original_uri(req.uri(), req.extensions());
    let Some(base) = &config.base_url else {
        return Some(uri.clone());
    };

    let path_and_query = uri
        .path_and_query()
        .cloned()
        .unwrap_or_else(|| http::uri::PathAndQuery::from_static("/"));
    join_base_url(base, &path_and_query)
}
