use std::{marker::PhantomData, pin::Pin, sync::Arc};

use axum_core::{extract::Request, response::IntoResponse, response::Response};
use http::Uri;
use huskarl_resource_server::{
    error::{ToRfc6750Error as _, TokenErrorCode, TokenValidationError},
    validator::{AccessTokenValidator, metadata::ProvideValidatorMetadata},
};
use tower::{Layer, Service};

use crate::extensions::{ClientCertDer, HasValidToken, RequestUrl, ValidatorData};
use crate::extractors::{HasClaims, ValidatedToken};
use crate::layers::ClaimsContext;
use crate::response::{ChallengeResponse, DPOP_NONCE, ErrorBody, ErrorDetails};

/// Tower [`Layer`] that validates the access token on each request
/// and injects the claims for extractors.
///
/// Validates bearer/DPoP/mTLS tokens via the wrapped [`AccessTokenValidator`],
/// inserts a [`ValidatedToken`] (plus DPoP/metadata extensions) on success, and
/// returns an RFC 6750 `WWW-Authenticate` challenge on failure. Build one with
/// [`builder`](Self::builder); it must be the outermost auth layer, with any
/// [`RequireScopesLayer`](super::RequireScopesLayer) nested inside. Call
/// [`claims_context`](Self::claims_context) to attach scope middleware.
pub struct ValidatorLayer<V: ProvideValidatorMetadata, E: ErrorBody = ()> {
    config: Arc<ValidatorConfig<V>>,
    error_body: Option<E>,
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
    /// `base_url` (optional) is this resource server's own externally-visible base
    /// URL — scheme + authority, e.g. `https://api.example.com`. It is used for two
    /// things:
    ///
    /// 1. the resource URL advertised in `WWW-Authenticate` / RFC 9728 metadata, and
    /// 2. **DPoP `htu` binding** — the layer reconstructs the request URL as
    ///    `base_url` + the request path and passes it to the validator, which checks
    ///    it against the proof's `htu` claim.
    ///
    /// # Security
    ///
    /// For (2), the origin used for `htu` must be one the client cannot spoof:
    /// a static `base_url` you configure, or — when one server fronts several
    /// origins — a [`RequestUrl`] you inject from forwarded headers your
    /// deployment makes trustworthy. Never derive it from the raw `Host` header
    /// or an untrusted forwarded header: a request could set it to match a
    /// captured proof's `htu` and pass the check. With neither configured the
    /// request URL is origin-form and the validator fails closed with an
    /// integration error rather than checking `htu`. See the huskarl-resource-server
    /// DPoP how-to guide for reconstructing the origin behind a proxy.
    pub fn new(
        validator: V,
        #[builder(into)] base_url: Option<String>,
        #[builder(setters(name = error_body_internal, vis = ""))] error_body: Option<E>,
    ) -> Self {
        let validator_metadata = validator.validator_metadata(base_url.as_deref());

        Self {
            config: Arc::new(ValidatorConfig {
                validator,
                base_url,
                validator_data: ValidatorData {
                    inner: Arc::new(validator_metadata),
                },
            }),
            error_body,
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
    /// Binds the token claims type `C` and returns a
    /// [`ClaimsContext`] for attaching scope-enforcement
    /// middleware, carrying this layer's configured error body.
    pub fn claims_context<C>(&self) -> ClaimsContext<C, E> {
        ClaimsContext {
            error_body: self.error_body.clone(),
            phantom: PhantomData,
        }
    }

    /// Like [`claims_context`](Self::claims_context), but compiler-checked
    /// against the app state: binds the claims type through `S`'s
    /// [`HasClaims`] declaration and requires it to match the wrapped
    /// validator's claims type. Prefer this form — a mismatch between the
    /// state's declared claims type and the validator's is the one wiring
    /// error `claims_context` cannot catch, and it otherwise surfaces only at
    /// runtime, as every extraction failing with 401.
    ///
    /// ```compile_fail
    /// use huskarl_axum::extractors::HasClaims;
    /// use huskarl_axum::layers::ValidatorLayer;
    /// use huskarl_axum::resource_server::validator::custom::CustomValidator;
    ///
    /// struct StateClaims;
    /// struct ValidatorClaims;
    ///
    /// struct AppState;
    /// impl HasClaims for AppState {
    ///     type Claims = StateClaims;
    /// }
    ///
    /// // The state declares StateClaims but the validator produces
    /// // ValidatorClaims — this must not compile.
    /// fn mismatch(layer: &ValidatorLayer<CustomValidator<ValidatorClaims>>) {
    ///     let _ = layer.claims_context_for::<AppState>();
    /// }
    /// ```
    pub fn claims_context_for<S>(&self) -> ClaimsContext<S::Claims, E>
    where
        S: HasClaims,
        V: AccessTokenValidator<Claims = S::Claims>,
    {
        ClaimsContext {
            error_body: self.error_body.clone(),
            phantom: PhantomData,
        }
    }

    /// Returns a [`RequireAuthenticatedLayer`](super::RequireAuthenticatedLayer)
    /// carrying this layer's error body.
    ///
    /// Stack it inside this [`ValidatorLayer`] to reject any request that did not
    /// present a valid token with `401 Unauthorized`, rather than letting an
    /// unauthenticated request reach the handler and relying on a
    /// [`ValidatedToken`](crate::extractors::ValidatedToken) extractor to gate it.
    #[must_use]
    pub fn require_authenticated(&self) -> super::RequireAuthenticatedLayer<E> {
        super::RequireAuthenticatedLayer::with_options(self.error_body.clone())
    }
}

impl<V: ProvideValidatorMetadata, E: ErrorBody> Clone for ValidatorLayer<V, E> {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            error_body: self.error_body.clone(),
        }
    }
}

/// Shared, immutable validator state, held in an `Arc` by the layer and service.
#[derive(Debug)]
pub struct ValidatorConfig<V: ProvideValidatorMetadata> {
    validator: V,
    base_url: Option<String>,
    validator_data: ValidatorData,
}

impl<V, E, S> Layer<S> for ValidatorLayer<V, E>
where
    V: AccessTokenValidator + ProvideValidatorMetadata,
    E: ErrorBody,
    S: Clone,
{
    type Service = ValidatorService<V, E, S>;

    fn layer(&self, inner: S) -> Self::Service {
        ValidatorService::new(inner, self.config.clone(), self.error_body.clone())
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
    error_body: Option<E>,
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
            error_body: self.error_body.clone(),
        }
    }
}

impl<V, E, S> ValidatorService<V, E, S>
where
    V: AccessTokenValidator + ProvideValidatorMetadata,
    E: ErrorBody,
    S: Clone,
{
    /// Constructs the service directly; normally produced by [`ValidatorLayer`]'s
    /// [`Layer`] impl.
    pub fn new(inner: S, config: Arc<ValidatorConfig<V>>, error_body: Option<E>) -> Self {
        Self {
            inner,
            config,
            error_body,
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
        let error_body = self.error_body.clone();

        Box::pin(async move {
            let uri = get_request_uri(&config, &req);

            req.extensions_mut().insert(config.validator_data.clone());

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
                    req.extensions_mut().insert(HasValidToken);
                    req.extensions_mut()
                        .insert(ValidatedToken(Arc::new(validated_request)));
                }
                Ok(None) => {}
                Err(err) => {
                    let token_error = err.token_error();
                    let status = token_error.suggested_status();
                    // Server-side failures deliberately reveal no error details
                    // (see `TokenValidationError`); pass none to the body either.
                    let details = match token_error {
                        TokenValidationError::Client(code) => FailureDetails {
                            error_code: Some(code),
                            error_description: err.error_description(),
                            required_scopes: None,
                        },
                        TokenValidationError::Server(_) => FailureDetails::unauthenticated(),
                    };
                    let challenges = config
                        .validator_data
                        .inner
                        .challenges(Some(&err), None, None);
                    return Ok(challenge_response(
                        &error_body,
                        status,
                        &details,
                        challenges,
                        dpop_nonce,
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
                body,
            }
            .into_response()
        }
        None => ChallengeResponse {
            status,
            challenges,
            dpop_nonce,
            body: (),
        }
        .into_response(),
    }
}

fn get_request_uri<V: ProvideValidatorMetadata>(config: &ValidatorConfig<V>, req: &Request) -> Uri {
    req.extensions()
        .get::<RequestUrl>()
        .map(|r| r.0.clone())
        .or_else(|| {
            config.base_url.as_ref().and_then(|base| {
                let base = base.trim_end_matches('/');
                let pq = req
                    .uri()
                    .path_and_query()
                    .map_or("/", http::uri::PathAndQuery::as_str);
                format!("{base}{pq}").parse().ok()
            })
        })
        .unwrap_or_else(|| req.uri().clone())
}
