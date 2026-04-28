use std::{marker::PhantomData, pin::Pin, sync::Arc};

use axum_core::{extract::Request, response::IntoResponse, response::Response};
use http::Uri;
use huskarl_resource_server::{
    error::ToRfc6750Error as _,
    validator::{AccessTokenValidator, metadata::ProvideValidatorMetadata},
};
use tower::{Layer, Service};

use crate::extensions::{ClientCertDer, HasValidToken, RequestUrl, ValidatedToken, ValidatorData};
use crate::layers::ClaimsContext;
use crate::response::{ChallengeResponse, ErrorBody};

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
    pub fn new(
        validator: V,
        #[builder(into)] base_url: Option<String>,
        #[builder(setters(name = error_body_internal, vis = ""))]
        error_body: Option<E>,
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
    pub fn builder() -> ValidatorLayerBuilder<V, ()> {
        ValidatorLayer::<V, ()>::__builder()
    }
}

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
    pub fn claims_context<C>(&self) -> ClaimsContext<C, E> {
        ClaimsContext {
            error_body: self.error_body.clone(),
            phantom: PhantomData,
        }
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
                    let status = err.token_error().suggested_status();
                    let challenges = config
                        .validator_data
                        .inner
                        .challenges(Some(&err), None, None);
                    return Ok(challenge_response(&error_body, status, challenges, dpop_nonce));
                }
            }

            let mut response = inner.call(req).await?;

            if let Some(nonce) = dpop_nonce {
                if let Ok(value) = http::HeaderValue::from_str(&nonce) {
                    response.headers_mut().insert(
                        http::HeaderName::from_static("dpop-nonce"),
                        value,
                    );
                }
            }

            Ok(response)
        })
    }
}

pub(crate) fn challenge_response<E: ErrorBody>(
    error_body: &Option<E>,
    status: http::StatusCode,
    challenges: Vec<String>,
    dpop_nonce: Option<String>,
) -> Response {
    match error_body {
        Some(eb) => {
            let body = eb.error_body(status, &challenges);
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
                    .map(|pq| pq.as_str())
                    .unwrap_or("/");
                format!("{base}{pq}").parse().ok()
            })
        })
        .unwrap_or_else(|| req.uri().clone())
}
