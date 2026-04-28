use std::{marker::PhantomData, pin::Pin, sync::Arc};

use axum_core::{extract::Request, response::Response};
use http::StatusCode;
use huskarl_resource_server::error::InsufficientScope;
use tower::{Layer, Service};

use crate::extensions::{AncestorRequiredScopes, ValidatedToken, ValidatorData};
use crate::layers::validator::challenge_response;
use crate::response::ErrorBody;

pub trait HasScopes {
    fn scopes(&self) -> Option<Vec<String>>;
}


#[derive(Clone)]
pub struct RequireScopesLayer<C, E: ErrorBody = ()> {
    required_scopes: Vec<String>,
    error_body: Option<E>,
    phantom: PhantomData<C>,
}

impl<C> RequireScopesLayer<C> {
    pub fn new(scopes: Vec<String>) -> Self {
        RequireScopesLayer {
            required_scopes: scopes,
            error_body: None,
            phantom: PhantomData,
        }
    }
}

impl<C, E: ErrorBody> RequireScopesLayer<C, E> {
    pub(crate) fn with_options(scopes: Vec<String>, error_body: Option<E>) -> Self {
        RequireScopesLayer {
            required_scopes: scopes,
            error_body,
            phantom: PhantomData,
        }
    }
}

impl<C, E: ErrorBody, S> Layer<S> for RequireScopesLayer<C, E> {
    type Service = RequireScopesService<C, E, S>;

    fn layer(&self, inner: S) -> Self::Service {
        RequireScopesService::new(inner, self.required_scopes.clone(), self.error_body.clone())
    }
}

#[derive(Clone)]
pub struct RequireScopesService<C, E: ErrorBody, S> {
    inner: S,
    required_scopes: Vec<String>,
    error_body: Option<E>,
    phantom: PhantomData<C>,
}

impl<C, E: ErrorBody, S> RequireScopesService<C, E, S> {
    pub fn new(inner: S, scopes: Vec<String>, error_body: Option<E>) -> Self {
        Self {
            inner,
            required_scopes: scopes,
            error_body,
            phantom: PhantomData,
        }
    }
}

impl<C, E, S> Service<Request> for RequireScopesService<C, E, S>
where
    S: Service<Request, Response = Response> + Send + Clone + 'static,
    S::Future: Send + 'static,
    C: HasScopes + Send + Sync + 'static,
    E: ErrorBody,
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
        let required_scopes = self.required_scopes.clone();
        let error_body = self.error_body.clone();

        Box::pin(async move {
            let ancestor_required_scopes = req.extensions().get::<AncestorRequiredScopes>();

            let all_required_scopes: Arc<Vec<String>> = Arc::new(
                ancestor_required_scopes
                    .into_iter()
                    .flat_map(|c| c.0.as_ref())
                    .chain(required_scopes.iter())
                    .cloned()
                    .collect(),
            );

            req.extensions_mut()
                .insert(AncestorRequiredScopes(all_required_scopes.clone()));

            let validator_data = req
                .extensions()
                .get::<ValidatorData>()
                .expect("Validator must be base layer");

            let Some(token) = req.extensions().get::<ValidatedToken<C>>() else {
                // We do not know all the claims for the route, so we'll have to just return what we know.
                // We report ancestor required scopes, but do not know about nested scope middleware.
                let challenges = validator_data
                    .inner
                    .unauthenticated_challenges(Some(&all_required_scopes.join(" ")));
                return Ok(challenge_response(
                    &error_body,
                    StatusCode::UNAUTHORIZED,
                    challenges,
                    None,
                ));
            };

            let scopes: Vec<_> = token.claims.scopes().unwrap_or_default();

            // N^2, should be cheaper than constructing a HashSet for small N?
            for scp in &required_scopes {
                if !scopes.contains(scp) {
                    let challenges = validator_data.inner.challenges(
                        Some(&InsufficientScope),
                        Some(&all_required_scopes.join(" ")),
                        None,
                    );
                    return Ok(challenge_response(
                        &error_body,
                        StatusCode::FORBIDDEN,
                        challenges,
                        None,
                    ));
                }
            }

            inner.call(req).await
        })
    }
}
