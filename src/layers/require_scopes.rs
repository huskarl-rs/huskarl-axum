use std::{marker::PhantomData, pin::Pin, sync::Arc};

use axum_core::{
    extract::Request,
    response::{IntoResponse, Response},
};
use http::StatusCode;
use huskarl_resource_server::error::{InsufficientScope, ToRfc6750Error as _, TokenErrorCode};
use tower::{Layer, Service};

use crate::extensions::{AncestorRequiredScopes, ValidatorData};
use crate::extractors::ValidatedToken;
use crate::layers::validator::{FailureDetails, challenge_response};
use crate::response::ErrorBody;

/// Checks the scopes granted to a token, for [`RequireScopesLayer`] enforcement.
///
/// Implement this on your claims type. Scope comparisons must be exact: a
/// granted `read-all` scope must not satisfy a requirement for `read`.
pub trait HasScopes {
    /// Returns whether the token grants `scope`.
    fn has_scope(&self, scope: &str) -> bool;
}

impl<E> HasScopes for huskarl_resource_server::validator::rfc9068::Rfc9068AccessTokenClaims<E> {
    fn has_scope(&self, scope: &str) -> bool {
        self.scope
            .as_ref()
            .is_some_and(|granted| granted.split_whitespace().any(|token| token == scope))
    }
}

/// Enforces that the validated token carries every scope in `required_scopes`.
///
/// Must be stacked **inside** a [`ValidatorLayer`](super::ValidatorLayer): it
/// reads `ValidatorData` and (optionally) `ValidatedToken<C>` from request
/// extensions. If those are missing, the request short-circuits with a
/// `500 Internal Server Error` rather than panicking — this almost always
/// indicates a middleware-ordering bug. Prefer
/// [`ValidatorLayer::require_scopes`](super::ValidatorLayer::require_scopes),
/// which composes validation and scope enforcement in the correct order.
#[derive(Clone)]
pub struct RequireScopesLayer<C, E: ErrorBody = ()> {
    required_scopes: Vec<String>,
    error_body: Option<E>,
    phantom: PhantomData<C>,
}

impl<C> RequireScopesLayer<C> {
    /// Creates a layer requiring every scope in `scopes` (AND-combined).
    ///
    /// Must sit inside a [`ValidatorLayer`](super::ValidatorLayer); prefer its
    /// [`require_scopes`](super::ValidatorLayer::require_scopes) method, which
    /// returns an order-safe composite layer.
    #[must_use]
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

/// The [`Service`] produced by [`RequireScopesLayer`]; you don't
/// normally name this directly.
pub struct RequireScopesService<C, E: ErrorBody, S> {
    inner: S,
    required_scopes: Vec<String>,
    error_body: Option<E>,
    phantom: PhantomData<C>,
}

impl<C, E: ErrorBody, S: Clone> Clone for RequireScopesService<C, E, S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            required_scopes: self.required_scopes.clone(),
            error_body: self.error_body.clone(),
            phantom: PhantomData,
        }
    }
}

impl<C, E: ErrorBody, S> RequireScopesService<C, E, S> {
    /// Constructs the service directly; normally produced by
    /// [`RequireScopesLayer`]'s [`Layer`] impl.
    fn new(inner: S, scopes: Vec<String>, error_body: Option<E>) -> Self {
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

            let Some(validator_data) = req.extensions().get::<ValidatorData>() else {
                // ValidatorData is only inserted by ValidatorLayer. Missing it means
                // RequireScopesLayer is stacked outside (or without) a validator —
                // a configuration bug. Fail closed with 500 instead of panicking so a
                // single misconfigured route can't take the whole server down.
                let mut resp = http::Response::new(axum_core::body::Body::empty());
                *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                return Ok(resp.into_response());
            };

            let Some(token) = req.extensions().get::<ValidatedToken<C>>() else {
                // We do not know all the claims for the route, so we'll have to just return what we know.
                // We report ancestor required scopes, but do not know about nested scope middleware.
                let challenges = validator_data
                    .inner
                    .unauthenticated_challenges(Some(&all_required_scopes.join(" ")));
                // Unauthenticated, so no error code (RFC 6750 §3.1) — but the
                // required scopes are known and worth passing to the body.
                let details = FailureDetails {
                    error_code: None,
                    error_description: None,
                    required_scopes: Some(all_required_scopes.clone()),
                };
                return Ok(challenge_response(
                    &error_body,
                    StatusCode::UNAUTHORIZED,
                    &details,
                    challenges,
                    None,
                    None,
                ));
            };

            for scp in &required_scopes {
                if !token.claims.has_scope(scp) {
                    let insufficient = InsufficientScope::new(scp.clone());
                    let challenge = insufficient.challenge();
                    let challenges = validator_data.inner.challenges_from(
                        insufficient.attempted_scheme(),
                        Some(&challenge),
                        Some(&all_required_scopes.join(" ")),
                        None,
                    );
                    let details = FailureDetails {
                        error_code: Some(TokenErrorCode::InsufficientScope),
                        error_description: challenge.description,
                        required_scopes: Some(all_required_scopes.clone()),
                    };
                    return Ok(challenge_response(
                        &error_body,
                        StatusCode::FORBIDDEN,
                        &details,
                        challenges,
                        None,
                        None,
                    ));
                }
            }

            inner.call(req).await
        })
    }
}

#[cfg(test)]
mod tests {
    use huskarl_resource_server::validator::rfc9068::Rfc9068AccessTokenClaims;

    use super::HasScopes as _;

    fn claims(scope: Option<&str>) -> Rfc9068AccessTokenClaims {
        Rfc9068AccessTokenClaims {
            client_id: "client".into(),
            auth_time: None,
            acr: None,
            amr: Vec::new(),
            scope: scope.map(str::to_owned),
            extra_claims: (),
        }
    }

    #[test]
    fn rfc9068_scopes_are_exact_space_separated_tokens() {
        let claims = claims(Some("read  write-all"));

        assert!(claims.has_scope("read"));
        assert!(claims.has_scope("write-all"));
        assert!(!claims.has_scope("write"));
    }

    #[test]
    fn rfc9068_missing_scope_grants_nothing() {
        assert!(!claims(None).has_scope("read"));
    }
}
