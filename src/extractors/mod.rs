//! Axum extractors for validated access tokens.
//!
//! [`ValidatedToken<C>`](ValidatedToken) is extracted directly in a handler and
//! works with any router state. Applications that prefer to declare their
//! claims type on state can use [`TokenFor<S>`](TokenFor) and [`HasClaims`].

use std::convert::Infallible;
use std::ops::Deref;
use std::sync::Arc;

use axum_core::{
    extract::{FromRequestParts, OptionalFromRequestParts},
    response::{IntoResponse, Response},
};
use http::{StatusCode, request::Parts};
use huskarl_resource_server::validator::ValidatedRequest;

use crate::extensions::ValidatorData;
use crate::response::{ChallengeResponse, ErrorBodyRenderer, ErrorDetails};

/// A validated access token and its claims, inserted into the request by the
/// [`ValidatorLayer`](crate::layers::ValidatorLayer).
///
/// Extract it in a handler as `ValidatedToken<MyClaims>` (the claims type must
/// match the validator's), or as
/// `Option<ValidatedToken<MyClaims>>` to tolerate unauthenticated requests.
/// Derefs to the underlying [`ValidatedRequest`].
///
/// In tests or custom middleware, construct one directly with
/// [`new`](Self::new).
pub struct ValidatedToken<Claims>(pub(crate) Arc<ValidatedRequest<Claims>>);

impl<Claims> ValidatedToken<Claims> {
    /// Wraps a [`ValidatedRequest`], for code other than the
    /// [`ValidatorLayer`](crate::layers::ValidatorLayer) that needs to produce
    /// a token: a handler unit test, a router test that inserts the token into
    /// request extensions before calling the service, or custom middleware
    /// that synthesizes a token from another auth scheme.
    ///
    /// # Examples
    ///
    /// Unit-testing a handler directly, without a validator:
    ///
    /// ```
    /// use huskarl_axum::extractors::ValidatedToken;
    /// use huskarl_axum::resource_server::validator::ValidatedRequest;
    ///
    /// struct MyClaims {
    ///     user_id: String,
    /// }
    ///
    /// async fn user(token: ValidatedToken<MyClaims>) -> String {
    ///     format!("User ID: {}", token.claims.user_id)
    /// }
    ///
    /// let token = ValidatedToken::new(ValidatedRequest {
    ///     iss: None,
    ///     sub: None,
    ///     aud: Vec::new(),
    ///     jti: None,
    ///     iat: None,
    ///     exp: None,
    ///     cnf: None,
    ///     claims: MyClaims { user_id: "alice".into() },
    ///     introspection_jwt: None,
    /// });
    ///
    /// # let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
    /// # rt.block_on(async {
    /// assert_eq!(user(token).await, "User ID: alice");
    /// # });
    /// ```
    #[must_use]
    pub fn new(request: ValidatedRequest<Claims>) -> Self {
        Self(Arc::new(request))
    }
}

impl<Claims> From<ValidatedRequest<Claims>> for ValidatedToken<Claims> {
    fn from(request: ValidatedRequest<Claims>) -> Self {
        Self::new(request)
    }
}

impl<Claims> Deref for ValidatedToken<Claims> {
    type Target = ValidatedRequest<Claims>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<Claims> std::fmt::Debug for ValidatedToken<Claims> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Claims may contain PII, authorization data, or a raw introspection
        // JWT. Do not make those values accidentally loggable through this
        // convenience wrapper.
        f.debug_struct("ValidatedToken").finish_non_exhaustive()
    }
}

impl<Claims> Clone for ValidatedToken<Claims> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

/// Names the token claims type for the app's router state.
///
/// Implement this on your `State` type when handlers should use
/// [`TokenFor<State>`](TokenFor) instead of spelling their claims type as
/// [`ValidatedToken<MyClaims>`](ValidatedToken). Direct `ValidatedToken`
/// extraction does not require this trait or any particular router state.
/// This trait is only a naming convenience; it does not configure or alter the
/// validator.
pub trait HasClaims: Send + Sync + 'static {
    /// The token claims type the validator deserializes into.
    type Claims: Send + Sync + 'static;
}

/// Forwards to the inner state, so `Arc<MyState>` works as router state
/// without a separate `HasClaims` impl.
impl<C: HasClaims> HasClaims for std::sync::Arc<C> {
    type Claims = C::Claims;
}

/// The validated-token extractor for a given app state's claims type.
///
/// `TokenFor<AppState>` is [`ValidatedToken`] of `AppState`'s
/// [`HasClaims::Claims`], so handlers name the state they already know
/// instead of repeating the claims type — the claims type stays declared in
/// exactly one place, and a handler cannot name a different one through this
/// alias. `ValidatedToken<MyClaims>` remains the simpler form for stateless
/// routers. `Option<TokenFor<AppState>>` tolerates unauthenticated requests,
/// like the underlying extractor.
pub type TokenFor<S> = ValidatedToken<<S as HasClaims>::Claims>;

impl<S, Claims> FromRequestParts<S> for ValidatedToken<Claims>
where
    S: Send + Sync,
    Claims: Send + Sync + 'static,
{
    type Rejection = ChallengeResponse<Response>;

    // `async fn` reads better here than `impl Future` + `std::future::ready`.
    #[allow(clippy::unused_async_trait_impl)]
    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        if let Some(claims) = parts.extensions.get::<ValidatedToken<Claims>>().cloned() {
            return Ok(claims);
        }

        let challenges = parts.extensions.get::<ValidatorData>().map_or_else(
            || vec!["Bearer".to_string()],
            |vd| vd.inner.unauthenticated_challenges(None),
        );

        let details = ErrorDetails {
            status: StatusCode::UNAUTHORIZED,
            error_code: None,
            error_description: None,
            required_scopes: None,
            challenges: &challenges,
        };
        let body = parts
            .extensions
            .get::<ErrorBodyRenderer>()
            .map_or_else(|| ().into_response(), |renderer| renderer.render(&details));

        Err(ChallengeResponse {
            status: StatusCode::UNAUTHORIZED,
            challenges,
            dpop_nonce: None,
            retry_after: None,
            body,
        })
    }
}

/// Supports `Option<ValidatedToken<Claims>>` as an extractor: returns
/// `Some(token)` when the validator has authenticated the request and
/// `None` otherwise — never rejects.
impl<S, Claims> OptionalFromRequestParts<S> for ValidatedToken<Claims>
where
    S: Send + Sync,
    Claims: Send + Sync + 'static,
{
    type Rejection = Infallible;

    #[allow(clippy::unused_async_trait_impl)]
    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Option<Self>, Self::Rejection> {
        Ok(parts.extensions.get::<ValidatedToken<Claims>>().cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validated_token_debug_omits_claims_and_introspection_jwt() {
        #[derive(Debug)]
        struct SecretClaims(&'static str);

        let token = ValidatedToken::new(ValidatedRequest {
            iss: Some("https://issuer.example".into()),
            sub: Some("alice".into()),
            aud: vec!["api".into()],
            jti: None,
            iat: None,
            exp: None,
            cnf: None,
            claims: SecretClaims("top-secret-claim"),
            introspection_jwt: Some("top-secret-jwt".into()),
        });

        let debug = format!("{token:?}");
        assert_eq!(debug, "ValidatedToken { .. }");
        assert!(!debug.contains(token.claims.0));
        assert!(!debug.contains("top-secret-jwt"));
    }
}
