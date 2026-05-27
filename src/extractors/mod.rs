//! Axum extractors for validated access tokens.
//!
//! [`ValidatedToken<C>`](ValidatedToken) is extracted in a handler; the claims
//! type `C` is tied to the router state via [`HasClaims`], so a handler asking
//! for the wrong claims type fails to compile rather than returning 401 at
//! runtime.

use std::convert::Infallible;
use std::ops::Deref;
use std::sync::Arc;

use axum_core::extract::{FromRequestParts, OptionalFromRequestParts};
use http::{StatusCode, request::Parts};
use huskarl_resource_server::validator::ValidatedRequest;

use crate::extensions::ValidatorData;
use crate::response::ChallengeResponse;

/// A validated access token and its claims, inserted into the request by the
/// [`ValidatorLayer`](crate::layers::ValidatorLayer).
///
/// Extract it in a handler as `ValidatedToken<MyClaims>` (the claims type must
/// match the validator's, enforced via [`HasClaims`]), or as
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
    ///     issuer: None,
    ///     subject: None,
    ///     audience: Vec::new(),
    ///     jti: None,
    ///     issued_at: None,
    ///     expiration: None,
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

/// Names the token claims type for the app's router state.
///
/// Implement this on your `State` type so that handlers can extract
/// `ValidatedToken<MyClaims>` and the compiler can verify they ask for the
/// same claims type the [`ValidatorLayer`](crate::layers::ValidatorLayer)
/// was built with. A handler that asks for a different claims type fails
/// to compile rather than silently returning 401 at runtime.
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
/// exactly one place, and a handler cannot name a different one. Prefer this
/// form; `ValidatedToken<MyClaims>` remains for naming the claims type
/// directly. `Option<TokenFor<AppState>>` tolerates unauthenticated requests,
/// like the underlying extractor.
pub type TokenFor<S> = ValidatedToken<<S as HasClaims>::Claims>;

impl<S, Claims> FromRequestParts<S> for ValidatedToken<Claims>
where
    S: HasClaims<Claims = Claims>,
    Claims: Send + Sync + 'static,
{
    type Rejection = ChallengeResponse;

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

        Err(ChallengeResponse {
            status: StatusCode::UNAUTHORIZED,
            challenges,
            dpop_nonce: None,
            body: (),
        })
    }
}

/// Supports `Option<ValidatedToken<Claims>>` as an extractor: returns
/// `Some(token)` when the validator has authenticated the request and
/// `None` otherwise — never rejects.
impl<S, Claims> OptionalFromRequestParts<S> for ValidatedToken<Claims>
where
    S: HasClaims<Claims = Claims>,
    Claims: Send + Sync + 'static,
{
    type Rejection = Infallible;

    #[allow(clippy::unused_async_trait_impl)]
    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Option<Self>, Self::Rejection> {
        Ok(parts.extensions.get::<ValidatedToken<Claims>>().cloned())
    }
}
