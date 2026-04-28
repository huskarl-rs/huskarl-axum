use std::{convert::Infallible, ops::Deref};

use axum_core::extract::FromRequestParts;
use http::{StatusCode, request::Parts};

use crate::extensions::{ValidatedToken, ValidatorData};
use crate::response::ChallengeResponse;

impl<Claims, S> FromRequestParts<S> for ValidatedToken<Claims>
where
    Claims: Send + Sync + 'static,
    S: Send + Sync,
{
    type Rejection = ChallengeResponse;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        if let Some(claims) = parts.extensions.get::<ValidatedToken<Claims>>().cloned() {
            return Ok(claims);
        };

        let challenges = parts
            .extensions
            .get::<ValidatorData>()
            .map(|vd| vd.inner.unauthenticated_challenges(None))
            .unwrap_or_else(|| vec!["Bearer".to_string()]);

        Err(ChallengeResponse {
            status: StatusCode::UNAUTHORIZED,
            challenges,
            dpop_nonce: None,
            body: (),
        })
    }
}

#[derive(Debug, Clone)]
pub struct OptionalValidatedToken<Claims>(Option<ValidatedToken<Claims>>);

impl<Claims> Deref for OptionalValidatedToken<Claims> {
    type Target = Option<ValidatedToken<Claims>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<Claims, S> FromRequestParts<S> for OptionalValidatedToken<Claims>
where
    Claims: Send + Sync + 'static,
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        Ok(OptionalValidatedToken(
            parts.extensions.get::<ValidatedToken<Claims>>().cloned(),
        ))
    }
}
