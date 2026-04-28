use std::marker::PhantomData;

use huskarl_resource_server::{
    core::{client_auth::ClientAuthentication, http::HttpClient},
    validator::{
        custom::CustomValidator, dpop_nonce::DpopNonceChecker,
        introspection::IntrospectionValidator, rfc9068::Rfc9068Validator,
    },
};
pub use require_scopes::{HasScopes, RequireScopesLayer, RequireScopesService};
pub use validator::{ValidatorLayer, ValidatorService};

use crate::response::ErrorBody;

mod require_scopes;
mod validator;

pub struct ClaimsContext<C, E: ErrorBody = ()> {
    pub(crate) error_body: Option<E>,
    pub(crate) phantom: PhantomData<C>,
}

impl<C> Default for ClaimsContext<C> {
    fn default() -> Self {
        Self {
            error_body: None,
            phantom: PhantomData,
        }
    }
}

impl<C, E: ErrorBody> ClaimsContext<C, E> {
    pub fn require_scopes(&self, required_scopes: Vec<String>) -> RequireScopesLayer<C, E>
    where
        C: HasScopes,
    {
        RequireScopesLayer::with_options(required_scopes, self.error_body.clone())
    }
}

pub trait ValidatorExt<C> {
    fn claims_context(&self) -> ClaimsContext<C> {
        ClaimsContext::default()
    }
}

impl<N: DpopNonceChecker, C> ValidatorExt<C> for CustomValidator<N, C> {}
impl<N: DpopNonceChecker, C> ValidatorExt<C> for Rfc9068Validator<N, C> {}
impl<Auth: ClientAuthentication, C1: HttpClient, N: DpopNonceChecker, C> ValidatorExt<C>
    for IntrospectionValidator<Auth, C1, N, C>
{
}
