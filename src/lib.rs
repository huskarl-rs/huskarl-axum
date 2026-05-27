/*!
Specification compliant `OAuth2` resource server middleware for axum.

- RFC 6750 error headers on authentication/authorization failure
- WASM support
- JWT token validation with customizable token requirements
- Pluggable async JWT signature validation (e.g. validate from KMS)
- Opaque token validation using `OAuth2` token introspection
- `DPoP` and mTLS token binding validation
- `DPoP` resource server nonce support
- Authorization server/OIDC metadata discovery
- Scope enforcement middleware
- Per-endpoint token claim extractors

This is accomplished through integration with `huskarl-resource-server` which
provides the framework-independent features underlying this crate.

# Quick start

Protecting routes revolves around one claims type, named in four places:

1. the **validator** is built to deserialize access tokens into it;
2. **scope middleware** is bound to it, to read the token's granted scopes;
3. the **router state** declares it, once, via [`HasClaims`](extractors::HasClaims);
4. **handlers** extract it — via [`TokenFor<AppState>`](extractors::TokenFor),
   which spells the claims type through (3), or by naming it directly with
   [`ValidatedToken<C>`](extractors::ValidatedToken).

With `TokenFor`, (4) follows from (3) by definition (a directly-named
`ValidatedToken<C>` is compiler-checked against (3) instead), and
[`claims_context_for`](layers::ValidatorLayer::claims_context_for) makes the
compiler enforce that (2) and (3) match (1) — so the whole chain is checked,
and a mismatch is a compile error instead of every request failing with 401.

```no_run
use std::sync::Arc;

use axum::{Router, routing::get};
use huskarl_axum::layers::ValidatorLayer;
use huskarl_axum::prelude::*;
use huskarl_axum::resource_server::{
    core::{jwk::JwksSource, server_metadata::AuthorizationServerMetadata},
    validator::custom::CustomValidator,
};

// The one claims type: what the validator deserializes access tokens into.
#[derive(Clone, serde::Deserialize)]
struct OurClaims {
    scp: Vec<String>,
    sub: String,
}

impl HasScopes for OurClaims {
    fn scopes(&self) -> Option<Vec<String>> {
        Some(self.scp.clone())
    }
}

// (3) The router state declares the claims type, once, for all handlers.
#[derive(Clone)]
struct AppState;

impl HasClaims for AppState {
    type Claims = OurClaims;
}

// (4) Handlers extract the token through the state's declaration —
// `TokenFor<AppState>` is `ValidatedToken<OurClaims>` by definition, so a
// handler cannot name a different claims type.
async fn me(token: TokenFor<AppState>) -> String {
    format!("Hello {}", token.claims.sub)
}

# async fn build() {
# let http_client = huskarl_reqwest::ReqwestClient::builder()
#     .mtls(huskarl_reqwest::mtls::NoMtls)
#     .build()
#     .await
#     .unwrap();
let metadata = AuthorizationServerMetadata::oidc_fetch()
    .http_client(&http_client)
    .issuer("https://auth.example.com")
    .call()
    .await
    .unwrap();

// (1) The validator is built for the claims type.
let validator = CustomValidator::builder_from_metadata(&metadata)
    .with_claims::<OurClaims>()
    .jws_verifier_factory(Arc::new(JwksSource::builder().http_client(http_client).build()))
    .build()
    .await
    .unwrap();

let validator_layer = ValidatorLayer::builder().validator(validator).build();

// (2) Scope middleware. `claims_context_for::<AppState>()` compiles only if
// the validator's claims type matches AppState's `HasClaims` declaration.
let require_admin = validator_layer
    .claims_context_for::<AppState>()
    .require_scopes(vec!["admin".into()]);

let app: Router = Router::new()
    .route("/admin", get(me).layer(require_admin))
    .route("/me", get(me))
    .layer(validator_layer)
    .with_state(AppState);
# }
```
*/

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![warn(clippy::pedantic)]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod extensions;
pub mod extractors;
pub mod layers;
#[cfg(feature = "login")]
pub mod login;
pub mod prelude;
pub mod response;

pub use huskarl_resource_server as resource_server;
