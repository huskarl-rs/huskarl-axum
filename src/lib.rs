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
- Audience and custom authorization enforcement
- RFC 9728 Protected Resource Metadata endpoint
- Programmatic current-session termination
- Per-endpoint token claim extractors

This is accomplished through integration with `huskarl-resource-server` which
provides the framework-independent features underlying this crate.

# Browser-login deployment limits

Before deploying the `login` feature beyond localhost:

- Use HTTPS and configure the public HTTPS redirect URI; its scheme controls
  secure cookies, even when TLS terminates before Axum.
- Persist cookie keys and share compatible key rings across replicas. Shared
  keys let replicas read sessions; they do not coordinate refresh exchanges.
- Check provider rules for simultaneous refresh-token exchanges. The
  engine does not prevent them, even within one replica.
- Cookie sessions cannot prevent an older response from restoring browser
  state after refresh or logout. Local logout does not end provider SSO.
- Preserve session cookies on the response through outer middleware and reverse
  proxies. Keep personalized responses out of shared caches.

Follow the [deployment guide](https://docs.rs/huskarl-axum/latest/huskarl_axum/login/deployment/)
for session-store choices, layer ordering, and rollout checks.

# Quick start

Build a validator for your claims type, then use one of its order-safe layers:
[`authenticated`](https://docs.rs/huskarl-axum/latest/huskarl_axum/layers/struct.ValidatorLayer.html#method.authenticated) requires a valid
token, while [`require_scopes`](https://docs.rs/huskarl-axum/latest/huskarl_axum/layers/struct.ValidatorLayer.html#method.require_scopes)
additionally enforces scopes. Handlers extract
[`ValidatedToken<C>`](extractors::ValidatedToken)
(or [`TokenFor<State>`](extractors::TokenFor) when an application prefers to
declare the claims type on its router state).

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
    fn has_scope(&self, scope: &str) -> bool {
        self.scp.iter().any(|granted| granted == scope)
    }
}

async fn me(token: ValidatedToken<OurClaims>) -> String {
    format!("Hello {}", token.claims.sub)
}

async fn build() {
    let http_client = huskarl_reqwest::ReqwestClient::builder()
        .mtls(huskarl_reqwest::mtls::NoMtls)
        .build()
        .await
        .unwrap();
    let metadata = AuthorizationServerMetadata::oidc_fetch()
        .http_client(&http_client)
        .issuer("https://auth.example.com")
        .call()
        .await
        .unwrap();

    let validator = CustomValidator::builder_from_metadata(&metadata)
        .with_claims::<OurClaims>()
        .jws_verifier_factory(Arc::new(JwksSource::builder().http_client(http_client).build()))
        .build()
        .await
        .unwrap();

    let validator_layer = ValidatorLayer::builder().validator(validator).build();

    // Both returned layers include validation and the appropriate gate in the
    // correct order. The scope layer derives its claims type from the validator.
    let require_admin = validator_layer.require_scopes(["admin"]);
    let require_token = validator_layer.authenticated();

    let app: Router = Router::new()
        .route("/admin", get(me).layer(require_admin))
        .route("/me", get(me).layer(require_token));
}
```

# Browser login

Enable the `login` feature to add an OAuth 2.0 Authorization Code login flow,
encrypted sessions, refresh handling, and logout routes through the
[`login`](https://docs.rs/huskarl-axum/latest/huskarl_axum/login/) module.
The bundled [`LoginLayer`](https://docs.rs/huskarl-axum/latest/huskarl_axum/login/struct.LoginLayer.html) protects a whole router;
its component layers support applications with a mix of public and protected
routes. See the runnable example for the required environment variables:

```sh
cargo run --example login --features login
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
pub mod resource_metadata;
pub mod response;

pub use huskarl_resource_server as resource_server;
