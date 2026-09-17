# huskarl-axum

<!-- cargo-reedme: start -->

<!-- cargo-reedme: info-start

    Do not edit this region by hand
    ===============================

    This region was generated from Rust documentation comments by `cargo-reedme` using this command:

        cargo +nightly reedme

    for more info: https://github.com/nik-rev/cargo-reedme

cargo-reedme: info-end -->

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

## Quick start

Build a validator for your claims type, then use one of its order-safe layers:
[`authenticated`](https://docs.rs/huskarl-axum/latest/huskarl_axum/layers/struct.ValidatorLayer.html#method.authenticated) requires a valid
token, while [`require_scopes`](https://docs.rs/huskarl-axum/latest/huskarl_axum/layers/struct.ValidatorLayer.html#method.require_scopes)
additionally enforces scopes. Handlers extract [`ValidatedToken<C>`](https://docs.rs/huskarl-axum/latest/huskarl_axum/extractors/struct.ValidatedToken.html)
(or [`TokenFor<State>`](https://docs.rs/huskarl-axum/latest/huskarl_axum/extractors/type.TokenFor.html) when an application prefers to
declare the claims type on its router state).

```rust
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

## Browser login

Enable the `login` feature to add an OAuth 2.0 Authorization Code login flow,
encrypted sessions, refresh handling, and logout routes through the
[`login`](https://docs.rs/huskarl-axum/latest/huskarl_axum/login/) module. The bundled [`login::LoginLayer`](https://docs.rs/huskarl-axum/latest/huskarl_axum/login/layer/struct.LoginLayer.html) protects a whole router;
its component layers support applications with a mix of public and protected
routes. See the runnable example for the required environment variables:

```sh
cargo run --example login --features login
```

<!-- cargo-reedme: end -->

## Nested routers

Authentication layers preserve `Router::nest` prefixes through Axum's
`OriginalUri`. For a router nested at `/app`:

- Set the validator's `base_url` to the public origin, such as
  `https://example.com`. A request to `/app/items` is validated against
  `https://example.com/app/items`.
- Configure login callback/logout paths as `/app/callback` and `/app/logout`,
  and the grant's redirect URI as `https://example.com/app/callback`.
  Register inner Axum routes as `/callback` and `/logout` so they reach the layer.
- Reserve the validator's base URL path and login's `base_path` for prefixes
  stripped by a reverse proxy. Do not repeat an Axum nesting prefix there.
  If these settings previously compensated for nesting, remove that compensation.

A trusted `RequestUrl` extension still takes precedence. Login applies its
configured `base_path`/`strip_prefix` mapping to that URI, so the override must
agree with the configured callback/logout paths and proxy mapping. Mount
protected-resource metadata services at their advertised paths on the root router.
