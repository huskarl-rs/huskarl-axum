# Publish protected-resource metadata

Use this guide to publish RFC 9728 discovery information for one resource or
several resources on the same origin. This is the API's own metadata, separate
from the authorization-server metadata used to construct a token validator.

You need a trusted public HTTPS origin, a validator for each resource, and the
audiences your provider puts in access tokens. A logical resource can have many
endpoints; it gets one metadata document, not one per endpoint.

## Choose identifiers and audiences

For an origin of `https://api.example.com`, this guide uses:

| Resource identifier | Public metadata URL |
|---|---|
| `https://api.example.com/mcp/inventory` | `https://api.example.com/.well-known/oauth-protected-resource/mcp/inventory` |
| `https://api.example.com/mcp/payments` | `https://api.example.com/.well-known/oauth-protected-resource/mcp/payments` |

Use `AudienceBinding::ResourceIdentifier` if the token's `aud` is the resource
URL. Use `AudienceBinding::mapped(["inventory-api"])` if your provider issues a
different audience. Configure the validator to accept that audience too.
Resources accepting the same audience are not isolated by their different URLs;
use distinct audiences or additional authorization checks when tokens must not
cross between resources.

## Publish one resource

The call returns an authentication layer and a metadata service. Install the
layer on the resource's endpoints and mount the metadata separately:

```rust
use axum::{Router, routing::get};
use huskarl_axum::{layers::ValidatorLayer, resource_metadata::AudienceBinding};
# fn configure<V>(validator: V) -> Result<Router, Box<dyn std::error::Error>>
# where V: huskarl_axum::resource_server::validator::AccessTokenValidator
#     + huskarl_axum::resource_server::validator::metadata::ProvideValidatorMetadata
#     + Send + Sync + 'static,
# V::Claims: huskarl_axum::layers::HasScopes + Send + Sync + 'static {
let (inventory, metadata) = ValidatorLayer::builder()
    .validator(validator)
    .base_url("https://api.example.com")?
    .build()
    .with_protected_resource(
        "/mcp/inventory",
        AudienceBinding::ResourceIdentifier,
        ["inventory.read"],
    )?;

let endpoints = Router::new()
    .route("/items", get(|| async { "inventory" }))
    .layer(inventory.require_scopes(["inventory.read"]));
let app = Router::new()
    .nest("/mcp/inventory", endpoints)
    .route_service(metadata.path(), metadata.clone());
# Ok(app)
# }
```

The scopes passed to `with_protected_resource` are **advertised capabilities**.
`require_scopes` enforces them on requests. Apply `.layer(inventory)` instead
when authentication and audience validation alone are sufficient.

Router placement defines protection: a resource identifier does not attach
middleware to paths automatically. Add all intended endpoints before applying
the layer, and keep the metadata service outside that layer so discovery needs
no token.

## Add a second resource

Repeat the setup with a payments validator, `/mcp/payments`, and its audience.
Nest its protected endpoints separately and mount both metadata services on the
root router. Each layer owns its audience and challenge metadata; do not apply
one resource's layer to the whole combined router.

The complete runnable example is [examples/multi_resource.rs](https://github.com/huskarl-rs/huskarl-axum/blob/main/examples/multi_resource.rs):

```sh
PUBLIC_BASE=https://api.example.com \
INVENTORY_ISSUER=https://inventory-auth.example.com \
PAYMENTS_ISSUER=https://payments-auth.example.com \
cargo run --example multi_resource
```

Replace the issuer URLs with your providers. The same issuer can serve both
resources if it issues the intended distinct audiences. This example uses
RFC 9068 JWT access tokens and enforces `inventory.read` and `payments.read` on
the corresponding `/items` routes. `INVENTORY_AUDIENCE` and `PAYMENTS_AUDIENCE`
override the default resource-URL audiences. `LISTEN` defaults to
`127.0.0.1:3000`; `/health` is public.

The example's listener is plain HTTP and `PUBLIC_BASE` must be an HTTPS origin
without a path. Terminate public HTTPS at a trusted reverse proxy. For a
production deployment with rewritten prefixes, follow the API's
[public URL mapping](crate::layers::ValidatorLayer::with_protected_resource)
and mount the returned metadata services at their canonical public URLs.
Axum rejects resource identifiers containing queries because it routes metadata
by path; ordinary API requests may still contain queries.

## Verify discovery and isolation

Run these against the public HTTPS entry point. For a local routing check only,
you can point `BASE` at the example's HTTP listener; advertised resource and
metadata URLs will still use `PUBLIC_BASE`.

```sh
BASE=https://api.example.com
curl -i "$BASE/.well-known/oauth-protected-resource/mcp/inventory"
curl -I "$BASE/.well-known/oauth-protected-resource/mcp/payments"
curl -i "$BASE/mcp/inventory/items"
curl -i -X POST "$BASE/.well-known/oauth-protected-resource/mcp/inventory"
```

Expect:

| Request | Result |
|---|---|
| Metadata GET without a token | 200 JSON with the intended `resource` and `authorization_servers` |
| Metadata HEAD without a token | 200 with representation headers and no body |
| Protected endpoint without a token | 401; `WWW-Authenticate` advertises that resource's metadata URL |
| Metadata POST | 405 with `Allow: GET, HEAD` |

Repeat GET and the unauthenticated endpoint check for the other resource.
Obtain access tokens from your provider; these examples do not issue them.
Test a token for each resource on its own endpoint, then on the other resource.
With distinct accepted audiences, a token for the wrong resource must receive
401. A token with the correct audience but missing an enforced scope must
receive 403.
A correctly authorized request should reach its handler or upstream.

If discovery fails, check that no authentication layer or branch wraps the
metadata endpoint. If the challenge points to the wrong document, check the
selected resource and trusted public base URL. If a token crosses resource
boundaries, check for overlapping audiences and missing route protection.
