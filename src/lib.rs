/*!
Specification compliant OAuth2 resource server middleware for axum.

- RFC 6750 error headers on authentication/authorization failure
- WASM support
- JWT token validation with customizable token requirements
- Pluggable async JWT signature validation (e.g. validate from KMS)
- Opaque token validation using OAuth2 token introspection
- DPoP and mTLS token binding validation
- DPoP resource server nonce support
- Authorization server/OIDC metadata discovery
- Scope enforcement middleware
- Per-endpoint token claim extractors

This is accomplished through integration with `huskarl-resource-server` which
provides the framework-independent features underlying this crate.
*/

pub mod extensions;
pub mod extractors;
pub mod layers;
pub mod response;

pub use huskarl_resource_server as resource_server;
