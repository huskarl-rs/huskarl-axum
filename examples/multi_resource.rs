//! Two independently authenticated resources with public RFC 9728 metadata.
//!
//! Run with PUBLIC_BASE, INVENTORY_ISSUER, and PAYMENTS_ISSUER set. Optional
//! INVENTORY_AUDIENCE and PAYMENTS_AUDIENCE override the resource-URL audiences.
//! LISTEN defaults to 127.0.0.1:3000. The listener is plain HTTP; terminate public
//! HTTPS at a trusted reverse proxy. See docs/how_to/resource_metadata.md.

use std::sync::Arc;

use axum::{Router, routing::get};
use huskarl_axum::{
    layers::{HasScopes, ValidatorLayer},
    resource_metadata::AudienceBinding,
    resource_server::{
        core::{jwk::JwksSource, server_metadata::AuthorizationServerMetadata},
        validator::{
            AccessTokenValidator, metadata::ProvideValidatorMetadata, rfc9068::Rfc9068Validator,
        },
    },
};
use huskarl_reqwest::{ReqwestClient, mtls::NoMtls};

type AppResult<T> = Result<T, Box<dyn std::error::Error>>;

async fn validator(issuer: &str, audience: &str) -> AppResult<Rfc9068Validator> {
    let client = ReqwestClient::builder().mtls(NoMtls).build().await?;
    let metadata = AuthorizationServerMetadata::fetch()
        .http_client(&client)
        .issuer(issuer)
        .call()
        .await?;
    Ok(Rfc9068Validator::builder_from_metadata(&metadata)
        .audience(audience)
        .jws_verifier_factory(Arc::new(JwksSource::builder().http_client(client).build()))
        .build()
        .await?)
}

fn app<V>(
    base: &str,
    inventory: V,
    payments: V,
    inventory_audience: &str,
    payments_audience: &str,
) -> AppResult<Router>
where
    V: AccessTokenValidator + ProvideValidatorMetadata + Send + Sync + 'static,
    V::Claims: HasScopes + Send + Sync + 'static,
{
    let (inventory, inventory_metadata) = ValidatorLayer::builder()
        .validator(inventory)
        .base_url(base)?
        .build()
        .with_protected_resource(
            "/mcp/inventory",
            AudienceBinding::mapped([inventory_audience]),
            ["inventory.read"],
        )?;
    let (payments, payments_metadata) = ValidatorLayer::builder()
        .validator(payments)
        .base_url(base)?
        .build()
        .with_protected_resource(
            "/mcp/payments",
            AudienceBinding::mapped([payments_audience]),
            ["payments.read"],
        )?;

    // Advertised scopes do not enforce permissions. Apply the scope layers.
    let inventory_routes = Router::new()
        .route("/items", get(|| async { "inventory" }))
        .layer(inventory.require_scopes(["inventory.read"]));
    let payments_routes = Router::new()
        .route("/items", get(|| async { "payments" }))
        .layer(payments.require_scopes(["payments.read"]));

    // Metadata stays public on the root router, outside both auth layers.
    Ok(Router::new()
        .nest("/mcp/inventory", inventory_routes)
        .nest("/mcp/payments", payments_routes)
        .route_service(inventory_metadata.path(), inventory_metadata.clone())
        .route_service(payments_metadata.path(), payments_metadata.clone())
        .route("/health", get(|| async { "ok" })))
}

#[tokio::main]
async fn main() -> AppResult<()> {
    let base = std::env::var("PUBLIC_BASE")?;
    let public_url = url::Url::parse(&base)?;
    if public_url.scheme() != "https"
        || public_url.host_str().is_none()
        || public_url.path() != "/"
        || public_url.query().is_some()
        || public_url.fragment().is_some()
        || !public_url.username().is_empty()
        || public_url.password().is_some()
    {
        return Err(
            "PUBLIC_BASE must be an HTTPS origin without a path, query, or credentials".into(),
        );
    }
    let base = public_url.origin().ascii_serialization();
    let inventory_audience =
        std::env::var("INVENTORY_AUDIENCE").unwrap_or_else(|_| format!("{base}/mcp/inventory"));
    let payments_audience =
        std::env::var("PAYMENTS_AUDIENCE").unwrap_or_else(|_| format!("{base}/mcp/payments"));
    let inventory = validator(&std::env::var("INVENTORY_ISSUER")?, &inventory_audience).await?;
    let payments = validator(&std::env::var("PAYMENTS_ISSUER")?, &payments_audience).await?;
    let app = app(
        &base,
        inventory,
        payments,
        &inventory_audience,
        &payments_audience,
    )?;
    let listen = std::env::var("LISTEN").unwrap_or_else(|_| "127.0.0.1:3000".into());
    let listener = tokio::net::TcpListener::bind(&listen).await?;
    println!("Listening on {listen}; public origin {base}");
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use huskarl_axum::resource_server::{
        core::platform::MaybeSendBoxFuture,
        validator::{
            ValidatedRequest, ValidationResult, error::ValidateHeadersError,
            metadata::ValidatorMetadata,
        },
    };
    use tower::ServiceExt as _;

    struct Claims(Vec<String>);
    impl HasScopes for Claims {
        fn has_scope(&self, scope: &str) -> bool {
            self.0.iter().any(|value| value == scope)
        }
    }

    // Test-only token stand-ins: exercise the example's layer placement and
    // audience/scope gates independently of network discovery and signatures.
    struct TestValidator;
    impl AccessTokenValidator for TestValidator {
        type Claims = Claims;
        type Error = ValidateHeadersError;
        fn validate_request<'a>(
            &'a self,
            headers: &'a http::HeaderMap,
            _: &'a http::Method,
            _: &'a http::Uri,
            _: Option<&'a [u8]>,
        ) -> MaybeSendBoxFuture<'a, ValidationResult<Claims, ValidateHeadersError>> {
            Box::pin(async move {
                let token = headers
                    .get(http::header::AUTHORIZATION)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.strip_prefix("Bearer "));
                let outcome = token.map(|value| {
                    let (audience, scope) = value.split_once(':').unwrap_or((value, ""));
                    ValidatedRequest {
                        iss: None,
                        sub: None,
                        aud: vec![audience.to_owned()],
                        jti: None,
                        iat: None,
                        exp: None,
                        cnf: None,
                        claims: Claims(vec![scope.to_owned()]),
                        introspection_jwt: None,
                    }
                });
                ValidationResult {
                    outcome: Ok(outcome),
                    dpop_nonce: None,
                }
            })
        }
    }
    impl ProvideValidatorMetadata for TestValidator {
        fn validator_metadata(&self, resource: Option<&str>) -> ValidatorMetadata {
            ValidatorMetadata::builder()
                .maybe_resource(resource)
                .build()
        }
    }

    #[tokio::test]
    async fn public_discovery_and_independent_resource_gates() -> AppResult<()> {
        let app = app(
            "https://api.example.com",
            TestValidator,
            TestValidator,
            "inventory",
            "payments",
        )?;
        for resource in ["inventory", "payments"] {
            let metadata_path = format!("/.well-known/oauth-protected-resource/mcp/{resource}");
            let response = app
                .clone()
                .oneshot(
                    http::Request::builder()
                        .uri(&metadata_path)
                        .body(Body::empty())?,
                )
                .await?;
            assert_eq!(response.status(), 200);
            let document: serde_json::Value =
                serde_json::from_slice(&to_bytes(response.into_body(), 8192).await?)?;
            assert_eq!(
                document["resource"],
                format!("https://api.example.com/mcp/{resource}")
            );
            assert_eq!(
                document["scopes_supported"],
                serde_json::json!([format!("{resource}.read")])
            );
            for (method, status) in [("HEAD", 200), ("POST", 405)] {
                let response = app
                    .clone()
                    .oneshot(
                        http::Request::builder()
                            .method(method)
                            .uri(&metadata_path)
                            .body(Body::empty())?,
                    )
                    .await?;
                assert_eq!(response.status(), status);
                if method == "POST" {
                    assert_eq!(response.headers()["allow"], "GET, HEAD");
                }
                assert!(to_bytes(response.into_body(), 8192).await?.is_empty());
            }
            let path = format!("/mcp/{resource}/items");
            let response = app
                .clone()
                .oneshot(http::Request::builder().uri(&path).body(Body::empty())?)
                .await?;
            assert_eq!(response.status(), 401);
            assert!(
                response.headers()["www-authenticate"]
                    .to_str()?
                    .contains(&format!("https://api.example.com{metadata_path}"))
            );
            let other = if resource == "inventory" {
                "payments"
            } else {
                "inventory"
            };
            for (token, expected) in [
                (format!("{resource}:{resource}.read"), 200),
                (format!("{other}:{resource}.read"), 401),
                (format!("{resource}:wrong.scope"), 403),
            ] {
                let response = app
                    .clone()
                    .oneshot(
                        http::Request::builder()
                            .uri(&path)
                            .header("authorization", format!("Bearer {token}"))
                            .body(Body::empty())?,
                    )
                    .await?;
                assert_eq!(response.status(), expected, "resource {resource}");
            }
        }
        Ok(())
    }
}
