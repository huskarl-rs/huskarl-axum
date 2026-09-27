//! Tests for the resource-server protection layers.
//!
//! These drive the Tower services the layers produce against a mock
//! [`AccessTokenValidator`] whose outcome (valid token / no token / invalid
//! token) is fixed per test, and assert the status code *and* whether the inner
//! handler was reached. The focus is the security-relevant behaviour:
//! - `ValidatorLayer` rejects invalid tokens but, by design, lets
//!   unauthenticated requests through (the extractor is the gate);
//! - `RequireAuthenticatedLayer` closes that gap at the layer level;
//! - `RequireScopesLayer` enforces scopes with exact matching, failing closed.

use std::{
    convert::Infallible,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

use axum::{Router, body::to_bytes, routing::get};
use axum_core::{body::Body, extract::Request, response::Response};
use http::{HeaderMap, Method, StatusCode, Uri, header};
use huskarl_resource_server::{
    core::platform::Duration,
    error::{Challenge, ServerStatus, ToRfc6750Error, TokenErrorCode, TokenValidationError},
    validator::{
        AccessTokenValidator, ValidatedRequest, ValidationResult,
        extract::TokenType,
        metadata::{ProvideValidatorMetadata, ValidatorMetadata},
    },
};
use tower::{Layer, Service, ServiceExt as _};

use super::{AuthorizationError, HasScopes, RequireAuthenticatedLayer, ValidatorLayer};
use crate::extensions::{ClientCertDer, RequestUrl};
use crate::extractors::ValidatedToken;
use crate::resource_metadata::{AudienceBinding, ResourceMetadataError};
use crate::response::{ErrorBody, ErrorDetails};

/// What the mock validator should return for `validate_request`.
#[derive(Clone)]
enum Outcome {
    /// A valid token granting the given scopes.
    Valid(Vec<String>),
    /// No authentication header present (`Ok(None)`).
    NoToken,
    /// A token that failed validation (`Err`).
    Invalid,
    /// A backing service failed and advised the client to retry later.
    ServerUnavailable(Duration),
}

#[derive(Clone)]
struct MockValidator {
    outcome: Outcome,
    observed: Arc<Mutex<Vec<ObservedRequest>>>,
    dpop_nonce: Option<String>,
    dpop_supported: bool,
    issuer: String,
    audience: Vec<String>,
}

#[derive(Debug)]
struct ObservedRequest {
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    client_cert_der: Option<Vec<u8>>,
}

impl MockValidator {
    fn valid(scopes: &[&str]) -> Self {
        Self {
            outcome: Outcome::Valid(scopes.iter().map(|s| (*s).to_string()).collect()),
            observed: Arc::default(),
            dpop_nonce: None,
            dpop_supported: false,
            issuer: "https://as.example.com".to_owned(),
            audience: vec!["my-api".to_owned()],
        }
    }
    fn no_token() -> Self {
        Self {
            outcome: Outcome::NoToken,
            observed: Arc::default(),
            dpop_nonce: None,
            dpop_supported: false,
            issuer: "https://as.example.com".to_owned(),
            audience: vec!["my-api".to_owned()],
        }
    }
    fn invalid() -> Self {
        Self {
            outcome: Outcome::Invalid,
            observed: Arc::default(),
            dpop_nonce: None,
            dpop_supported: false,
            issuer: "https://as.example.com".to_owned(),
            audience: vec!["my-api".to_owned()],
        }
    }

    fn server_unavailable(retry_after: Duration) -> Self {
        Self {
            outcome: Outcome::ServerUnavailable(retry_after),
            observed: Arc::default(),
            dpop_nonce: None,
            dpop_supported: false,
            issuer: "https://as.example.com".to_owned(),
            audience: vec!["my-api".to_owned()],
        }
    }

    fn with_dpop_nonce(mut self, nonce: &str) -> Self {
        self.dpop_nonce = Some(nonce.to_owned());
        self
    }

    fn with_dpop_support(mut self) -> Self {
        self.dpop_supported = true;
        self
    }

    fn with_source(mut self, issuer: &str, audience: &[&str]) -> Self {
        self.issuer = issuer.to_owned();
        self.audience = audience.iter().map(|value| (*value).to_owned()).collect();
        self
    }

    fn observations(&self) -> Arc<Mutex<Vec<ObservedRequest>>> {
        self.observed.clone()
    }
}

#[derive(Clone)]
struct TestClaims {
    scopes: Vec<String>,
}

impl HasScopes for TestClaims {
    fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|granted| granted == scope)
    }
}

#[derive(Debug)]
enum MockError {
    InvalidToken,
    ServerUnavailable(Duration),
}

impl std::fmt::Display for MockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidToken => f.write_str("mock invalid token"),
            Self::ServerUnavailable(_) => f.write_str("mock backing service unavailable"),
        }
    }
}

impl std::error::Error for MockError {}

impl ToRfc6750Error for MockError {
    fn attempted_scheme(&self) -> Option<TokenType> {
        Some(TokenType::Bearer)
    }
    fn challenge(&self) -> Challenge {
        match self {
            // A client error → 401, mirroring an invalid/expired access token.
            Self::InvalidToken => {
                Challenge::new(TokenValidationError::Client(TokenErrorCode::InvalidToken))
                    .with_description("mock invalid token")
            }
            Self::ServerUnavailable(retry_after) => Challenge::new(TokenValidationError::Server {
                status: ServerStatus::SERVICE_UNAVAILABLE,
                retry_after: Some(*retry_after),
            }),
        }
    }
}

impl AccessTokenValidator for MockValidator {
    type Claims = TestClaims;
    type Error = MockError;

    fn validate_request<'a>(
        &'a self,
        headers: &'a http::HeaderMap,
        method: &'a http::Method,
        uri: &'a http::Uri,
        client_cert_der: Option<&'a [u8]>,
    ) -> huskarl_resource_server::core::platform::MaybeSendBoxFuture<
        'a,
        ValidationResult<Self::Claims, Self::Error>,
    > {
        self.observed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(ObservedRequest {
                headers: headers.clone(),
                method: method.clone(),
                uri: uri.clone(),
                client_cert_der: client_cert_der.map(<[u8]>::to_vec),
            });
        let outcome = match &self.outcome {
            Outcome::Valid(scopes) => Ok(Some(ValidatedRequest {
                iss: Some(self.issuer.clone()),
                sub: Some("user-1".to_string()),
                aud: self.audience.clone(),
                jti: None,
                iat: None,
                exp: None,
                cnf: None,
                claims: TestClaims {
                    scopes: scopes.clone(),
                },
                introspection_jwt: None,
            })),
            Outcome::NoToken => Ok(None),
            Outcome::Invalid => Err(MockError::InvalidToken),
            Outcome::ServerUnavailable(retry_after) => {
                Err(MockError::ServerUnavailable(*retry_after))
            }
        };
        Box::pin(async move {
            ValidationResult {
                outcome,
                dpop_nonce: self.dpop_nonce.clone(),
            }
        })
    }
}

impl ProvideValidatorMetadata for MockValidator {
    fn validator_metadata(&self, resource: Option<&str>) -> ValidatorMetadata {
        ValidatorMetadata::builder()
            .maybe_resource(resource)
            .dpop_supported(self.dpop_supported)
            .bearer_methods_supported(bon::vec!["header"])
            .build()
    }
}

#[derive(Clone, Copy)]
struct DetailsBody;

impl ErrorBody for DetailsBody {
    type Body = String;

    fn error_body(&self, details: &ErrorDetails<'_>) -> Self::Body {
        format!(
            "error={};scopes={};challenges={}",
            details.error_code.map_or("none", |code| code.as_str()),
            details
                .required_scopes
                .map_or_else(String::new, |scopes| scopes.join(" ")),
            details.challenges.len(),
        )
    }
}

/// A tracking flag set to `true` iff the inner handler was reached.
type Reached = Arc<AtomicBool>;

/// An innermost handler that records that it ran and returns `200 OK`.
fn handler(
    reached: Reached,
) -> impl Service<Request, Response = Response, Error = Infallible, Future: Send> + Clone + Send + 'static
{
    tower::service_fn(move |_req: Request| {
        let reached = reached.clone();
        async move {
            reached.store(true, Ordering::SeqCst);
            Ok::<Response, Infallible>(Response::new(Body::empty()))
        }
    })
}

fn request() -> Request {
    Request::new(Body::empty())
}

#[tokio::test]
async fn protected_resource_boundary_is_the_router_not_the_identifier()
-> Result<(), Box<dyn std::error::Error>> {
    for (mock, protected_status) in [
        (MockValidator::no_token(), StatusCode::UNAUTHORIZED),
        (
            MockValidator::valid(&[]).with_source(
                "https://issuer.example",
                &["https://api.example/mcp/inventory"],
            ),
            StatusCode::OK,
        ),
        (MockValidator::valid(&[]), StatusCode::UNAUTHORIZED),
    ] {
        let (protection, metadata) = ValidatorLayer::builder()
            .validator(mock)
            .base_url("https://api.example")?
            .build()
            .with_protected_resource(
                "/mcp/inventory",
                AudienceBinding::ResourceIdentifier,
                ["write"],
            )?;
        let app = Router::new()
            .nest(
                "/mcp/inventory",
                Router::new()
                    .route("/items", get(|| async {}))
                    .route("/items/{id}", get(|| async {}))
                    .layer(protection.clone()),
            )
            .merge(
                Router::new()
                    .route("/alias", get(|| async {}))
                    .layer(protection),
            )
            .route("/mcp/inventory/public", get(|| async {}))
            .route("/mcp/inventory-other", get(|| async {}))
            .route_service(metadata.path(), metadata.clone());

        for (path, expected) in [
            ("/mcp/inventory/items", protected_status),
            ("/mcp/inventory/items/42?detail=full", protected_status),
            ("/alias", protected_status),
            ("/mcp/inventory/public", StatusCode::OK),
            ("/mcp/inventory-other", StatusCode::OK),
            (metadata.path(), StatusCode::OK),
        ] {
            let response = app
                .clone()
                .oneshot(http::Request::builder().uri(path).body(Body::empty())?)
                .await?;
            assert_eq!(response.status(), expected, "{path}");
        }
    }
    Ok(())
}

#[tokio::test]
async fn optional_resource_authentication_still_validates_presented_tokens()
-> Result<(), Box<dyn std::error::Error>> {
    for (mock, expected) in [
        (MockValidator::no_token(), StatusCode::OK),
        (MockValidator::valid(&[]), StatusCode::OK),
        (MockValidator::invalid(), StatusCode::UNAUTHORIZED),
        (
            MockValidator::valid(&[]).with_source("https://issuer.example", &["other-api"]),
            StatusCode::UNAUTHORIZED,
        ),
    ] {
        let (optional, _metadata) = ValidatorLayer::builder()
            .validator(mock)
            .base_url("https://api.example")?
            .build()
            .with_optional_authentication_resource(
                "/mcp",
                AudienceBinding::mapped(["my-api"]),
                ["write"],
            )?;
        let reached: Reached = Arc::default();
        let response = optional
            .layer(handler(reached.clone()))
            .oneshot(request())
            .await?;
        assert_eq!(response.status(), expected);
        assert_eq!(reached.load(Ordering::SeqCst), expected == StatusCode::OK);
    }
    Ok(())
}

#[tokio::test]
async fn protected_resource_permissions_preserve_authentication_and_audience_checks()
-> Result<(), Box<dyn std::error::Error>> {
    for (mock, expected) in [
        (MockValidator::no_token(), StatusCode::UNAUTHORIZED),
        (MockValidator::valid(&[]), StatusCode::FORBIDDEN),
        (MockValidator::valid(&["write"]), StatusCode::OK),
        (
            MockValidator::valid(&["write"]).with_source("https://issuer.example", &["other-api"]),
            StatusCode::UNAUTHORIZED,
        ),
    ] {
        let (protection, _metadata) = ValidatorLayer::builder()
            .validator(mock)
            .base_url("https://api.example")?
            .build()
            .with_protected_resource("/mcp", AudienceBinding::mapped(["my-api"]), ["write"])?;
        let reached: Reached = Arc::default();
        let scoped = protection
            .require_scopes(["write"])
            .layer(handler(reached.clone()))
            .oneshot(request())
            .await?;
        assert_eq!(scoped.status(), expected);
        assert_eq!(reached.load(Ordering::SeqCst), expected == StatusCode::OK);

        let reached: Reached = Arc::default();
        let authorized = protection
            .authorize(|token| {
                if token.claims.has_scope("write") {
                    Ok(())
                } else {
                    Err(AuthorizationError::Forbidden("write required".to_owned()))
                }
            })
            .layer(handler(reached.clone()))
            .oneshot(request())
            .await?;
        assert_eq!(authorized.status(), expected);
        assert_eq!(reached.load(Ordering::SeqCst), expected == StatusCode::OK);
    }
    Ok(())
}

#[tokio::test]
async fn resource_isolation_depends_on_audience_bindings() -> Result<(), Box<dyn std::error::Error>>
{
    for shared in [false, true] {
        for path in ["/inventory", "/payments"] {
            let audience = if shared {
                "shared-api"
            } else {
                "https://api.example/inventory"
            };
            let binding = if shared {
                AudienceBinding::mapped(["shared-api"])
            } else {
                AudienceBinding::ResourceIdentifier
            };
            let (protection, _metadata) = ValidatorLayer::builder()
                .validator(
                    MockValidator::valid(&[]).with_source("https://issuer.example", &[audience]),
                )
                .base_url("https://api.example")?
                .build()
                .with_protected_resource(path, binding, std::iter::empty::<String>())?;
            let response = protection
                .layer(handler(Arc::default()))
                .oneshot(http::Request::builder().uri(path).body(Body::empty())?)
                .await?;
            let expected = if shared || path == "/inventory" {
                StatusCode::OK
            } else {
                StatusCode::UNAUTHORIZED
            };
            assert_eq!(response.status(), expected, "shared={shared}, path={path}");
        }
    }
    Ok(())
}

#[tokio::test]
async fn resource_metadata_is_served_and_advertised() -> Result<(), Box<dyn std::error::Error>> {
    let validator = ValidatorLayer::builder()
        .validator(MockValidator::no_token())
        .base_url("https://api.example")?
        .build();
    let (validator, metadata) = validator.with_protected_resource(
        "/",
        AudienceBinding::ResourceIdentifier,
        ["write", "read", "write"],
    )?;

    assert_eq!(metadata.path(), "/.well-known/oauth-protected-resource");

    let protected = Router::new()
        .route("/protected", get(|| async {}))
        .layer(validator);
    let app = Router::new()
        .route_service(metadata.path(), metadata.clone())
        .merge(protected);

    let response = app
        .clone()
        .oneshot(
            http::Request::builder()
                .uri(metadata.path())
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
    assert_eq!(response.headers()[header::CACHE_CONTROL], "max-age=3600");
    let body = to_bytes(response.into_body(), usize::MAX).await?;
    let document: serde_json::Value = serde_json::from_slice(&body)?;
    assert_eq!(document["resource"], "https://api.example/");
    assert_eq!(document["authorization_servers"], serde_json::Value::Null);
    assert_eq!(
        document["bearer_methods_supported"],
        serde_json::json!(["header"])
    );
    assert_eq!(
        document["scopes_supported"],
        serde_json::json!(["read", "write"])
    );

    let response = app
        .oneshot(
            http::Request::builder()
                .uri("/protected")
                .body(Body::empty())?,
        )
        .await?;
    let challenges = response
        .headers()
        .get_all(header::WWW_AUTHENTICATE)
        .iter()
        .map(http::HeaderValue::to_str)
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        challenges,
        [r#"Bearer resource_metadata="https://api.example/.well-known/oauth-protected-resource""#]
    );
    Ok(())
}

#[tokio::test]
async fn resource_metadata_supports_head_and_rejects_other_methods()
-> Result<(), Box<dyn std::error::Error>> {
    let validator = ValidatorLayer::builder()
        .validator(MockValidator::valid(&[]))
        .base_url("https://api.example")?
        .build();
    let (_validator, metadata) = validator.with_protected_resource(
        "/",
        AudienceBinding::ResourceIdentifier,
        std::iter::empty::<String>(),
    )?;
    let app = Router::new().route_service(metadata.path(), metadata.clone());

    let get = app
        .clone()
        .oneshot(
            http::Request::builder()
                .uri(metadata.path())
                .body(Body::empty())?,
        )
        .await?;
    let get_length = get.headers()[header::CONTENT_LENGTH].clone();

    let head = app
        .clone()
        .oneshot(
            http::Request::builder()
                .method(Method::HEAD)
                .uri(metadata.path())
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(head.status(), StatusCode::OK);
    assert_eq!(head.headers()[header::CONTENT_LENGTH], get_length);
    assert!(to_bytes(head.into_body(), usize::MAX).await?.is_empty());

    let post = app
        .oneshot(
            http::Request::builder()
                .method(Method::POST)
                .uri(metadata.path())
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(post.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(post.headers()[header::ALLOW], "GET, HEAD");
    assert_eq!(post.headers()[header::CACHE_CONTROL], "no-store");
    Ok(())
}

#[tokio::test]
async fn resource_metadata_preserves_path_resource_identifier()
-> Result<(), Box<dyn std::error::Error>> {
    let validator = ValidatorLayer::builder()
        .validator(MockValidator::no_token())
        .base_url("https://api.example")?
        .build();
    let (validator, metadata) = validator.with_protected_resource(
        "/tenant/one",
        AudienceBinding::ResourceIdentifier,
        std::iter::empty::<String>(),
    )?;

    assert_eq!(
        metadata.path(),
        "/.well-known/oauth-protected-resource/tenant/one"
    );
    assert_eq!(
        metadata.uri(),
        "https://api.example/.well-known/oauth-protected-resource/tenant/one"
    );
    let metadata_path = metadata.path().to_owned();
    let app = Router::new().route_service(&metadata_path, metadata).merge(
        Router::new()
            .route("/tenant/one/items", get(|| async {}))
            .layer(validator),
    );
    let response = app
        .clone()
        .oneshot(
            http::Request::builder()
                .uri("/.well-known/oauth-protected-resource/tenant/one")
                .body(Body::empty())?,
        )
        .await?;
    let body = to_bytes(response.into_body(), usize::MAX).await?;
    let document: serde_json::Value = serde_json::from_slice(&body)?;
    assert_eq!(document["resource"], "https://api.example/tenant/one");

    let response = app
        .oneshot(
            http::Request::builder()
                .uri("/tenant/one/items")
                .body(Body::empty())?,
        )
        .await?;
    assert!(
        response.headers()[header::WWW_AUTHENTICATE]
            .to_str()?
            .contains("https://api.example/.well-known/oauth-protected-resource/tenant/one")
    );
    Ok(())
}

#[tokio::test]
async fn one_origin_can_host_multiple_protected_resources() -> Result<(), Box<dyn std::error::Error>>
{
    let payments = ValidatorLayer::builder()
        .validator(MockValidator::no_token())
        .base_url("https://api.example")?
        .build();
    let (payments, payments_metadata) = payments.with_protected_resource(
        "/payments",
        AudienceBinding::ResourceIdentifier,
        std::iter::empty::<String>(),
    )?;

    let inventory = ValidatorLayer::builder()
        .validator(MockValidator::no_token())
        .base_url("https://api.example")?
        .build();
    let (inventory, inventory_metadata) = inventory.with_protected_resource(
        "/inventory",
        AudienceBinding::ResourceIdentifier,
        std::iter::empty::<String>(),
    )?;

    assert_ne!(payments_metadata.path(), inventory_metadata.path());
    let app = Router::new()
        .route_service(payments_metadata.path(), payments_metadata.clone())
        .route_service(inventory_metadata.path(), inventory_metadata.clone())
        .merge(
            Router::new()
                .route("/payments/item", get(|| async {}))
                .layer(payments),
        )
        .merge(
            Router::new()
                .route("/inventory/item", get(|| async {}))
                .layer(inventory),
        );

    for (path, resource_path) in [
        ("/payments/item", "payments"),
        ("/inventory/item", "inventory"),
    ] {
        let response = app
            .clone()
            .oneshot(http::Request::builder().uri(path).body(Body::empty())?)
            .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let challenge = response.headers()[header::WWW_AUTHENTICATE].to_str()?;
        assert!(
            challenge.contains(&format!(
                "https://api.example/.well-known/oauth-protected-resource/{resource_path}"
            )),
            "unexpected challenge for {path}: {challenge}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn protected_resource_enforces_resource_identifier_audience()
-> Result<(), Box<dyn std::error::Error>> {
    let reached: Reached = Arc::default();
    let validator = ValidatorLayer::builder()
        .validator(MockValidator::valid(&[]).with_source(
            "https://issuer.example",
            &["https://api.example/mcp/payments"],
        ))
        .base_url("https://api.example")?
        .build();
    let (validator, _metadata) = validator.with_protected_resource(
        "/mcp/inventory",
        AudienceBinding::ResourceIdentifier,
        std::iter::empty::<String>(),
    )?;
    let stack = validator.layer(handler(reached.clone()));

    let response = stack.oneshot(request()).await?;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(!reached.load(Ordering::SeqCst));
    let challenge = response.headers()[header::WWW_AUTHENTICATE].to_str()?;
    assert!(challenge.contains(r#"error="invalid_token""#));
    assert!(
        challenge
            .contains("https://api.example/.well-known/oauth-protected-resource/mcp/inventory")
    );
    Ok(())
}

#[tokio::test]
async fn protected_resource_accepts_mapped_audience() -> Result<(), Box<dyn std::error::Error>> {
    let reached: Reached = Arc::default();
    let validator = ValidatorLayer::builder()
        .validator(
            MockValidator::valid(&[]).with_source("https://issuer.example", &["api://inventory"]),
        )
        .base_url("https://api.example")?
        .build();
    let (validator, _metadata) = validator.with_protected_resource(
        "/mcp/inventory",
        AudienceBinding::mapped(["api://inventory"]),
        std::iter::empty::<String>(),
    )?;
    let stack = validator.layer(handler(reached.clone()));

    let response = stack.oneshot(request()).await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(reached.load(Ordering::SeqCst));
    Ok(())
}

#[tokio::test]
async fn protected_resource_supports_a_trusted_public_url_after_path_rewrite()
-> Result<(), Box<dyn std::error::Error>> {
    let mock = MockValidator::valid(&[]).with_source(
        "https://issuer.example",
        &["https://api.example/mcp/payments"],
    );
    let observed = mock.observations();
    let validator = ValidatorLayer::builder()
        .validator(mock)
        .base_url("https://api.example")?
        .build();
    let (validator, metadata) = validator.with_protected_resource(
        "/mcp/inventory",
        AudienceBinding::ResourceIdentifier,
        std::iter::empty::<String>(),
    )?;
    let stack = validator.layer(handler(Arc::default()));
    let mut request = http::Request::builder()
        .uri("/internal/inventory/tools?cursor=1")
        .body(Body::empty())?;
    request.extensions_mut().insert(RequestUrl(
        "https://api.example/mcp/inventory/tools?cursor=1".parse()?,
    ));

    let response = stack.oneshot(request).await?;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let challenge = response.headers()[header::WWW_AUTHENTICATE].to_str()?;
    assert!(
        challenge
            .contains("https://api.example/.well-known/oauth-protected-resource/mcp/inventory")
    );
    assert_eq!(
        observed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)[0]
            .uri,
        "https://api.example/mcp/inventory/tools?cursor=1"
    );

    // The same deployment may route the canonical public well-known URL to
    // whatever local path its front proxy exposes to Axum.
    let metadata_response = Router::new()
        .route_service("/internal/resource-metadata/inventory", metadata)
        .oneshot(
            http::Request::builder()
                .uri("/internal/resource-metadata/inventory")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(metadata_response.status(), StatusCode::OK);
    Ok(())
}

#[test]
fn protected_resource_rejects_empty_mapped_audience() -> Result<(), Box<dyn std::error::Error>> {
    let validator = ValidatorLayer::builder()
        .validator(MockValidator::valid(&[]))
        .base_url("https://api.example")?
        .build();
    let result = validator.with_protected_resource(
        "/mcp/inventory",
        AudienceBinding::mapped(std::iter::empty::<String>()),
        std::iter::empty::<String>(),
    );

    assert!(matches!(result, Err(ResourceMetadataError::EmptyAudiences)));
    Ok(())
}

#[test]
fn validator_layer_binds_only_one_protected_resource() -> Result<(), Box<dyn std::error::Error>> {
    let validator = ValidatorLayer::builder()
        .validator(MockValidator::valid(&[]))
        .base_url("https://api.example")?
        .build();
    let (validator, _metadata) = validator.with_optional_authentication_resource(
        "/mcp/one",
        AudienceBinding::ResourceIdentifier,
        std::iter::empty::<String>(),
    )?;

    let result = validator.with_optional_authentication_resource(
        "/mcp/two",
        AudienceBinding::ResourceIdentifier,
        std::iter::empty::<String>(),
    );

    assert!(matches!(
        result,
        Err(ResourceMetadataError::ProtectedResourceAlreadyConfigured)
    ));
    Ok(())
}

#[test]
fn protected_resource_requires_the_layers_public_base_url() {
    let validator = ValidatorLayer::builder()
        .validator(MockValidator::valid(&[]))
        .build();
    let result = validator.with_protected_resource(
        "/mcp/inventory",
        AudienceBinding::ResourceIdentifier,
        std::iter::empty::<String>(),
    );

    assert!(matches!(result, Err(ResourceMetadataError::MissingBaseUrl)));
}

#[tokio::test]
async fn audience_layer_accepts_any_audience_across_token_sources() {
    let reached: Reached = Arc::default();
    let validator = ValidatorLayer::builder()
        .validator(
            MockValidator::valid(&[])
                .with_source("https://issuer-b.example", &["tenant-b", "shared-api"]),
        )
        .build();
    let stack = validator
        .require_any_audience(["tenant-a", "shared-api"])
        .layer(handler(reached.clone()));

    let response = stack.oneshot(request()).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert!(reached.load(Ordering::SeqCst));
}

#[tokio::test]
async fn audience_mismatch_is_invalid_token() -> Result<(), Box<dyn std::error::Error>> {
    let reached: Reached = Arc::default();
    let validator = ValidatorLayer::builder()
        .validator(MockValidator::valid(&[]).with_source("https://issuer-b.example", &["api-b"]))
        .build();
    let stack = validator
        .require_audience("api-a")
        .layer(handler(reached.clone()));

    let response = stack.oneshot(request()).await?;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(!reached.load(Ordering::SeqCst));
    let challenge = response.headers()[header::WWW_AUTHENTICATE].to_str()?;
    assert!(challenge.contains(r#"error="invalid_token""#));
    assert!(challenge.contains("audience does not match"));
    Ok(())
}

#[tokio::test]
async fn custom_authorization_can_use_normalized_issuer_audience_and_claims() {
    let reached: Reached = Arc::default();
    let validator = ValidatorLayer::builder()
        .validator(
            MockValidator::valid(&["admin"]).with_source("https://issuer-b.example", &["api-b"]),
        )
        .build();
    let stack = validator
        .authorize(|token| {
            let source_matches = token.iss.as_deref() == Some("https://issuer-b.example")
                && token.aud.iter().any(|audience| audience == "api-b");
            if source_matches && token.claims.has_scope("admin") {
                Ok(())
            } else {
                Err(AuthorizationError::Forbidden("admin only".to_owned()))
            }
        })
        .layer(handler(reached.clone()));

    let response = stack.oneshot(request()).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert!(reached.load(Ordering::SeqCst));
}

#[tokio::test]
async fn custom_authorization_maps_denial_kinds_and_error_body()
-> Result<(), Box<dyn std::error::Error>> {
    let forbidden = ValidatorLayer::builder()
        .validator(MockValidator::valid(&[]))
        .error_body(DetailsBody)
        .build()
        .authorize(|_| Err(AuthorizationError::Forbidden("policy denied".to_owned())))
        .layer(handler(Arc::default()))
        .oneshot(request())
        .await?;
    assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);
    assert!(
        forbidden.headers()[header::WWW_AUTHENTICATE]
            .to_str()?
            .contains(r#"error="insufficient_scope""#)
    );
    assert_eq!(
        to_bytes(forbidden.into_body(), usize::MAX).await?,
        "error=insufficient_scope;scopes=;challenges=1"
    );

    let invalid = ValidatorLayer::builder()
        .validator(MockValidator::valid(&[]))
        .build()
        .authorize(|_| {
            Err(AuthorizationError::InvalidToken(
                "token source rejected".to_owned(),
            ))
        })
        .layer(handler(Arc::default()))
        .oneshot(request())
        .await?;
    assert_eq!(invalid.status(), StatusCode::UNAUTHORIZED);
    let challenge = invalid.headers()[header::WWW_AUTHENTICATE].to_str()?;
    assert!(challenge.contains(r#"error="invalid_token""#));
    assert!(challenge.contains("token source rejected"));
    Ok(())
}

// --- RequireAuthenticatedLayer: the layer-level gate ---

#[tokio::test]
async fn require_authenticated_allows_valid_token() {
    let reached: Reached = Arc::default();
    let validator = ValidatorLayer::builder()
        .validator(MockValidator::valid(&[]))
        .build();
    let stack = validator.authenticated().layer(handler(reached.clone()));

    let resp = stack.oneshot(request()).await.unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        reached.load(Ordering::SeqCst),
        "handler should run for a valid token"
    );
}

#[tokio::test]
async fn require_authenticated_rejects_missing_token() {
    // The key test: a request with no token must NOT reach the handler when the
    // gate is present (closing the ValidatorLayer fail-open-on-missing-token gap).
    let reached: Reached = Arc::default();
    let validator = ValidatorLayer::builder()
        .validator(MockValidator::no_token())
        .build();
    let stack = validator.authenticated().layer(handler(reached.clone()));

    let resp = stack.oneshot(request()).await.unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(resp.headers()[header::CACHE_CONTROL], "no-store");
    assert!(
        resp.headers().contains_key(http::header::WWW_AUTHENTICATE),
        "401 should carry a WWW-Authenticate challenge"
    );
    assert!(
        !reached.load(Ordering::SeqCst),
        "handler must not run without a token"
    );
}

#[tokio::test]
async fn validator_preserves_server_retry_advice() {
    let validator = ValidatorLayer::builder()
        .validator(MockValidator::server_unavailable(Duration::from_millis(
            1_500,
        )))
        .build();

    let response = validator
        .layer(handler(Arc::default()))
        .oneshot(request())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.headers()[header::RETRY_AFTER], "2");
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert!(
        !response.headers().contains_key(header::WWW_AUTHENTICATE),
        "server failures must not suggest that re-authentication will help"
    );
}

#[test]
fn validator_rejects_invalid_base_urls_at_configuration_time() {
    for invalid in [
        "/relative",
        "ftp://api.example",
        "https://api.example?tenant=one",
    ] {
        let result = ValidatorLayer::builder()
            .validator(MockValidator::valid(&[]))
            .base_url(invalid);

        assert!(result.is_err(), "{invalid:?} should be rejected");
    }
}

#[test]
fn validator_accepts_a_public_base_path() -> Result<(), Box<dyn std::error::Error>> {
    let validator = ValidatorLayer::builder()
        .validator(MockValidator::valid(&[]))
        .base_url("https://api.example/gateway")?
        .build();
    let (_validator, metadata) = validator.with_protected_resource(
        "/mcp/inventory",
        AudienceBinding::ResourceIdentifier,
        std::iter::empty::<String>(),
    )?;
    assert_eq!(
        metadata.resource(),
        "https://api.example/gateway/mcp/inventory"
    );
    assert_eq!(
        metadata.uri(),
        "https://api.example/.well-known/oauth-protected-resource/gateway/mcp/inventory"
    );
    Ok(())
}

#[test]
fn resource_metadata_rejects_invalid_resource_paths() -> Result<(), Box<dyn std::error::Error>> {
    for invalid in [
        "relative",
        "https://api.example/mcp",
        "/path#fragment",
        "/mcp?tenant=a",
        "/mcp?",
    ] {
        let validator = ValidatorLayer::builder()
            .validator(MockValidator::valid(&[]))
            .base_url("https://api.example")?
            .build();
        let result = validator.with_protected_resource(
            invalid,
            AudienceBinding::ResourceIdentifier,
            std::iter::empty::<String>(),
        );

        assert!(matches!(
            result,
            Err(ResourceMetadataError::InvalidResourcePath { .. })
        ));
    }
    Ok(())
}

#[tokio::test]
async fn require_authenticated_without_validator_is_500() {
    // Stacked outside a ValidatorLayer there is no ValidatorData: fail closed
    // with 500 rather than panicking, and do not reach the handler.
    let reached: Reached = Arc::default();
    let stack = RequireAuthenticatedLayer::new().layer(handler(reached.clone()));

    let resp = stack.oneshot(request()).await.unwrap();

    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        !reached.load(Ordering::SeqCst),
        "handler must not run when misconfigured"
    );
}

// --- ValidatorLayer: documented fail-open-on-missing + fail-closed-on-invalid ---

#[tokio::test]
async fn validator_passes_through_when_no_token() {
    // By design: ValidatorLayer alone lets an unauthenticated request reach the
    // handler (the extractor, not the layer, is the gate). This pins that
    // behaviour so a change to it is deliberate.
    let reached: Reached = Arc::default();
    let validator = ValidatorLayer::builder()
        .validator(MockValidator::no_token())
        .build();
    let stack = validator.layer(handler(reached.clone()));

    let resp = stack.oneshot(request()).await.unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        reached.load(Ordering::SeqCst),
        "handler runs (no layer-level gate)"
    );
}

#[tokio::test]
async fn validator_rejects_invalid_token() {
    let reached: Reached = Arc::default();
    let validator = ValidatorLayer::builder()
        .validator(MockValidator::invalid())
        .build();
    let stack = validator.layer(handler(reached.clone()));

    let resp = stack.oneshot(request()).await.unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(
        !reached.load(Ordering::SeqCst),
        "handler must not run for an invalid token"
    );
}

#[tokio::test]
async fn validator_forwards_external_request_context() -> Result<(), Box<dyn std::error::Error>> {
    let mock = MockValidator::valid(&[]);
    let observed = mock.observations();
    let validator = ValidatorLayer::builder()
        .validator(mock)
        .base_url("https://configured.example")?
        .build();
    let stack = validator.layer(handler(Arc::default()));

    let mut request = http::Request::builder()
        .method(Method::POST)
        .uri("/items/42?expand=true")
        .header("x-request-id", "request-1")
        .body(Body::empty())?;
    request
        .extensions_mut()
        .insert(ClientCertDer(vec![1, 2, 3]));
    request.extensions_mut().insert(RequestUrl(
        "https://external.example/api/items/42?expand=true".parse()?,
    ));

    let response = stack.oneshot(request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let observed = observed
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let [request] = observed.as_slice() else {
        return Err("expected exactly one validation call".into());
    };
    assert_eq!(request.method, Method::POST);
    assert_eq!(
        request.uri,
        "https://external.example/api/items/42?expand=true"
    );
    assert_eq!(request.headers["x-request-id"], "request-1");
    assert_eq!(
        request.client_cert_der.as_deref(),
        Some([1, 2, 3].as_slice())
    );
    Ok(())
}

#[tokio::test]
async fn validator_reconstructs_uri_from_base_url() -> Result<(), Box<dyn std::error::Error>> {
    let mock = MockValidator::valid(&[]);
    let observed = mock.observations();
    let validator = ValidatorLayer::builder()
        .validator(mock)
        .base_url("https://api.example/gateway")?
        .build();
    let stack = validator.layer(handler(Arc::default()));
    let request = http::Request::builder()
        .uri("/items?limit=10")
        .body(Body::empty())?;

    stack.oneshot(request).await?;

    let observed = observed
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert_eq!(
        observed[0].uri,
        "https://api.example/gateway/items?limit=10"
    );
    Ok(())
}

#[tokio::test]
async fn validator_propagates_dpop_nonce_on_success() {
    let validator = ValidatorLayer::builder()
        .validator(MockValidator::valid(&[]).with_dpop_nonce("fresh-nonce"))
        .build();

    let response = validator
        .layer(handler(Arc::default()))
        .oneshot(request())
        .await
        .unwrap();

    assert_eq!(response.headers()["dpop-nonce"], "fresh-nonce");
}

#[tokio::test]
async fn rejection_preserves_challenges_nonce_and_custom_body()
-> Result<(), Box<dyn std::error::Error>> {
    let validator = ValidatorLayer::builder()
        .validator(
            MockValidator::invalid()
                .with_dpop_support()
                .with_dpop_nonce("retry-nonce"),
        )
        .error_body(DetailsBody)
        .build();

    let response = validator
        .layer(handler(Arc::default()))
        .oneshot(request())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(response.headers()["dpop-nonce"], "retry-nonce");
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let challenges = response
        .headers()
        .get_all(header::WWW_AUTHENTICATE)
        .iter()
        .map(http::HeaderValue::to_str)
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(challenges.len(), 2);
    assert!(challenges[0].starts_with("Bearer "));
    assert_eq!(challenges[1], "DPoP");
    let body = to_bytes(response.into_body(), usize::MAX).await?;
    assert_eq!(body, "error=invalid_token;scopes=;challenges=2");
    Ok(())
}

#[tokio::test]
async fn extractor_rejection_uses_custom_body_with_stateless_router()
-> Result<(), Box<dyn std::error::Error>> {
    async fn protected(_: ValidatedToken<TestClaims>) {}

    let validator = ValidatorLayer::builder()
        .validator(MockValidator::no_token())
        .error_body(DetailsBody)
        .build();
    let app = Router::new().route("/", get(protected)).layer(validator);

    let response = app.oneshot(request()).await?;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = to_bytes(response.into_body(), usize::MAX).await?;
    assert_eq!(body, "error=none;scopes=;challenges=1");
    Ok(())
}

// --- RequireScopesLayer: exact-match, fail-closed ---

#[tokio::test]
async fn require_scopes_allows_sufficient_scopes() {
    let reached: Reached = Arc::default();
    let validator = ValidatorLayer::builder()
        .validator(MockValidator::valid(&["read", "write"]))
        .build();
    let stack = validator
        .require_scopes(["read"])
        .layer(handler(reached.clone()));

    let resp = stack.oneshot(request()).await.unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert!(reached.load(Ordering::SeqCst));
}

#[tokio::test]
async fn require_scopes_rejects_insufficient_scopes() {
    let reached: Reached = Arc::default();
    let validator = ValidatorLayer::builder()
        .validator(MockValidator::valid(&["read"]))
        .build();
    let stack = validator
        .require_scopes(["write"])
        .layer(handler(reached.clone()));

    let resp = stack.oneshot(request()).await.unwrap();

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(
        !reached.load(Ordering::SeqCst),
        "handler must not run when under-scoped"
    );
}

#[tokio::test]
async fn require_scopes_is_exact_match_not_prefix() {
    // A token granting "readwrite" must not satisfy a requirement for "read".
    let reached: Reached = Arc::default();
    let validator = ValidatorLayer::builder()
        .validator(MockValidator::valid(&["readwrite"]))
        .build();
    let stack = validator
        .require_scopes(["read"])
        .layer(handler(reached.clone()));

    let resp = stack.oneshot(request()).await.unwrap();

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(!reached.load(Ordering::SeqCst));
}

#[tokio::test]
async fn require_scopes_rejects_missing_token() {
    let reached: Reached = Arc::default();
    let validator = ValidatorLayer::builder()
        .validator(MockValidator::no_token())
        .build();
    let stack = validator
        .require_scopes(["read"])
        .layer(handler(reached.clone()));

    let resp = stack.oneshot(request()).await.unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(!reached.load(Ordering::SeqCst));
}

#[tokio::test]
async fn nested_scope_failure_reports_all_required_scopes() -> Result<(), Box<dyn std::error::Error>>
{
    let validator = ValidatorLayer::builder()
        .validator(MockValidator::valid(&["read"]))
        .error_body(DetailsBody)
        .build();
    let read = validator.scope_layer(["read"]);
    let write = validator.scope_layer(["write"]);
    let stack = validator.layer(read.layer(write.layer(handler(Arc::default()))));

    let response = stack.oneshot(request()).await.unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = to_bytes(response.into_body(), usize::MAX).await?;
    assert_eq!(
        body,
        "error=insufficient_scope;scopes=read write;challenges=1"
    );
    Ok(())
}

#[tokio::test]
async fn validator_preserves_nested_request_uri() -> Result<(), Box<dyn std::error::Error>> {
    for (base, override_url, expected) in [
        (None, None, "/api/v1/items?limit=10"),
        (
            Some("https://api.example"),
            None,
            "https://api.example/api/v1/items?limit=10",
        ),
        (
            Some("https://api.example/gateway"),
            None,
            "https://api.example/gateway/api/v1/items?limit=10",
        ),
        (
            Some("https://api.example/gateway"),
            Some("https://public.example/custom/items?limit=10"),
            "https://public.example/custom/items?limit=10",
        ),
    ] {
        let mock = MockValidator::valid(&[]);
        let observed = mock.observations();
        let validator = ValidatorLayer::builder().validator(mock);
        let validator = match base {
            Some(base) => validator.base_url(base)?.build(),
            None => validator.build(),
        };
        let inner = Router::new()
            .route("/items", get(|uri: Uri| async move { uri.to_string() }))
            .layer(validator);
        let app = Router::new().nest("/api", Router::new().nest("/v1", inner));
        let mut request = http::Request::builder()
            .uri("/api/v1/items?limit=10")
            .body(Body::empty())?;
        if let Some(url) = override_url {
            request.extensions_mut().insert(RequestUrl(url.parse()?));
        }
        let response = app.oneshot(request).await?;
        assert_eq!(response.status(), StatusCode::OK);
        // Auth URI reconstruction must not change the router-local handler URI.
        assert_eq!(
            to_bytes(response.into_body(), 1024).await?.as_ref(),
            b"/items?limit=10"
        );
        let observed = observed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(observed[0].uri, expected);
    }
    Ok(())
}
