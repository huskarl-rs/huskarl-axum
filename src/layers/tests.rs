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
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use axum_core::{body::Body, extract::Request, response::Response};
use http::StatusCode;
use huskarl_resource_server::{
    error::{ToRfc6750Error, TokenErrorCode, TokenValidationError},
    validator::{
        AccessTokenValidator, ValidatedRequest, ValidationResult,
        extract::TokenType,
        metadata::{ProvideValidatorMetadata, ValidatorMetadata},
    },
};
use tower::{Layer, Service, ServiceExt as _};

use super::{HasScopes, RequireAuthenticatedLayer, ValidatorLayer};
use crate::extractors::HasClaims;

/// What the mock validator should return for `validate_request`.
#[derive(Clone)]
enum Outcome {
    /// A valid token granting the given scopes.
    Valid(Vec<String>),
    /// No authentication header present (`Ok(None)`).
    NoToken,
    /// A token that failed validation (`Err`).
    Invalid,
}

#[derive(Clone)]
struct MockValidator {
    outcome: Outcome,
}

impl MockValidator {
    fn valid(scopes: &[&str]) -> Self {
        Self {
            outcome: Outcome::Valid(scopes.iter().map(|s| (*s).to_string()).collect()),
        }
    }
    fn no_token() -> Self {
        Self {
            outcome: Outcome::NoToken,
        }
    }
    fn invalid() -> Self {
        Self {
            outcome: Outcome::Invalid,
        }
    }
}

#[derive(Clone)]
struct TestClaims {
    scopes: Vec<String>,
}

impl HasScopes for TestClaims {
    fn scopes(&self) -> Option<Vec<String>> {
        Some(self.scopes.clone())
    }
}

/// Router-state stand-in declaring the claims type, for `claims_context_for`.
struct TestState;

impl HasClaims for TestState {
    type Claims = TestClaims;
}

#[derive(Debug)]
struct MockError;

impl ToRfc6750Error for MockError {
    fn attempted_scheme(&self) -> Option<TokenType> {
        Some(TokenType::Bearer)
    }
    fn token_error(&self) -> TokenValidationError {
        // A client error → 401, mirroring an invalid/expired access token.
        TokenValidationError::Client(TokenErrorCode::InvalidToken)
    }
    fn error_description(&self) -> Option<String> {
        Some("mock invalid token".to_string())
    }
}

impl AccessTokenValidator for MockValidator {
    type Claims = TestClaims;
    type Error = MockError;

    fn validate_request<'a>(
        &'a self,
        _headers: &'a http::HeaderMap,
        _method: &'a http::Method,
        _uri: &'a http::Uri,
        _client_cert_der: Option<&'a [u8]>,
    ) -> huskarl_resource_server::core::platform::MaybeSendBoxFuture<
        'a,
        ValidationResult<Self::Claims, Self::Error>,
    > {
        let outcome = match &self.outcome {
            Outcome::Valid(scopes) => Ok(Some(ValidatedRequest {
                iss: Some("https://as.example.com".to_string()),
                sub: Some("user-1".to_string()),
                aud: vec!["my-api".to_string()],
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
            Outcome::Invalid => Err(MockError),
        };
        Box::pin(async move {
            ValidationResult {
                outcome,
                dpop_nonce: None,
            }
        })
    }
}

impl ProvideValidatorMetadata for MockValidator {
    fn validator_metadata(&self, resource: Option<&str>) -> ValidatorMetadata {
        ValidatorMetadata::builder()
            .maybe_resource(resource)
            .bearer_methods_supported(bon::vec!["header"])
            .build()
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

// --- RequireAuthenticatedLayer: the layer-level gate ---

#[tokio::test]
async fn require_authenticated_allows_valid_token() {
    let reached: Reached = Arc::default();
    let validator = ValidatorLayer::builder()
        .validator(MockValidator::valid(&[]))
        .build();
    let stack = validator.layer(
        validator
            .require_authenticated()
            .layer(handler(reached.clone())),
    );

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
    let stack = validator.layer(
        validator
            .require_authenticated()
            .layer(handler(reached.clone())),
    );

    let resp = stack.oneshot(request()).await.unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
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

// --- RequireScopesLayer: exact-match, fail-closed ---

#[tokio::test]
async fn require_scopes_allows_sufficient_scopes() {
    let reached: Reached = Arc::default();
    let validator = ValidatorLayer::builder()
        .validator(MockValidator::valid(&["read", "write"]))
        .build();
    // `claims_context_for` only compiles because TestState declares the same
    // claims type the mock validator produces — the compiler-checked bridge.
    let scopes = validator
        .claims_context_for::<TestState>()
        .require_scopes(vec!["read".to_string()]);
    let stack = validator.layer(scopes.layer(handler(reached.clone())));

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
    let scopes = validator
        .claims_context::<TestClaims>()
        .require_scopes(vec!["write".to_string()]);
    let stack = validator.layer(scopes.layer(handler(reached.clone())));

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
    let scopes = validator
        .claims_context::<TestClaims>()
        .require_scopes(vec!["read".to_string()]);
    let stack = validator.layer(scopes.layer(handler(reached.clone())));

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
    let scopes = validator
        .claims_context::<TestClaims>()
        .require_scopes(vec!["read".to_string()]);
    let stack = validator.layer(scopes.layer(handler(reached.clone())));

    let resp = stack.oneshot(request()).await.unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(!reached.load(Ordering::SeqCst));
}
