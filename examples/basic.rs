use std::sync::Arc;

use axum::{Json, Router, routing::get};
use huskarl_axum::{
    extractors::{HasClaims, TokenFor},
    layers::{HasScopes, ValidatorLayer},
    resource_server::{
        core::{jwk::JwksSource, server_metadata::AuthorizationServerMetadata},
        validator::custom::CustomValidator,
    },
    response::{ErrorBody, ErrorDetails},
};
use huskarl_reqwest::mtls::NoMtls;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OurClaims {
    scp: Vec<String>,
    user_id: String,
}

#[derive(Clone)]
struct AppState;

impl HasClaims for AppState {
    type Claims = OurClaims;
}

impl HasScopes for OurClaims {
    fn scopes(&self) -> Option<Vec<String>> {
        Some(self.scp.clone())
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct MyJsonError;

/// An RFC 6750-style JSON error body, built from the structured failure
/// details — no parsing of the `WWW-Authenticate` challenge strings needed.
impl ErrorBody for MyJsonError {
    type Body = Json<serde_json::Value>;

    fn error_body(&self, details: &ErrorDetails<'_>) -> Self::Body {
        Json(serde_json::json!({
            "status": details.status.as_u16(),
            "error": details.error_code.map(|c| c.as_str()),
            "error_description": details.error_description,
            "scope": details.required_scopes.map(|s| s.join(" ")),
        }))
    }
}

#[tokio::main]
async fn main() {
    let client = huskarl_reqwest::ReqwestClient::builder()
        .mtls(NoMtls)
        .build()
        .await
        .unwrap();

    let authorization_server_metadata = AuthorizationServerMetadata::oidc_fetch()
        .http_client(&client)
        .issuer("https://earnestanalytics.okta.com/oauth2/aus1tu9e8dbwLsWJl358")
        .call()
        .await
        .unwrap();

    let validator = CustomValidator::builder_from_metadata(&authorization_server_metadata)
        .with_claims::<OurClaims>()
        .jws_verifier_factory(Arc::new(JwksSource::builder().http_client(client).build()))
        .build()
        .await
        .unwrap();

    let validator_layer = ValidatorLayer::builder()
        .validator(validator)
        .error_body(MyJsonError)
        .build();

    // Scope enforcement for /admin. `claims_context_for::<AppState>()` is
    // compiler-checked: it only builds if the validator's claims type matches
    // AppState's `HasClaims` declaration, so the state and the validator
    // cannot silently disagree about the claims type.
    let require_admin = validator_layer
        .claims_context_for::<AppState>()
        .require_scopes(vec!["admin".to_owned()]);

    let app = Router::new()
        .route("/admin", get(admin).layer(require_admin))
        .route("/user", get(user))
        .layer(validator_layer)
        .with_state(AppState);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

// `TokenFor<AppState>` is `ValidatedToken<OurClaims>` spelled through the
// state's `HasClaims` declaration, so the claims type is named in one place.
async fn user(token: TokenFor<AppState>) -> String {
    format!("User ID: {}", token.claims.user_id)
}

/// Reached only with a token granting the `admin` scope; otherwise the
/// `RequireScopesLayer` on this route answers 403 (or 401 without a token).
async fn admin(token: TokenFor<AppState>) -> String {
    format!("Admin: {}", token.claims.user_id)
}
