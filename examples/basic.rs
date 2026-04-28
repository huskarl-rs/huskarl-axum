use std::sync::Arc;

use axum::{Json, Router, routing::get};
use huskarl_axum::{
    extensions::ValidatedToken,
    layers::{HasScopes, ValidatorLayer},
    resource_server::{
        core::{jwk::JwksSource, server_metadata::AuthorizationServerMetadata},
        validator::custom::CustomValidator,
    },
    response::ErrorBody,
};
use huskarl_reqwest::mtls::NoMtls;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OurClaims {
    scp: Vec<String>,
    user_id: String,
    blah: u32,
}

impl HasScopes for OurClaims {
    fn scopes(&self) -> Option<Vec<String>> {
        Some(self.scp.clone())
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct MyJsonError;

impl ErrorBody for MyJsonError {
    type Body = Json<serde_json::Value>;

    fn error_body(&self, status: http::StatusCode, _challenges: &[String]) -> Self::Body {
        Json(serde_json::json!({
            "status": status.as_u16(),
            "error": status.to_string(),
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

    let authorization_server_metadata = AuthorizationServerMetadata::builder()
        .http_client(&client)
        .issuer("https://earnestanalytics.okta.com/oauth2/aus1tu9e8dbwLsWJl358")
        .build()
        .await
        .unwrap();

    let validator = CustomValidator::builder_from_metadata(&authorization_server_metadata)
        .with_claims::<OurClaims>()
        .jws_verifier_factory(Arc::new(JwksSource::builder().http_client(client).build()))
        .build()
        .await
        .unwrap();

    let app = Router::new().route("/user", get(user)).layer(
        ValidatorLayer::builder()
            .validator(validator)
            .error_body(MyJsonError)
            .build(),
    );

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn user(token: ValidatedToken<OurClaims>) -> String {
    format!("User ID: {}", token.claims.user_id)
}
