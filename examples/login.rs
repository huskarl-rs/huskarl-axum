//! OAuth 2.0 Authorization Code Grant login example for Axum.
//!
//! # Usage
//!
//! ```sh
//! ISSUER=https://auth.example.com \
//! CLIENT_ID=my-client \
//! REDIRECT_URI=http://localhost:3000/callback \
//! cargo run --example login --features login
//! ```
//!
//! Then open http://localhost:3000 in your browser. Navigate to
//! http://localhost:3000/logout to log out.
//!
//! Environment variables:
//!   - `ISSUER`        — Authorization server issuer URL (required)
//!   - `CLIENT_ID`     — OAuth2 client ID (required)
//!   - `REDIRECT_URI`  — Callback URL registered with the AS (required)
//!   - `COOKIE_KEY`    — 32-byte AES-256 key, hex-encoded (required)
//!   - `LISTEN`        — Listen address (default: `0.0.0.0:3000`)

use std::sync::Arc;

use axum::{Router, routing::get};
use huskarl::{
    core::{
        jwk::{JwksSource, OctBytes},
        secrets::{EnvVarSecret, Secret as _, encodings::HexEncoding},
        server_metadata::AuthorizationServerMetadata,
    },
    grant::authorization_code::AuthorizationCodeGrant,
};
use huskarl_axum::login::{
    CookieSession, CookieSessionStore, LoginConfig, LoginLayer, LoginSession, LogoutConfig,
    SessionLifetime,
};
use huskarl_axum::resource_server::core::client_auth::NoAuth;
use huskarl_crypto_native::aead::AesGcmKey;
use huskarl_reqwest::ReqwestClient;

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    env_logger::init();

    let issuer = std::env::var("ISSUER").expect("ISSUER env var required");
    let client_id = std::env::var("CLIENT_ID").expect("CLIENT_ID env var required");
    let redirect_uri = std::env::var("REDIRECT_URI").expect("REDIRECT_URI env var required");
    let parsed_redirect = url::Url::parse(&redirect_uri).expect("REDIRECT_URI must be a valid URL");
    let base_url = format!(
        "{}://{}",
        parsed_redirect.scheme(),
        parsed_redirect.authority()
    );
    let listen = std::env::var("LISTEN").unwrap_or_else(|_| "0.0.0.0:3000".into());

    let http_client = ReqwestClient::builder()
        .mtls(huskarl_reqwest::mtls::NoMtls)
        .build()
        .await
        .expect("failed to create HTTP client");

    let metadata = AuthorizationServerMetadata::oidc_fetch()
        .http_client(&http_client)
        .issuer(&issuer)
        .call()
        .await
        .expect("failed to fetch authorization server metadata");

    let grant = AuthorizationCodeGrant::builder_from_metadata(&metadata)
        .expect("authorization server does not advertise an authorization endpoint")
        .client_id(client_id)
        .client_auth(NoAuth)
        .http_client(http_client.clone())
        .redirect_uri(redirect_uri.clone())
        .jws_verifier_factory(Arc::new(
            JwksSource::builder().http_client(http_client).build(),
        ))
        .build()
        .await
        .expect("failed to build authorization code grant");

    let sealer = AesGcmKey::from_secret(
        EnvVarSecret::new("COOKIE_KEY", &HexEncoding)
            .expect("COOKIE_KEY env var required (hex-encoded 32 bytes)")
            .mapped(OctBytes::new("A256GCM")),
    )
    .await
    .expect("failed to load AES-256 key");

    // The session store owns the cipher; `LoginLayer` reuses it for the
    // login-state cookie by default (see below), so the key lives in one place.
    let session_store: CookieSessionStore = CookieSessionStore::builder()
        .sealer(sealer)
        .cookie_name("huskarl_session".parse().unwrap())
        .cookie_path("/".parse().unwrap())
        .build();

    let login_config = LoginConfig::builder()
        .callback_path(parsed_redirect.path().to_owned())
        .scope(vec!["openid".to_owned()])
        .base_url(base_url.parse().expect("valid base URL"))
        .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
        .logout(
            LogoutConfig::builder()
                .path("/logout")
                .maybe_end_session_endpoint(metadata.end_session_endpoint)
                .build()
                .expect("valid logout config"),
        )
        .build()
        .expect("failed to build login config");

    let login = LoginLayer::builder()
        .config(login_config)
        .grant(grant)
        .session_store(session_store)
        .sealer(sealer)
        .build();

    let app = Router::new().route("/", get(index)).layer(login);

    let listener = tokio::net::TcpListener::bind(&listen).await.unwrap();
    println!("Listening on {listen}");
    println!("Callback URL: {redirect_uri}");
    println!("Logout URL:   {base_url}/logout");
    axum::serve(listener, app).await.unwrap();
}

async fn index(session: LoginSession<CookieSession>) -> String {
    format!(
        "Hello! Token expires: {:?}\nCreated at: {:?}",
        session.token_expiry(),
        session.created_at()
    )
}
