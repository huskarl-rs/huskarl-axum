//! Browser login, session identity, and local logout for Axum.
//!
//! Follow the walkthrough in `docs/tutorial/browser_login.md`.
//!
//! ```sh
//! export ISSUER=https://your-provider.example.com
//! export CLIENT_ID=your-public-client-id
//! export REDIRECT_URI=http://localhost:3000/callback
//! export COOKIE_KEY="$(openssl rand -hex 32)"
//! cargo run --example login --features login
//! ```
//!
//! Open http://localhost:3000, sign in, and select "View session identity".
//! Return to the home page and use the "Sign out" form to POST to /logout.
//! `LISTEN` defaults to `127.0.0.1:3000`. Keep COOKIE_KEY stable across restarts.

use std::{sync::Arc, time::Duration};

use axum::{
    Json, Router,
    http::{StatusCode, header},
    response::{Html, IntoResponse},
    routing::{any, get},
};
use huskarl::{
    core::{
        client_auth::NoAuth,
        crypto::seal::AeadV1Sealer,
        jwk::{JwksSource, OctBytes},
        secrets::{EnvVarSecret, Secret as _, encodings::HexEncoding},
        server_metadata::AuthorizationServerMetadata,
    },
    grant::authorization_code::AuthorizationCodeGrant,
};
use huskarl_axum::login::{
    CookieSession, CookieSessionStore, LoginConfig, LoginLayer, LoginSession, LogoutConfig,
    Session, SessionLifetime,
};
use huskarl_crypto_native::{NativeVerifierPlatform, aead::AesGcmKey};
use huskarl_reqwest::ReqwestClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let issuer = std::env::var("ISSUER")?;
    let client_id = std::env::var("CLIENT_ID")?;
    let redirect_uri = std::env::var("REDIRECT_URI")?;
    let parsed_redirect = url::Url::parse(&redirect_uri)?;
    let base_url = parsed_redirect.origin().ascii_serialization();
    let listen = std::env::var("LISTEN").unwrap_or_else(|_| "127.0.0.1:3000".into());

    let http_client = ReqwestClient::builder().build().await?;
    let metadata = AuthorizationServerMetadata::oidc_fetch()
        .http_client(&http_client)
        .issuer(&issuer)
        .call()
        .await?;
    let grant = AuthorizationCodeGrant::builder_from_metadata(&metadata)?
        .client_id(client_id)
        .client_auth(NoAuth)
        .http_client(http_client.clone())
        .redirect_uri(redirect_uri.clone())
        .jws_verifier_platform(Arc::new(NativeVerifierPlatform))
        .jws_verifier_factory(JwksSource::builder().http_client(http_client).build())
        .build()
        .await?;

    let key = AesGcmKey::from_secret(
        EnvVarSecret::new("COOKIE_KEY", &HexEncoding)?.mapped(OctBytes::new("A256GCM")),
    )
    .await?;
    let session_store: CookieSessionStore = CookieSessionStore::builder()
        .sealer(AeadV1Sealer::new(key))
        .cookie_name("huskarl_session".parse()?)
        .cookie_path("/".parse()?)
        .build();

    let login_config = LoginConfig::builder()
        .callback_path(parsed_redirect.path().to_owned())
        .scope(vec!["openid".to_owned()])
        .session_lifetime(SessionLifetime::Bounded(Duration::from_secs(8 * 60 * 60)))
        // Local logout ends this application's session. The public destination
        // lets the user see the result without immediately starting login again.
        .logout(
            LogoutConfig::builder()
                .path("/logout")
                .post_logout_redirect_uri(format!("{base_url}/signed-out"))
                .build()?,
        )
        .build()?;
    let login = LoginLayer::builder()
        .config(login_config)
        .grant(grant)
        .session_store(session_store)
        .build()?;

    let app = app(login, parsed_redirect.path());
    let listener = tokio::net::TcpListener::bind(&listen).await?;
    println!("Open {base_url}/ in your browser (listening on {listen})");
    axum::serve(listener, app).await?;
    Ok(())
}

fn app(login: LoginLayer<CookieSessionStore>, callback_path: &str) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/me", get(identity))
        // Gate only the routes added so far.
        .route_layer(login.require_session())
        .route("/signed-out", get(signed_out))
        // Register engine routes so Axum routes them through the outer layer.
        // The placeholder runs only if the engine fails to recognize the path.
        .route(callback_path, any(engine_route_fallback))
        .route("/logout", any(engine_route_fallback))
        .layer(login.load_session())
        .layer(login.login_routes())
}

async fn engine_route_fallback() -> StatusCode {
    StatusCode::NOT_FOUND
}

async fn index() -> impl IntoResponse {
    (
        [(header::CACHE_CONTROL, "no-store")],
        Html(
            r#"<!doctype html><html lang="en"><title>Login example</title>
<h1>You are signed in</h1>
<p><a href="/me">View session identity</a></p>
<form method="post" action="/logout"><button>Sign out</button></form>
</html>"#,
        ),
    )
}

async fn identity(session: LoginSession<CookieSession>) -> impl IntoResponse {
    (
        [(header::CACHE_CONTROL, "no-store")],
        Json(serde_json::json!({ "subject": session.sub() })),
    )
}

async fn signed_out() -> Html<&'static str> {
    Html(
        r#"<!doctype html><html lang="en"><title>Signed out</title>
<h1>You are signed out of this application</h1>
<p><a href="/">Sign in again</a></p></html>"#,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use huskarl::core::jwk::{OctKey, SymmetricJwk};
    use tower::ServiceExt as _;

    struct JwksClient;

    impl huskarl::core::http::HttpClient for JwksClient {
        fn execute(
            &self,
            request: http::Request<bytes::Bytes>,
            _: huskarl::core::http::Idempotency,
        ) -> huskarl::core::platform::MaybeSendBoxFuture<
            '_,
            Result<huskarl::core::http::HttpResponse, huskarl::core::Error>,
        > {
            assert_eq!(request.uri(), "https://provider.example/jwks");
            Box::pin(async {
                Ok(huskarl::core::http::HttpResponse {
                    status: StatusCode::OK,
                    headers: http::HeaderMap::new(),
                    body: bytes::Bytes::from_static(br#"{"keys":[]}"#),
                })
            })
        }
    }

    #[tokio::test]
    async fn browser_routes_reach_the_engine_and_logout_has_a_public_destination()
    -> Result<(), Box<dyn std::error::Error>> {
        let _ = env_logger::builder().is_test(true).try_init();
        // Direct endpoints avoid discovery. None of these requests exchanges
        // tokens; the JWKS client returns an empty test keyset without network I/O.
        let grant = AuthorizationCodeGrant::builder()
            .client_id("test-client")
            .issuer("https://provider.example".to_owned())
            .client_auth(NoAuth)
            .http_client(JwksClient)
            .authorization_endpoint("https://provider.example/authorize".parse()?)
            .token_endpoint("https://provider.example/token".parse()?)
            .jwks_uri("https://provider.example/jwks".parse()?)
            .jws_verifier_platform(Arc::new(NativeVerifierPlatform))
            .jws_verifier_factory(JwksSource::builder().http_client(JwksClient).build())
            .redirect_uri("http://localhost:3000/callback")
            .build()
            .await?;
        let key = AesGcmKey::from_jwk(
            SymmetricJwk::builder()
                .key(OctKey::builder().k(vec![42; 32]).build())
                .build(),
        )?;
        let store: CookieSessionStore = CookieSessionStore::builder()
            .sealer(AeadV1Sealer::new(key))
            .cookie_name("huskarl_session".parse()?)
            .build();
        let login = LoginLayer::builder()
            .grant(grant)
            .session_store(store)
            .config(
                LoginConfig::builder()
                    .callback_path("/callback")
                    .scope(vec!["openid".to_owned()])
                    .session_lifetime(SessionLifetime::Bounded(Duration::from_secs(3600)))
                    .logout(
                        LogoutConfig::builder()
                            .path("/logout")
                            .post_logout_redirect_uri("http://localhost:3000/signed-out")
                            .build()?,
                    )
                    .build()?,
            )
            .build()?;
        let app = app(login, "/callback");

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(header::ACCEPT, "text/html")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::FOUND);
        assert!(
            response.headers()[header::LOCATION]
                .to_str()?
                .starts_with("https://provider.example/authorize?")
        );
        assert!(response.headers().contains_key(header::SET_COOKIE));

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/me")
                    .header(header::ACCEPT, "application/json")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // POST on the callback must reach the engine's 405, not Axum's 404.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/callback")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(response.headers()[header::ALLOW], "GET");

        let response = app
            .clone()
            .oneshot(Request::builder().uri("/logout").body(Body::empty())?)
            .await?;
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(response.headers()[header::ALLOW], "POST");

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/logout")
                    .header(header::ORIGIN, "http://localhost:3000")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers()[header::LOCATION],
            "http://localhost:3000/signed-out"
        );
        assert!(
            response
                .headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .any(|value| value
                    .to_str()
                    .is_ok_and(|value| value.contains("Max-Age=0")))
        );

        let response = app
            .oneshot(Request::builder().uri("/signed-out").body(Body::empty())?)
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!response.headers().contains_key(header::LOCATION));
        Ok(())
    }
}
