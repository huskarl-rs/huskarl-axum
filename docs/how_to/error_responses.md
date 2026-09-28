# Customize authentication error responses

Use separate renderers for browser-login pages and resource-server rejections.
They receive different information: login pages get a status and message;
resource rejections also expose token error codes, required scopes, and
challenge values. Metadata endpoints keep their own JSON and method responses.

## Resource-server error bodies

Both adapters accept an `ErrorBody` renderer through `.error_body(...)`.
The default is an empty body. Use the structured fields instead of parsing
`WWW-Authenticate`; missing credentials have no error code, and server-side
failures deliberately omit internal descriptions. This JSON example has the
same payload in both adapters:

```rust
use axum::Json;
use huskarl_axum::response::{ErrorBody, ErrorDetails};

#[derive(Clone)]
struct ApiErrors;

impl ErrorBody for ApiErrors {
    type Body = Json<serde_json::Value>;

    fn error_body(&self, details: &ErrorDetails<'_>) -> Self::Body {
        Json(serde_json::json!({
            "status": details.status.as_u16(),
            "error": details.error_code.map(|code| code.as_str()),
            "error_description": details.error_description,
            "scope": details.required_scopes.map(|scopes| scopes.join(" ")),
        }))
    }
}
# fn configure<V>(validator: V)
# where V: huskarl_axum::resource_server::validator::AccessTokenValidator
#     + huskarl_axum::resource_server::validator::metadata::ProvideValidatorMetadata {
let layer = huskarl_axum::layers::ValidatorLayer::builder()
    .validator(validator)
    .error_body(ApiErrors)
    .build();
# }
```

Configure this on `ValidatorLayer::builder()` before `.build()`. The renderer is propagated
to authentication/scope layers and token extractor rejections.
Keep the returned value focused on its body and content type, as `Json` does;
the library applies the status, authentication challenges, nonce, retry interval,
and `Cache-Control: no-store`. Outer middleware must preserve these headers.

## Browser-login error pages

Both adapters use `huskarl_login::ErrorPage`. The renderer controls the media
type and body; the login engine controls the response status and protocol
headers. This example uses plain text so provider-supplied messages cannot be
interpreted as HTML:

```rust
# #[cfg(feature = "login")]
# mod login_example {
use huskarl_login::{ErrorPage, ErrorPageResponse};
use http::StatusCode;

struct LoginErrors;

impl ErrorPage for LoginErrors {
    fn render(&self, status: StatusCode, message: &str) -> ErrorPageResponse {
        ErrorPageResponse {
            content_type: "text/plain; charset=utf-8",
            body: format!("Sign-in failed ({status}): {message}").into(),
        }
    }
}
# }
```

If you render HTML instead, escape the message for that context. Provider and
request-derived messages are untrusted. Use JSON serialization for JSON bodies.

Add `.error_page(Box::new(LoginErrors))` to `LoginLayer::builder()`. The layer
passes this renderer to the shared login engine. Its bundled and component
layers then use the same login-error configuration.
