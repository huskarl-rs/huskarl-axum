# Sign in to an Axum application

Run the `login` example, sign in through your OIDC provider, view the session's
subject identifier, and sign out. The example uses encrypted cookie sessions
with an eight-hour absolute lifetime and local application logout.

## 1. Register a development client

You need Rust 1.92 or later, OpenSSL, and an OIDC provider you can configure.
Register a **public client** supporting Authorization Code with PKCE and no
client secret. The example uses `NoAuth`; confidential client registrations
require a different grant configuration.

Register this exact callback URI:

```text
http://localhost:3000/callback
```

Record the issuer URL and client ID. Use `localhost` consistently: changing to
`127.0.0.1` in the browser changes the origin and cookie host.

## 2. Configure and start the example

From a checkout of `huskarl-axum`, with the sibling `huskarl` and `huskarl-login`
repositories available for its Cargo path dependencies, run:

```sh
export ISSUER='https://your-provider.example.com'
export CLIENT_ID='your-public-client-id'
export REDIRECT_URI='http://localhost:3000/callback'
export COOKIE_KEY="$(openssl rand -hex 32)"
cargo run --example login --features login
```

Replace the issuer and client ID with your registration. `COOKIE_KEY` is a
hex-encoded 256-bit AES key. Generate it once for this exercise and retain it
across restarts. The core `huskarl-login` tutorial uses a different variable
with base64 encoding; do not copy that encoded value into `COOKIE_KEY`.

The example discovers the provider, constructs the login layers, and prints:

```text
Open http://localhost:3000/ in your browser (listening on 127.0.0.1:3000)
```

If startup fails, check the named environment variable, key encoding, issuer,
and network access. `LISTEN` changes the listening address; changing the public
port also requires updating `REDIRECT_URI` and the provider registration.

## 3. Sign in and view your identity

Open `http://localhost:3000/` in a browser. Expect this sequence:

1. The protected route redirects to your provider.
2. You authenticate and, if requested, consent to the `openid` scope.
3. The provider returns to `/callback` with an authorization code and state.
4. The engine exchanges the code, validates the response, and sets the session
   cookie. The browser returns to `/` and displays **You are signed in**.
5. Select **View session identity**. `/me` displays JSON such as
   `{"subject":"your-provider-subject"}`. This is the provider's subject
   identifier, not necessarily your email address.

The example exposes only the subject, never access or refresh tokens. Its
protected responses explicitly use `Cache-Control: no-store`.

## 4. Sign out

Return to `/` and select **Sign out**. The form submits `POST /logout` from the
same origin. The engine clears the session cookies and returns a `303` redirect
to `/signed-out`, which displays **You are signed out of this application**.

Typing `/logout` into the address bar sends GET and receives `405 Method Not
Allowed`. A POST without the matching `Origin` receives `403 Forbidden`.

This example does not call the provider's end-session endpoint. Selecting
**Sign in again** starts a new application login; your provider may still have
an SSO session and authenticate you without asking for a password. That is
separate from the application cookie having been cleared.

## How the routes fit together

The example's `app` function assembles the layers in this order:

| Routes/layer | Purpose |
|---|---|
| `/` and `/me`, followed by `require_session()` | Protect the application pages |
| `/signed-out` | Show a public destination after logout |
| Callback and `/logout` routes | Ensure Axum routes these requests through the engine layer |
| `load_session()` | Supply sessions to handlers when present |
| `login_routes()` added last | Handle callback and logout before loading or gating requests |

Axum runs the last-added layer first. The callback and logout placeholders
should never serve a correctly configured engine request; they return `404`
if a path is not recognized. Keep the configured callback path and registered
Axum route identical.

[`LoginSession`](crate::login::LoginSession) gives the identity handler access
to the session. For an application where every route is protected, the bundled
[`LoginLayer`](crate::login::LoginLayer) is shorter. Here the separate layers
allow the signed-out page to remain public.

## Next steps

- Read [mixed public/protected routes](crate::login) before adding more routes.
- Add custom session fields using the
  [enrichment guide](https://docs.rs/huskarl-login/latest/huskarl_login/_docs/how_to/enrichment/).
- Diagnose unexpected responses using
  [Troubleshoot browser login](https://docs.rs/huskarl-login/latest/huskarl_login/_docs/how_to/troubleshooting/).
- Follow [Deploy browser login](crate::login::deployment) before exposing the
  application beyond localhost.
