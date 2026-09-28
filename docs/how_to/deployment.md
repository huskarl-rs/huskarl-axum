# Deploy browser login with Axum

Use this after the browser-login tutorial, before exposing the application
beyond localhost.

## Choose your deployment

| Session storage | Use when | Limit |
|---|---|---|
| Cookie sessions (the example) | You can accept sessions without individual server-side revocation | Delayed responses can restore older cookies, including after logout |
| Store-backed sessions with a shared backend | Logout must revoke the session on the server | Revocation depends on successful deletion; stored-state protection does not prevent simultaneous refresh exchanges |

Neither choice prevents two requests from exchanging the same refresh token,
even on one replica. Local logout also leaves provider SSO active. Resolve
these choices using the shared [deployment guide](https://docs.rs/huskarl-login/latest/huskarl_login/_docs/how_to/deployment/),
which covers provider reuse, keys, storage, and logout. The steps below cover
this adapter's integration.

## Configure Axum

1. **Set the public origin.** Register the public HTTPS callback with the provider
   and set `REDIRECT_URI` to it. This controls secure cookies; it does not enable
   TLS on the example's plain HTTP listener. Terminate TLS at your server or a
   trusted reverse proxy and protect the internal connection.
2. **Keep sessions readable.** Load a stable `COOKIE_KEY` from managed secret
   storage and share compatible keys and session configuration across replicas.
   The example accepts one key; rolling rotation requires an integration with
   a key ring. Follow the shared guide for the rotation sequence.
3. **Order the layers.** Callback/logout handling must run before session
   loading, which must run before the protected-route gate. Axum runs the
   last-added layer first. Use [`LoginLayer`](crate::login::LoginLayer) for an
   entirely protected router or the [tutorial](crate::login::tutorial) for mixed
   routes. Register callback/logout routes and keep the signed-out page public.
4. **Match proxy and router paths.** Follow
   [Nested routers and reverse proxies](crate::login#nested-routers-and-reverse-proxies).
   Preserve the browser's `Origin` for POST logout. If middleware supplies
   [`RequestUrl`](crate::extensions::RequestUrl), derive it only from trusted
   configuration or headers overwritten by a trusted proxy that clients cannot
   bypass; it overrides Axum's original URI.
5. **Preserve response headers.** Keep every `Set-Cookie` header through outer
   middleware and reverse proxies. Exclude personalized responses from shared
   caches even when cookies do not change. The example's protected handlers use
   `Cache-Control: no-store`; see the shared
   [caching guide](https://docs.rs/huskarl-login/latest/huskarl_login/_docs/how_to/caching/).

## Account for Axum's response lifecycle

The login middleware loads or refreshes the session before calling the inner
service. After that service returns a response, it attaches queued cookies and
attempts any pending persistence before returning to outer middleware.

| Request outcome | Cookie-delivery consequence |
|---|---|
| Handler returns a response, including an HTTP error response | The response passes through login's cookie handling |
| Service error, cancellation, or timeout interrupts the inner call | Cookie handling and pending persistence may not run |
| Outer middleware replaces the response | Cookies already attached by login may be discarded |

Test your timeout and error-handling layers. Preserve required cookie updates
and clears when replacing a response and those headers are available. A
successful refresh exchange alone does not prove delivery to the browser.
The shared guide explains [delivery and response-ordering limits](https://docs.rs/huskarl-login/latest/huskarl_login/_docs/how_to/deployment/#limits-configuration-cannot-remove).

## If you forward identity to another service

Axum handlers normally read identity from the session extractor. If your app
forwards identity, remove client-supplied identity headers and populate them
from authenticated context. Restrict the receiving service to trusted
application connections using network controls or authenticated transport.
Do not forward session cookies as an identity mechanism.

## Verify the integration

Run the shared guide's [rollout checks](https://docs.rs/huskarl-login/latest/huskarl_login/_docs/how_to/deployment/#verify-before-rollout)
for restart persistence, replicas, concurrent refresh, and logout. Then check
these Axum-specific paths:

- Protected, public, callback, and logout routes through nesting and proxy rewrites.
- Timeouts, service errors, and response replacement during refresh; confirm
  updated cookies return on the next browser request when delivery succeeds.
- Forged identity headers and direct downstream access, if forwarding identity.

For failures, use [Troubleshoot browser login](https://docs.rs/huskarl-login/latest/huskarl_login/_docs/how_to/troubleshooting/).
