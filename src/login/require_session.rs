//! Tower middleware that gates a route subtree on an authenticated session.

use std::{pin::Pin, sync::Arc};

use axum_core::{
    extract::Request,
    response::{IntoResponse, Response},
};
use huskarl_login::{
    SessionDriver,
    engine::{LoginEngine, is_cors_preflight},
};
use tower::{Layer, Service};

use super::extractors::LoginSession;
use super::layer::{effective_uri, to_response};
use super::load_session::SessionLoadAttempted;

/// What [`RequireSessionLayer`] does when a request arrives without a session
/// already loaded into request extensions.
#[derive(Clone, Copy)]
pub enum UnauthenticatedAction {
    /// Always return `401 Unauthorized`. Use this for API-only subtrees.
    Reject,
    /// For browser navigation requests: 302 to the authorization server,
    /// preserving the current URL. For XHR / API requests: 401. Decided by
    /// the engine's navigation/XHR heuristic.
    LoginOrReject,
}

/// Pure gate: lets requests through if a session is in extensions, otherwise
/// applies [`UnauthenticatedAction`]. Does not load or persist anything —
/// stack a [`LoadSessionLayer`](super::LoadSessionLayer) outside this one.
///
/// If no loader ran ahead of the gate (detected via the
/// [`SessionLoadAttempted`] marker), the request short-circuits with
/// `500 Internal Server Error` — almost always a middleware-ordering bug.
/// Without the loader no request could ever carry a session, so
/// [`LoginOrReject`](UnauthenticatedAction::LoginOrReject) would redirect
/// every request to the authorization server in an endless login loop.
pub struct RequireSessionLayer<SD> {
    engine: Arc<LoginEngine<SD>>,
    action: UnauthenticatedAction,
    cors_passthrough: bool,
}

impl<SD> RequireSessionLayer<SD> {
    #[cfg(test)]
    pub(super) fn new(engine: Arc<LoginEngine<SD>>, action: UnauthenticatedAction) -> Self {
        Self::with_cors_passthrough(engine, action, true)
    }

    pub(super) fn with_cors_passthrough(
        engine: Arc<LoginEngine<SD>>,
        action: UnauthenticatedAction,
        cors_passthrough: bool,
    ) -> Self {
        Self {
            engine,
            action,
            cors_passthrough,
        }
    }
}

impl<SD> Clone for RequireSessionLayer<SD> {
    fn clone(&self) -> Self {
        Self {
            engine: self.engine.clone(),
            action: self.action,
            cors_passthrough: self.cors_passthrough,
        }
    }
}

impl<SD, S> Layer<S> for RequireSessionLayer<SD> {
    type Service = RequireSessionService<SD, S>;

    fn layer(&self, inner: S) -> Self::Service {
        RequireSessionService {
            inner,
            engine: self.engine.clone(),
            action: self.action,
            cors_passthrough: self.cors_passthrough,
        }
    }
}

/// The [`Service`] produced by [`RequireSessionLayer`].
pub struct RequireSessionService<SD, S> {
    inner: S,
    engine: Arc<LoginEngine<SD>>,
    action: UnauthenticatedAction,
    cors_passthrough: bool,
}

impl<SD, S: Clone> Clone for RequireSessionService<SD, S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            engine: self.engine.clone(),
            action: self.action,
            cors_passthrough: self.cors_passthrough,
        }
    }
}

impl<SD, S> Service<Request> for RequireSessionService<SD, S>
where
    SD: SessionDriver + 'static,
    S: Service<Request, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request) -> Self::Future {
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let engine = self.engine.clone();
        let action = self.action;
        let cors_passthrough = self.cors_passthrough;

        Box::pin(async move {
            if cors_passthrough && is_cors_preflight(req.method(), req.headers()) {
                return inner.call(req).await;
            }

            if req
                .extensions()
                .get::<LoginSession<SD::SessionType>>()
                .is_some()
            {
                return inner.call(req).await;
            }

            if req.extensions().get::<SessionLoadAttempted>().is_none() {
                // SessionLoadAttempted is only inserted by LoadSessionLayer /
                // LoginLayer. Missing it means no loader ran ahead of this gate —
                // a middleware-ordering bug. Without a loader no request can ever
                // carry a session, so LoginOrReject would redirect every request
                // to the authorization server in an endless login loop. Fail
                // closed with 500 instead.
                log::error!(
                    "RequireSessionLayer ran without a session loader ahead of it; \
                     stack a LoadSessionLayer (or LoginLayer) outside this gate"
                );
                let mut resp = http::Response::new(axum_core::body::Body::empty());
                *resp.status_mut() = http::StatusCode::INTERNAL_SERVER_ERROR;
                return Ok(resp.into_response());
            }

            match action {
                UnauthenticatedAction::Reject => {
                    let mut resp = http::Response::new(axum_core::body::Body::empty());
                    *resp.status_mut() = http::StatusCode::UNAUTHORIZED;
                    Ok(resp.into_response())
                }
                UnauthenticatedAction::LoginOrReject => {
                    let (parts, _body) = req.into_parts();
                    let uri = effective_uri(&parts);
                    let resp = engine.redirect_to_login(&parts.headers, &uri).await;
                    Ok(to_response(resp))
                }
            }
        })
    }
}
