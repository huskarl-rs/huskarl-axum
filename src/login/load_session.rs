//! Tower middleware that loads (and persists) the session if a cookie is present.
//!
//! On absence, the inner handler runs without a session in scope — no
//! redirect. To gate a route subtree on the presence of a session, stack a
//! [`RequireSessionLayer`](super::RequireSessionLayer) inside.

use std::{pin::Pin, sync::Arc};

use axum_core::{extract::Request, response::Response};
use huskarl_login::{
    PersistFailurePolicy, SessionDriver,
    engine::{LoginEngine, is_cors_preflight},
};
use tower::{Layer, Service};

use super::layer::{AnonymousBehavior, load_session_and_serve};

/// Request-extension marker set by [`LoadSessionLayer`] (and the bundled
/// [`LoginLayer`](super::LoginLayer)) once a session load has been attempted,
/// whether or not a session was found.
///
/// [`RequireSessionLayer`](super::RequireSessionLayer) checks for this marker
/// and fails closed with `500 Internal Server Error` when it is missing:
/// without a loader ahead of the gate no request can ever carry a session, so
/// the gate would otherwise redirect every request to the authorization
/// server in an endless login loop. Custom middleware that loads sessions
/// itself and inserts [`LoginSession`](super::LoginSession) directly should
/// insert this marker too.
#[derive(Debug, Clone, Copy)]
pub struct SessionLoadAttempted;

/// Tower [`Layer`] that loads (and persists) the session when a
/// session cookie is present; never redirects on absence.
///
/// One of the layers produced by `LoginLayer::load_session()`. Stack a
/// `RequireSessionLayer` inside it to gate access; public handlers see the
/// session via `Option<LoginSession<S>>`.
pub struct LoadSessionLayer<SD> {
    engine: Arc<LoginEngine<SD>>,
    persist_failure_policy: Arc<dyn PersistFailurePolicy>,
}

impl<SD> LoadSessionLayer<SD> {
    pub(super) fn new(
        engine: Arc<LoginEngine<SD>>,
        persist_failure_policy: Arc<dyn PersistFailurePolicy>,
    ) -> Self {
        Self {
            engine,
            persist_failure_policy,
        }
    }
}

impl<SD> Clone for LoadSessionLayer<SD> {
    fn clone(&self) -> Self {
        Self {
            engine: self.engine.clone(),
            persist_failure_policy: self.persist_failure_policy.clone(),
        }
    }
}

impl<SD, S> Layer<S> for LoadSessionLayer<SD> {
    type Service = LoadSessionService<SD, S>;

    fn layer(&self, inner: S) -> Self::Service {
        LoadSessionService {
            inner,
            engine: self.engine.clone(),
            persist_failure_policy: self.persist_failure_policy.clone(),
        }
    }
}

/// The [`Service`] produced by [`LoadSessionLayer`].
pub struct LoadSessionService<SD, S> {
    inner: S,
    engine: Arc<LoginEngine<SD>>,
    persist_failure_policy: Arc<dyn PersistFailurePolicy>,
}

impl<SD, S: Clone> Clone for LoadSessionService<SD, S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            engine: self.engine.clone(),
            persist_failure_policy: self.persist_failure_policy.clone(),
        }
    }
}

impl<SD, S> Service<Request> for LoadSessionService<SD, S>
where
    SD: SessionDriver + 'static,
    // `PendingPersist::commit` on the owed save requires an owned session.
    SD::SessionType: Clone,
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
        let persist_failure_policy = self.persist_failure_policy.clone();

        Box::pin(async move {
            if is_cors_preflight(req.method(), req.headers()) {
                return inner.call(req).await;
            }

            load_session_and_serve(
                &engine,
                persist_failure_policy.as_ref(),
                AnonymousBehavior::PassThrough,
                req,
                &mut inner,
            )
            .await
        })
    }
}
