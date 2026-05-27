//! Tower middleware that handles `/callback` and `/logout` only.

use std::{pin::Pin, sync::Arc};

use axum_core::{extract::Request, response::Response};
use huskarl_login::{SessionDriver, engine::LoginEngine};
use tower::{Layer, Service};

use super::layer::{effective_uri, to_response};

/// Layer that intercepts the configured callback and logout paths and passes
/// every other request through unchanged.
///
/// Stack this outside any session-loading or auth-gating layers so the
/// callback / logout responses are not themselves gated.
pub struct LoginRoutesLayer<SD> {
    engine: Arc<LoginEngine<SD>>,
}

impl<SD> LoginRoutesLayer<SD> {
    pub(super) fn new(engine: Arc<LoginEngine<SD>>) -> Self {
        Self { engine }
    }
}

impl<SD> Clone for LoginRoutesLayer<SD> {
    fn clone(&self) -> Self {
        Self {
            engine: self.engine.clone(),
        }
    }
}

impl<SD, S> Layer<S> for LoginRoutesLayer<SD> {
    type Service = LoginRoutesService<SD, S>;

    fn layer(&self, inner: S) -> Self::Service {
        LoginRoutesService {
            inner,
            engine: self.engine.clone(),
        }
    }
}

/// The [`Service`] produced by [`LoginRoutesLayer`].
pub struct LoginRoutesService<SD, S> {
    inner: S,
    engine: Arc<LoginEngine<SD>>,
}

impl<SD, S: Clone> Clone for LoginRoutesService<SD, S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            engine: self.engine.clone(),
        }
    }
}

impl<SD, S> Service<Request> for LoginRoutesService<SD, S>
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

        Box::pin(async move {
            let (parts, body) = req.into_parts();
            let uri = effective_uri(&parts);

            if let Some(resp) = engine
                .try_handle_login_route(&parts.method, &parts.headers, &uri)
                .await
            {
                return Ok(to_response(resp));
            }

            let req = Request::from_parts(parts, body);
            inner.call(req).await
        })
    }
}
