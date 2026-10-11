//! Per-Service health-check NodePort responders, as kube-proxy publishes them.
//!
//! For a `type: LoadBalancer` Service with `externalTrafficPolicy: Local` the
//! API server allocates a `healthCheckNodePort`. The node's proxy must serve
//! HTTP there — 200 when at least one Ready endpoint is local to this node, 503
//! otherwise — so the load balancer knows whether this node can serve the
//! Service. (The node may still serve the NodePort with only terminating
//! endpoints; the health check deliberately reports 503 in that case.)
//!
//! Every Service gets one listener task. Shutting a task down is done by
//! dropping the [`oneshot::Sender`] kept in [`HealthChecks`] (when the Service
//! disappears, loses its health-check port, or its port changes).

use std::collections::BTreeMap as Map;
use std::convert::Infallible;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::header::HeaderValue;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use log::debug;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

use crate::state::keys;

/// The set of health-check listeners, kept in sync with the proxy state.
#[derive(Default)]
pub struct HealthChecks {
    services: Map<keys::Object, Instance>,
}

struct Instance {
    port: u16,
    /// The number of Ready node-local endpoints, read by the request handler.
    ready: Arc<AtomicU16>,
    /// Dropping this stops the listener task.
    _shutdown: oneshot::Sender<()>,
}

impl HealthChecks {
    pub fn new() -> Self {
        Self::default()
    }

    /// Reconciles the listeners against `services` (`(key, healthCheckNodePort,
    /// ready local endpoints)`). Listeners for Services that disappeared or
    /// whose port changed are shut down; new ones are spawned; the others just
    /// get their endpoint count updated.
    pub fn update(&mut self, services: impl IntoIterator<Item = (keys::Object, u16, u16)>) {
        let desired: Map<_, _> = services.into_iter().map(|(k, p, r)| (k, (p, r))).collect();

        self.services.retain(|key, instance| {
            desired
                .get(key)
                .is_some_and(|&(port, _)| port == instance.port)
        });

        for (key, &(port, ready)) in &desired {
            match self.services.get_mut(key) {
                Some(instance) => instance.ready.store(ready, Ordering::Relaxed),
                None => {
                    let ready = Arc::new(AtomicU16::new(ready));
                    let (shutdown, rx) = oneshot::channel();
                    tokio::spawn(serve(port, ready.clone(), rx));
                    self.services.insert(
                        key.clone(),
                        Instance {
                            port,
                            ready,
                            _shutdown: shutdown,
                        },
                    );
                }
            }
        }
    }
}

/// Serves the health-check port until the shutdown sender is dropped.
///
/// The port may still be bound by a previous owner (e.g. when a Service's
/// policy changes and its port is reallocated), so binding is retried every
/// second, giving up only on shutdown.
async fn serve(port: u16, ready: Arc<AtomicU16>, mut shutdown: oneshot::Receiver<()>) {
    let addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, port));
    let listener = loop {
        match TcpListener::bind(addr).await {
            Ok(listener) => break listener,
            Err(e) => {
                debug!("healthcheck: failed to bind {addr}: {e}, retrying");
                tokio::select! {
                    _ = &mut shutdown => return,
                    _ = tokio::time::sleep(Duration::from_secs(1)) => {}
                }
            }
        }
    };

    loop {
        tokio::select! {
            _ = &mut shutdown => return,
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else {
                    continue;
                };

                let io = TokioIo::new(stream);
                let ready = ready.clone();
                tokio::spawn(async move {
                    let service = service_fn(move |req| {
                        let ready = ready.clone();
                        async move { handle(req, &ready) }
                    });
                    if let Err(e) = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, service)
                        .await
                    {
                        debug!("healthcheck: connection error: {e}");
                    }
                });
            }
        }
    }
}

/// The health-check response status: healthy iff there is at least one Ready
/// local endpoint (kube-proxy reports 503 for a node with none).
fn status_for(count: u16) -> StatusCode {
    if count != 0 {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

/// Answers any request with the current health status, as kube-proxy does.
fn handle(
    _req: Request<hyper::body::Incoming>,
    ready: &AtomicU16,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let count = ready.load(Ordering::Relaxed);
    let status = status_for(count);

    let body = format!("{{\"localEndpoints\":{count},\"serviceProxyHealthy\":true}}\n");
    let mut resp = Response::new(Full::new(Bytes::from(body)));
    *resp.status_mut() = status;
    resp.headers_mut()
        .insert("content-type", HeaderValue::from_static("application/json"));
    resp.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_is_503_without_ready_endpoints() {
        assert_eq!(status_for(0), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(status_for(1), StatusCode::OK);
    }
}
