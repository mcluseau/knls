//! kube-proxy-compatible admin endpoints.
//!
//! Kubernetes tooling and the e2e tests query the node's proxy on
//! `127.0.0.1:10249` (`/proxyMode`: the proxy backend — reporting `nftables`
//! rather than `iptables` is what the iptables-specific tests key off to decide
//! whether they apply) and on `127.0.0.1:10256` (`/healthz` and `/livez`: the
//! proxy's own health).

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::header::HeaderValue;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use log::{debug, warn};
use tokio::net::TcpListener;

/// kube-proxy's default status port (`ProxyStatusPort`).
pub const STATUS_PORT: u16 = 10249;
/// kube-proxy's default healthz port (`ProxyHealthzPort`).
pub const HEALTHZ_PORT: u16 = 10256;

/// The backend reported by `/proxyMode`.
const PROXY_MODE: &str = "nftables";

/// The proxy's health as served on `127.0.0.1:10256`.
pub struct Health {
    /// The last time the proxy successfully updated its dataplane, in Unix
    /// seconds.
    last_updated: AtomicU64,
}

impl Health {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            last_updated: AtomicU64::new(now()),
        })
    }

    /// Records that the proxy just successfully pushed a dataplane update.
    pub fn updated(&self) {
        self.last_updated.store(now(), Ordering::Relaxed);
    }

    fn last_updated(&self) -> u64 {
        self.last_updated.load(Ordering::Relaxed)
    }
}

/// Serves the status endpoint on `127.0.0.1:10249` until the process exits.
pub async fn serve() {
    let listener = bind(SocketAddr::from(([127, 0, 0, 1], STATUS_PORT)), "metrics").await;
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };

        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service_fn(handle))
                .await
            {
                debug!("metrics: connection error: {e}");
            }
        });
    }
}

/// Serves the proxy health endpoint on `127.0.0.1:10256` until the process
/// exits.
pub async fn serve_healthz(health: Arc<Health>) {
    let listener = bind(SocketAddr::from(([127, 0, 0, 1], HEALTHZ_PORT)), "healthz").await;
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };

        let health = health.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let service = service_fn(move |req| {
                let health = health.clone();
                async move { handle_healthz(req, &health).await }
            });
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await
            {
                debug!("healthz: connection error: {e}");
            }
        });
    }
}

/// Binds `addr`, retrying so a transient failure (or a lingering previous
/// instance) does not permanently disable the endpoint.
async fn bind(addr: SocketAddr, who: &str) -> TcpListener {
    loop {
        match TcpListener::bind(addr).await {
            Ok(listener) => {
                debug!("{who}: serving on {addr}");
                return listener;
            }
            Err(e) => {
                warn!("{who}: failed to bind {addr}: {e}, retrying");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
}

async fn handle(req: Request<hyper::body::Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let (status, body) = match req.uri().path() {
        "/proxyMode" => (StatusCode::OK, format!("{PROXY_MODE}\n")),
        _ => (StatusCode::NOT_FOUND, String::new()),
    };

    let mut resp = Response::new(Full::new(Bytes::from(body)));
    *resp.status_mut() = status;
    Ok(resp)
}

/// The proxy's own `/healthz` and `/livez`. `lastUpdated` is the last time the
/// proxy successfully updated its dataplane (kube-proxy reports the last sync);
/// `currentTime` is the request time.
async fn handle_healthz(
    req: Request<hyper::body::Incoming>,
    health: &Health,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let (status, body) = match req.uri().path() {
        "/healthz" | "/livez" => (
            StatusCode::OK,
            format!(
                "{{\"lastUpdated\":{},\"currentTime\":{},\"healthy\":true}}\n",
                health.last_updated(),
                now(),
            ),
        ),
        _ => (StatusCode::NOT_FOUND, String::new()),
    };

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

/// The current time in Unix seconds.
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
