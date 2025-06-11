use eyre::Result;
use std::sync::Arc;

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct Config {
    /// Namespace to watch instead of the whole cluster.
    pub namespace: Option<String>,

    /// Kubernetes API server URL
    pub cluster_url: Option<String>,

    /// Kubernetes watch events buffer size
    #[serde(default = "default_event_buffer")]
    pub event_buffer: usize,

    /// Proxy service, responsible for handling v1/Service semantics on the node.
    pub proxy: Option<Proxy>,

    /// Connectivity service, responsible for allowing pods to communicate across the cluster.
    pub connectivity: Option<Connectivity>,

    /// DNS service, authoritative on the cluster domain.
    pub dns: Option<DNS>,
}
fn default_event_buffer() -> usize {
    100
}

impl Config {
    /// parse the cluster_url
    pub fn cluster_url(&self) -> Result<Option<http::Uri>> {
        match self.cluster_url {
            None => Ok(None),
            Some(ref v) => Ok(Some(v.parse()?)),
        }
    }
}

use knls::{connectivity, dns, proxy};

knls::service!("proxy" Proxy {
    "nftables" Nftables: proxy::nftables::Config => proxy::nftables::watch,
});

knls::service!("connectivity" Connectivity {
    "wireguard" Wireguard: connectivity::wireguard::Config => connectivity::wireguard::watch,
});

knls::service!("dns" DNS {
    "internal" Internal: dns::internal::Config => dns::internal::watch,
});
