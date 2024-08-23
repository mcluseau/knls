use base64::prelude::{Engine as _, BASE64_STANDARD};
use defguard_wireguard_rs::net::IpAddrMask;
use eyre::format_err;
use k8s_openapi::api::core::v1 as core;
use log::warn;
use std::collections::BTreeMap as Map;
use std::net::{IpAddr, SocketAddr};

use super::Labelled;
use crate::memstore;

pub const ANN_LISTEN_PORT: &str = "kwg-listen-port";
pub const ANN_PUBKEY: &str = "kwg-pubkey";
pub const ANN_NET: &str = "kwg-net";
pub const ANN_ENDPOINT: &str = "kwg-endpoint";
pub const ANN_ENDPOINT_FROM: &str = "kwg-endpoint-from/";

pub const ZONE_LABEL: &str = "topology.kubernetes.io/zone";

fn default_zone() -> String {
    "default".to_string()
}

pub type Key = [u8; 32];
pub fn encode_key(key: &Key) -> String {
    BASE64_STANDARD.encode(&key)
}
pub fn decode_key(s: &[u8]) -> eyre::Result<Key> {
    let mut key: Key = [0; 32];
    let len = BASE64_STANDARD.decode_slice(s, key.as_mut_slice())?;
    if len != key.len() {
        return Err(format_err!("wrong decoded length: {len}"));
    }
    Ok(key)
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct Node {
    pub zone: String,
    pub listen_port: Option<u16>,
    pub pubkey: Option<Key>,
    pub endpoint: Option<Endpoint>,
    pub endpoint_from: Option<Map<String, Endpoint>>,
    pub pod_cidrs: Vec<IpAddrMask>,
}
impl Node {
    pub fn new() -> Self {
        Self {
            zone: default_zone(),
            listen_port: None,
            pubkey: None,
            endpoint: None,
            endpoint_from: None,
            pod_cidrs: Vec::new(),
        }
    }

    pub fn if_addr(&self) -> Option<String> {
        // TODO first address in range
        self.pod_cidrs.iter().next().map(|c| c.to_string())
    }

    pub fn get_endpoint_from(
        &self,
        zone: &String,
        default_port: u16,
    ) -> Option<std::net::SocketAddr> {
        self.endpoint_from
            .as_ref()
            .and_then(|eps| eps.get(zone))
            .or(self.endpoint.as_ref())
            .map(|ep| ep.to_addr_port(default_port))
    }
}
impl memstore::KeyValueFrom<core::Node> for Node {
    type Key = String;

    fn key_from(n: &core::Node) -> Option<Self::Key> {
        n.metadata.name.clone()
    }

    fn value_from(n: core::Node) -> Option<Self> {
        let anns = n.metadata.annotations.as_ref()?;

        let topo_zone = n.get_zone().cloned().unwrap_or_else(default_zone);

        let first_address = n
            .status
            .and_then(|st| st.addresses)
            .and_then(|addrs| addrs.iter().next().cloned())
            .and_then(|addr| addr.address.parse().ok());

        let listen_port = anns.get(ANN_LISTEN_PORT).and_then(|p| p.parse().ok());

        Some(Self {
            zone: anns.get(ANN_NET).cloned().unwrap_or(topo_zone),
            listen_port,
            pubkey: anns.get(ANN_PUBKEY).and_then(|s| {
                decode_key(s.as_bytes())
                    .inspect_err(|e| warn!("invalid key: {s:?}: {e}"))
                    .ok()
            }),
            endpoint: match anns.get(ANN_ENDPOINT) {
                Some(s) => s.parse().ok(),
                None => Some(Endpoint {
                    address: first_address?,
                    port: listen_port,
                }),
            },
            endpoint_from: Some(
                anns.into_iter()
                    .filter_map(|(k, v)| {
                        let k = k.strip_prefix(ANN_ENDPOINT_FROM)?.to_string();
                        let v = v.parse().ok()?;
                        Some((k, v))
                    })
                    .collect(),
            ),
            pod_cidrs: n
                .spec
                .and_then(|spec| spec.pod_cidrs)
                .map(|cidrs| cidrs.iter().filter_map(|s| s.parse().ok()).collect())
                .unwrap_or_default(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct Endpoint {
    pub address: IpAddr,
    pub port: Option<u16>,
}
impl Endpoint {
    pub fn to_addr_port(&self, default_port: u16) -> SocketAddr {
        SocketAddr::new(self.address, self.port.unwrap_or(default_port))
    }
}
impl std::str::FromStr for Endpoint {
    type Err = std::net::AddrParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let Ok(sa) = SocketAddr::from_str(s) else {
            return Ok(Self {
                address: IpAddr::from_str(s)?,
                port: None,
            });
        };
        return Ok(Self {
            address: sa.ip(),
            port: Some(sa.port()),
        });
    }
}
