use base64::prelude::{BASE64_STANDARD, Engine as _};
use cidr::{IpCidr, Ipv4Inet, Ipv6Inet};
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
    "default".into()
}

pub type Key = [u8; 32];
pub fn encode_key(key: &Key) -> String {
    BASE64_STANDARD.encode(key)
}
pub fn decode_key(s: &[u8]) -> eyre::Result<Key> {
    let mut key: Key = [0; 32];
    let len = BASE64_STANDARD.decode_slice(s, key.as_mut_slice())?;
    if len != key.len() {
        return Err(format_err!("wrong decoded length: {len}"));
    }
    Ok(key)
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Node {
    #[serde(default = "default_zone")]
    pub zone: String,
    pub listen_port: Option<u16>,
    pub pubkey: Option<Key>,
    pub endpoint: Option<Endpoint>,
    pub endpoint_from: Option<Map<String, Endpoint>>,
    pub pod_cidrs: Vec<IpCidr>,
}
impl Node {
    pub fn new() -> Self {
        Self {
            zone: default_zone(),
            ..Default::default()
        }
    }

    pub fn if_addr4(&self) -> Option<Ipv4Inet> {
        (self.pod_cidrs.iter())
            .filter_map(|c| match c {
                IpCidr::V4(v) => Some(v),
                _ => None,
            })
            .next()
            .and_then(|c| c.first().next())
    }
    pub fn if_addr6(&self) -> Option<Ipv6Inet> {
        (self.pod_cidrs.iter())
            .filter_map(|c| match c {
                IpCidr::V6(v) => Some(v),
                _ => None,
            })
            .next()
            .and_then(|c| c.first().next())
    }

    pub fn get_endpoint_from(&self, zone: &str, default_port: u16) -> Option<std::net::SocketAddr> {
        (self.endpoint_from.as_ref())
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

    fn value_from(n: &core::Node) -> Option<Self> {
        let anns = n.metadata.annotations.as_ref()?;
        let spec = n.spec.as_ref()?;

        let topo_zone = n.get_zone().cloned().unwrap_or_else(default_zone);

        let first_address = (n.status.as_ref())
            .and_then(|st| st.addresses.as_ref())
            .and_then(|addrs| addrs.first())
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
                anns.iter()
                    .filter_map(|(k, v)| {
                        let k = k.strip_prefix(ANN_ENDPOINT_FROM)?.into();
                        let v = v.parse().ok()?;
                        Some((k, v))
                    })
                    .collect(),
            ),
            pod_cidrs: (spec.pod_cidrs.iter())
                .flatten()
                .filter_map(|cidr| cidr.parse().ok())
                .collect(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
        Ok(Self {
            address: sa.ip(),
            port: Some(sa.port()),
        })
    }
}
