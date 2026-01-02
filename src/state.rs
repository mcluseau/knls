use cidr::IpCidr;
use eyre::format_err;
use itertools::Itertools;
use k8s_openapi::api::{core::v1 as core, discovery::v1 as discovery};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap as Map, BTreeSet as Set};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::{kube_watch, memstore};

pub mod keys;
pub mod proxy;
pub mod wireguard;

#[cfg(test)]
mod tests;

crate::multimap!(
    pub StateMaps {
        services: Service(core::Service) => Service,
        ep_slices: EndpointSlice(discovery::EndpointSlice) => EndpointSlice,
    }
);

pub struct State {
    pub node_name: String,
    pub my_node: memstore::Value<core::Node, Node>,
    pub maps: StateMaps,
}
impl State {
    pub fn new(node_name: String) -> Self {
        Self {
            node_name,
            my_node: memstore::Value::new(Node::from_kube),
            maps: StateMaps::new(),
        }
    }

    pub fn is_ready(&self) -> bool {
        self.my_node.is_ready() && self.maps.is_ready()
    }

    pub fn slices<'a>(
        &'a self,
        service_key: &'a keys::Object,
        local: bool,
    ) -> Box<dyn Iterator<Item = LocalEndpointSlice> + 'a> {
        if local {
            self.local_slices(service_key)
        } else {
            self.zoned_slices(service_key)
        }
    }

    fn local_slices<'a>(
        &'a self,
        service_key: &'a keys::Object,
    ) -> Box<dyn Iterator<Item = LocalEndpointSlice> + 'a> {
        // couldn't use impl in fn endpoints
        //) -> impl Iterator<Item = &'a Endpoint> {
        Box::new(self.service_slices(service_key).filter_map(|slice| {
            LocalEndpointSlice::from_slice(slice, &self.node_name, |ep| {
                ep.is_local(&self.node_name)
            })
        }))
    }

    fn zoned_slices<'a>(
        &'a self,
        service_key: &'a keys::Object,
    ) -> Box<dyn Iterator<Item = LocalEndpointSlice> + 'a> {
        // couldn't use impl in fn endpoints
        //) -> impl Iterator<Item = &'a Endpoint> {
        let my_node = self.my_node.get();
        let has_node = my_node.is_some();
        let zone = my_node.and_then(|n| n.zone.as_ref());

        let iter = self
            .service_slices(service_key)
            .take_while(move |_| has_node)
            .filter_map(move |slice| {
                LocalEndpointSlice::from_slice(slice, &self.node_name, move |ep| match zone {
                    None => true,
                    Some(zone) => ep.is_for_zone(zone),
                })
            });
        Box::new(iter)
    }

    fn service_slices<'a>(
        &'a self,
        service_key: &'a keys::Object,
    ) -> impl Iterator<Item = &'a EndpointSlice> {
        let key_min = keys::EndpointSlice {
            namespace: service_key.namespace.clone(),
            service_name: service_key.name.clone(),
            name: String::new(),
        };

        use std::ops::Bound;

        (self.maps.ep_slices)
            .range((Bound::Included(key_min), Bound::Unbounded))
            .take_while(|(k, _)| k.is_service(service_key))
            .map(|(_, v)| v)
    }

    pub fn ingest(&mut self, event: kube_watch::Event) -> bool {
        use kube_watch::Event::*;
        match event {
            MyNode(e) => {
                self.my_node.ingest(&e);
                true
            }
            _ => self.maps.ingest(event),
        }
    }

    /// See crate::memstore::multimap.ingest_events
    pub async fn ingest_events(
        &mut self,
        rx: &mut crate::kube_watch::EventReceiver,
    ) -> Option<bool> {
        let mut updated = self.ingest(rx.recv().await?);

        while let Ok(e) = rx.try_recv() {
            updated |= self.ingest(e);
        }

        Some(updated)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LocalEndpoint {
    pub node_local: bool,
    pub hostname: Option<String>,
    pub ipv4: Option<Ipv4Addr>,
    pub ipv6: Option<Ipv6Addr>,
}
impl LocalEndpoint {
    fn from_endpoint(ep: &Endpoint, node_name: &String) -> Self {
        Self {
            node_local: ep.node.as_ref() == Some(node_name),
            hostname: ep.hostname.clone(),
            ipv4: ep.ipv4,
            ipv6: ep.ipv6,
        }
    }

    pub fn ip(&self, ipv4: bool) -> Option<IpAddr> {
        if ipv4 {
            self.ipv4.map(IpAddr::V4)
        } else {
            self.ipv6.map(IpAddr::V6)
        }
    }

    pub fn ips(&self) -> impl Iterator<Item = IpAddr> {
        let ipv4 = self.ipv4.map(IpAddr::V4);
        let ipv6 = self.ipv6.map(IpAddr::V6);
        ipv4.into_iter().chain(ipv6)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LocalEndpointSlice {
    pub target_ports: Map<String, u16>,
    pub endpoints: Vec<LocalEndpoint>,
}
impl LocalEndpointSlice {
    fn from_slice<F>(slice: &EndpointSlice, node_name: &String, mut filter: F) -> Option<Self>
    where
        F: FnMut(&Endpoint) -> bool,
    {
        let endpoints = slice
            .endpoints
            .iter()
            .filter(|ep| filter(ep))
            .collect::<Vec<_>>();

        if endpoints.is_empty() {
            return None;
        }

        Some(Self {
            target_ports: slice.target_ports.clone(),
            endpoints: endpoints
                .into_iter()
                .map(|ep| LocalEndpoint::from_endpoint(ep, node_name))
                .collect(),
        })
    }

    pub fn ips(&self) -> impl Iterator<Item = IpAddr> {
        self.endpoints.iter().flat_map(|ep| ep.ips())
    }

    pub fn ipsv4(&self) -> impl Iterator<Item = Ipv4Addr> {
        self.endpoints.iter().filter_map(|ep| ep.ipv4)
    }
    pub fn ipsv6(&self) -> impl Iterator<Item = Ipv6Addr> {
        self.endpoints.iter().filter_map(|ep| ep.ipv6)
    }
}

trait Labelled {
    fn get_label(&self, label_key: &str) -> Option<&String>;

    fn get_zone(&self) -> Option<&String> {
        self.get_label("topology.kubernetes.io/zone")
    }
}
impl Labelled for core::Node {
    fn get_label(&self, label_key: &str) -> Option<&String> {
        self.metadata
            .labels
            .as_ref()
            .and_then(|labels| labels.get(label_key))
    }
}

#[derive(Clone, Debug)]
pub struct Node {
    pub ips: Vec<IpAddr>,
    pub zone: Option<String>,
    pub pod_cidrs: Vec<String>,
    pub labels: Map<String, String>,
}
impl Node {
    fn from_kube(n: &core::Node) -> Self {
        Self {
            ips: (n.status.as_ref())
                .and_then(|s| s.addresses.as_ref())
                .map(|addrs| {
                    addrs
                        .iter()
                        .filter_map(|addr| addr.address.parse().ok())
                        .collect()
                })
                .unwrap_or_default(),
            zone: n.get_zone().cloned(),
            pod_cidrs: (n.spec.as_ref())
                .and_then(|s| s.pod_cidrs.clone())
                .unwrap_or_default(),
            labels: n.metadata.labels.clone().unwrap_or_default(),
        }
    }
}

#[derive(Serialize, Clone)]
pub enum ServiceTarget {
    None,
    Headless,
    ClusterIPs(Set<IpAddr>),
    Name(String),
}

#[derive(Debug, Clone, Serialize)]
pub enum SessionAffinity {
    None,
    ClientIP { timeout: i32 },
}

#[derive(Serialize, Clone)]
pub struct Service {
    pub is_load_balancer: bool,
    pub target: ServiceTarget,
    pub ports: Vec<(ProtoPort, String)>,
    pub node_ports: Vec<(ProtoPort, String)>,
    pub internal_traffic: TrafficPolicy,
    pub external_traffic: TrafficPolicy,
    pub external_ips: Set<IpAddr>,
    pub session_affinity: SessionAffinity,
    pub external_allow_list: Option<Set<String>>,
}

impl memstore::KeyValueFrom<core::Service> for Service {
    type Key = keys::Object;

    fn key_from(svc: &core::Service) -> Option<Self::Key> {
        keys::Object::try_from(&svc.metadata).ok()
    }

    fn value_from(svc: &core::Service) -> Option<Self> {
        let Some(ref spec) = svc.spec else {
            return Some(Self {
                is_load_balancer: false,
                target: ServiceTarget::None,
                ports: Vec::new(),
                node_ports: Vec::new(),
                internal_traffic: Default::default(),
                external_traffic: Default::default(),
                external_ips: Set::new(),
                session_affinity: SessionAffinity::None,
                external_allow_list: None,
            });
        };

        let target = match spec.type_.as_deref() {
            None => ServiceTarget::None,
            Some("ExternalName") => match &spec.external_name {
                None => ServiceTarget::None,
                Some(name) => ServiceTarget::Name(format!("{name}.")),
            },
            Some("ClusterIP") | Some("NodePort") | Some("LoadBalancer") => {
                match &spec.cluster_ips {
                    None => ServiceTarget::None,
                    Some(ips) => {
                        if ips.iter().map(|s| s.as_str()).contains(&"None") {
                            ServiceTarget::Headless
                        } else {
                            ServiceTarget::ClusterIPs(
                                ips.iter().filter_map(|ip| ip.parse().ok()).collect(),
                            )
                        }
                    }
                }
            }
            _ => ServiceTarget::None,
        };

        let spec_ports = || spec.ports.iter().flatten();

        let ports = spec_ports()
            .filter_map(|p| {
                Some((
                    ProtoPort::from_service_port(p)?,
                    p.name.clone().unwrap_or_default(),
                ))
            })
            .collect();
        let node_ports = spec_ports()
            .filter_map(|p| {
                Some((
                    ProtoPort::from_service_node_port(p)?,
                    p.name.clone().unwrap_or_default(),
                ))
            })
            .collect();

        let session_affinity = match spec.session_affinity.as_deref() {
            Some("ClientIP") => {
                match (spec.session_affinity_config.as_ref())
                    .and_then(|ac| ac.client_ip.as_ref())
                    .and_then(|ac| ac.timeout_seconds)
                {
                    None => SessionAffinity::None,
                    Some(timeout) => SessionAffinity::ClientIP { timeout },
                }
            }
            _ => SessionAffinity::None,
        };

        let external_allow_list = (spec.load_balancer_source_ranges.as_ref().cloned()).map(|ips| {
            ips.into_iter()
                .filter(|ip| ip.parse::<IpCidr>().is_ok())
                .collect()
        });

        Some(Self {
            is_load_balancer: spec.type_.as_deref() == Some("LoadBalancer"),
            target,
            ports,
            node_ports,
            internal_traffic: (&spec.internal_traffic_policy).into(),
            external_traffic: (&spec.external_traffic_policy).into(),
            external_ips: parse_ips(&spec.external_ips),
            session_affinity,
            external_allow_list,
        })
    }
}

fn parse_ips(ips: &Option<Vec<String>>) -> Set<IpAddr> {
    ips.iter()
        .flatten()
        .filter_map(|s| s.parse().ok())
        .collect()
}

#[derive(Default, PartialEq, Eq, Serialize, Clone)]
pub enum TrafficPolicy {
    #[default]
    Cluster,
    Local,
}

impl TrafficPolicy {
    pub fn is_local(&self) -> bool {
        *self == TrafficPolicy::Local
    }
}

// this is what we get from the API
impl From<&Option<String>> for TrafficPolicy {
    fn from(v: &Option<String>) -> Self {
        use TrafficPolicy::*;
        match v.as_deref() {
            Some("Local") => Local,
            _ => Cluster,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum Protocol {
    TCP,
    UDP,
    SCTP,
}

impl TryFrom<&Option<String>> for Protocol {
    type Error = eyre::Error;
    fn try_from(v: &Option<String>) -> Result<Protocol, eyre::Error> {
        match v.as_deref() {
            None | Some("TCP") => Ok(Protocol::TCP),
            Some("UDP") => Ok(Protocol::UDP),
            Some("SCTP") => Ok(Protocol::SCTP),
            Some(v) => Err(format_err!("invalid protocol: {v}")),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum ProtoPort {
    TCP(u16),
    UDP(u16),
    SCTP(u16),
}
impl ProtoPort {
    fn from_service_port(sp: &core::ServicePort) -> Option<Self> {
        Self::from_protocol_port(sp.protocol.as_deref(), sp.port)
    }
    fn from_service_node_port(sp: &core::ServicePort) -> Option<Self> {
        Self::from_protocol_port(sp.protocol.as_deref(), sp.node_port?)
    }

    fn from_protocol_port(protocol: Option<&str>, port: i32) -> Option<Self> {
        match protocol.unwrap_or("TCP") {
            "TCP" => Some(ProtoPort::TCP(port as u16)),
            "UDP" => Some(ProtoPort::UDP(port as u16)),
            "SCTP" => Some(ProtoPort::SCTP(port as u16)),
            _ => None,
        }
    }

    pub fn protocol_port(&self) -> (Protocol, u16) {
        match self {
            ProtoPort::TCP(port) => (Protocol::TCP, *port),
            ProtoPort::UDP(port) => (Protocol::UDP, *port),
            ProtoPort::SCTP(port) => (Protocol::SCTP, *port),
        }
    }

    pub fn port(&self, protocol: &Protocol) -> Option<u16> {
        match (protocol, self) {
            (Protocol::TCP, ProtoPort::TCP(port)) => Some(*port),
            (Protocol::UDP, ProtoPort::UDP(port)) => Some(*port),
            (Protocol::SCTP, ProtoPort::SCTP(port)) => Some(*port),
            _ => None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EndpointSlice {
    pub target_ports: Map<String, u16>,
    pub endpoints: Set<Endpoint>,
}
impl memstore::KeyValueFrom<discovery::EndpointSlice> for EndpointSlice {
    type Key = keys::EndpointSlice;

    fn key_from(eps: &discovery::EndpointSlice) -> Option<Self::Key> {
        Some(Self::Key {
            namespace: eps.metadata.namespace.clone()?,
            service_name: eps
                .metadata
                .labels
                .as_ref()?
                .get("kubernetes.io/service-name")?
                .clone(),
            name: eps.metadata.name.clone()?,
        })
    }

    fn value_from(eps: &discovery::EndpointSlice) -> Option<Self> {
        Some(Self {
            target_ports: (eps.ports.iter().flatten())
                .filter_map(|p| {
                    let name = p.name.clone().unwrap_or_default();
                    Some((name, p.port? as u16))
                })
                .collect(),

            endpoints: Endpoint::from_slice_endpoints(&eps.endpoints).collect(),
        })
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Clone)]
pub struct Endpoint {
    ipv4: Option<Ipv4Addr>,
    ipv6: Option<Ipv6Addr>,
    pub hostname: Option<String>,
    node: Option<String>,
    for_zones: Option<Vec<String>>,
}
impl Endpoint {
    fn is_local(&self, node: &String) -> bool {
        self.node.as_ref() == Some(node)
    }
    fn is_for_zone(&self, zone: &String) -> bool {
        match &self.for_zones {
            None => true,
            Some(zones) => zones.contains(zone),
        }
    }

    pub fn ips(&self) -> impl Iterator<Item = IpAddr> + use<> {
        let ipv4 = self.ipv4.map(IpAddr::V4);
        let ipv6 = self.ipv6.map(IpAddr::V6);
        ipv4.into_iter().chain(ipv6)
    }

    fn from_slice_endpoints(endpoints: &[discovery::Endpoint]) -> impl Iterator<Item = Endpoint> {
        endpoints.iter().map(Self::from_slice_endpoint)
    }

    fn from_slice_endpoint(endpoint: &discovery::Endpoint) -> Endpoint {
        let for_zones = (endpoint.hints.as_ref())
            .and_then(|hints| hints.for_zones.as_ref())
            .map(|zones| zones.iter().map(|z| z.name.clone()).collect());

        let mut ipv4 = None;
        let mut ipv6 = None;

        for ip in &endpoint.addresses {
            let Ok(ip) = ip.parse() else {
                continue;
            };
            match ip {
                IpAddr::V4(ip) if ipv4.is_none() => ipv4 = Some(ip),
                IpAddr::V6(ip) if ipv6.is_none() => ipv6 = Some(ip),
                _ => continue,
            }
            if ipv4.is_some() && ipv6.is_some() {
                break;
            }
        }

        Self {
            ipv4,
            ipv6,
            hostname: endpoint.hostname.clone(),
            node: endpoint.node_name.clone(),
            for_zones: for_zones.clone(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Namespace {
    pub labels: Map<String, String>,
}
impl memstore::KeyValueFrom<core::Namespace> for Namespace {
    type Key = String;

    fn key_from(ns: &core::Namespace) -> Option<Self::Key> {
        ns.metadata.name.clone()
    }

    fn value_from(ns: &core::Namespace) -> Option<Self> {
        Some(Self {
            labels: ns.metadata.labels.clone().unwrap_or_default(),
        })
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Pod {
    pub labels: Map<String, String>,
    pub node: String,
    pub ipsv4: Vec<Ipv4Addr>,
    pub ipsv6: Vec<Ipv6Addr>,
    pub host_network: bool,
}
impl memstore::KeyValueFrom<core::Pod> for Pod {
    type Key = keys::Object;

    fn key_from(pod: &core::Pod) -> Option<Self::Key> {
        keys::Object::try_from(&pod.metadata).ok()
    }

    fn value_from(pod: &core::Pod) -> Option<Self> {
        let spec = pod.spec.as_ref()?;
        let node = spec.node_name.clone()?;

        let ips = pod.status.as_ref()?.pod_ips.as_ref()?;
        let mut ipsv4 = Vec::with_capacity(ips.len());
        let mut ipsv6 = Vec::with_capacity(ips.len());

        for ip in (ips.iter()).filter_map(|ip| ip.ip.parse::<IpAddr>().ok()) {
            match ip {
                IpAddr::V4(ip) => ipsv4.push(ip),
                IpAddr::V6(ip) => ipsv6.push(ip),
            }
        }

        ipsv4.shrink_to_fit();
        ipsv6.shrink_to_fit();

        Some(Self {
            labels: pod.metadata.labels.clone().unwrap_or_default(),
            node,
            ipsv4,
            ipsv6,
            host_network: spec.host_network.unwrap_or(false),
        })
    }
}
