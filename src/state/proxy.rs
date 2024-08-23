use std::collections::{BTreeMap as Map, BTreeSet as Set};
use std::net::IpAddr;

use crate::state::{keys, LocalEndpoint, LocalEndpointSlice, ProtoPort, ServiceTarget};

pub fn from_state(state: &super::State, disable_nodeports: bool) -> Option<State> {
    if !(state.services.is_ready() && state.ep_slices.is_ready()) {
        return None;
    }

    let mut proxy = Map::new();

    for (key, svc) in state.services.iter() {
        let ServiceTarget::ClusterIPs(ref cluster_ips) = svc.target else {
            continue;
        };

        let internal_slices = state
            .slices(&key, svc.internal_traffic.is_local())
            .collect();

        let external_slices = if !svc.external_ips.is_empty()
            && svc.internal_traffic.is_local() != svc.external_traffic.is_local()
        {
            Some(
                state
                    .slices(&key, svc.external_traffic.is_local())
                    .collect(),
            )
        } else {
            None // same as internal_endpoints
        };

        let node_ports = if disable_nodeports {
            vec![]
        } else {
            svc.node_ports.clone()
        };

        let service = Service {
            cluster_ips: cluster_ips.clone(),
            external_ips: svc.external_ips.clone(),
            ports: svc.ports.clone(),
            node_ports,
            internal_slices,
            external_slices,
            session_affinity: svc.session_affinity.clone(),
        };

        proxy.insert(key.clone(), service);
    }

    Some(proxy)
}

pub type State = Map<keys::Object, Service>;

#[derive(Clone, Debug, serde::Serialize)]
pub struct Service {
    pub cluster_ips: Set<IpAddr>,
    pub external_ips: Set<IpAddr>,
    pub ports: Vec<(ProtoPort, String)>,
    pub node_ports: Vec<(ProtoPort, String)>,
    pub internal_slices: Vec<LocalEndpointSlice>,
    pub external_slices: Option<Vec<LocalEndpointSlice>>,
    pub session_affinity: crate::state::SessionAffinity,
}
impl Service {
    pub fn external_slices(&self) -> &Vec<LocalEndpointSlice> {
        self.external_slices
            .as_ref()
            .unwrap_or(&self.internal_slices)
    }

    pub fn internal_endpoints<'t>(&'t self) -> impl Iterator<Item = &'t LocalEndpoint> {
        self.internal_slices
            .iter()
            .map(|slice| slice.endpoints.iter())
            .flatten()
    }

    pub fn external_endpoints<'t>(&'t self) -> impl Iterator<Item = &'t LocalEndpoint> {
        self.external_slices()
            .iter()
            .map(|slice| slice.endpoints.iter())
            .flatten()
    }
}
