use std::collections::{BTreeMap as Map, BTreeSet as Set};
use std::net::IpAddr;

use crate::state::{LocalEndpoint, LocalEndpointSlice, ProtoPort, ServiceTarget, keys};

pub type State = Map<keys::Object, Service>;

pub fn from_state(state: &super::State, disable_nodeports: bool) -> Option<State> {
    if !state.is_ready() {
        return None;
    }

    let mut proxy = Map::new();

    for (key, svc) in state.maps.services.iter() {
        let ServiceTarget::ClusterIPs(ref cluster_ips) = svc.target else {
            continue;
        };

        // A service carrying the `service-proxy-name` label is handled by
        // another proxy, and a service carrying the `headless` label must be
        // treated as headless: leave both alone.
        if svc.service_proxy_name.is_some() || svc.headless {
            continue;
        }

        // Headless-labelled EndpointSlices must not be programmed (the Service
        // is headless); DNS still resolves them separately.
        let internal_slices: Vec<_> = state
            .slices(key, svc.internal_traffic.is_local())
            .into_iter()
            .filter(|s| !s.headless)
            .collect();

        let node_ports = if disable_nodeports {
            vec![]
        } else {
            svc.node_ports.clone()
        };

        let internal_policy_local = svc.internal_traffic.is_local();
        let external_policy_local = svc.external_traffic.is_local();

        // External (NodePort/ExternalIP/LoadBalancer) traffic needs its own
        // chain whenever there are external IPs (their `loadBalancerSourceRanges`
        // are enforced there), or when the external policy differs from the
        // internal one, or when it is `Local`: the latter also carries the
        // local-traffic short-circuit rules and must exist even without any
        // external IP (a bare NodePort Service).
        let needs_ext = !svc.external_ips.is_empty()
            || (!node_ports.is_empty()
                && (external_policy_local || internal_policy_local != external_policy_local));

        let external_slices = if needs_ext && internal_policy_local != external_policy_local {
            Some(
                state
                    .slices(key, external_policy_local)
                    .into_iter()
                    .filter(|s| !s.headless)
                    .collect(),
            )
        } else {
            None // same endpoints as the internal chain
        };

        let service = Service {
            cluster_ips: cluster_ips.clone(),
            external_ips: svc.external_ips.clone(),
            external_allow_list: svc.external_allow_list.clone(),
            ports: svc.ports.clone(),
            node_ports,
            internal_slices,
            external_slices,
            session_affinity: svc.session_affinity.clone(),
            health_check_node_port: svc.health_check_node_port,
            needs_ext_chain: needs_ext,
            external_policy_local,
        };

        proxy.insert(key.clone(), service);
    }

    Some(proxy)
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct Service {
    pub cluster_ips: Set<IpAddr>,
    pub external_ips: Set<IpAddr>,
    pub external_allow_list: Option<Set<String>>,
    pub ports: Vec<(ProtoPort, String)>,
    pub node_ports: Vec<(ProtoPort, String)>,
    pub internal_slices: Vec<LocalEndpointSlice>,
    pub external_slices: Option<Vec<LocalEndpointSlice>>,
    pub session_affinity: crate::state::SessionAffinity,
    /// The Service's `healthCheckNodePort`, if it has one (set by the API server
    /// for `type: LoadBalancer` with `externalTrafficPolicy: Local`).
    pub health_check_node_port: Option<u16>,
    /// Whether external (NodePort/ExternalIP/LoadBalancer) traffic gets its own
    /// chain (see `from_state`).
    pub needs_ext_chain: bool,
    /// Whether the Service's `externalTrafficPolicy` is `Local` (enables the
    /// local-traffic short-circuit rule in the external chain).
    pub external_policy_local: bool,
}
impl Service {
    pub fn external_slices(&self) -> &[LocalEndpointSlice] {
        self.external_slices
            .as_ref()
            .unwrap_or(&self.internal_slices)
    }

    pub fn internal_endpoints(&self) -> impl Iterator<Item = &LocalEndpoint> {
        self.internal_slices
            .iter()
            .flat_map(|slice| slice.endpoints.iter())
    }

    pub fn external_endpoints(&self) -> impl Iterator<Item = &LocalEndpoint> {
        self.external_slices()
            .iter()
            .flat_map(|slice| slice.endpoints.iter())
    }
}
