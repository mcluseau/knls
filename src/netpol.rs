pub mod nftables;

use crate::{memstore::KeyValueFrom, state::keys};

use k8s_openapi::{
    api::networking::v1::{
        NetworkPolicy, NetworkPolicyEgressRule as EgressRule,
        NetworkPolicyIngressRule as IngressRule,
    },
    apimachinery::pkg::apis::meta::v1::LabelSelector,
};

#[derive(Clone)]
pub struct Policy {
    namespace: String,
    is_ingress: bool,
    is_egress: bool,
    pod_selector: LabelSelector,
    ingress: Vec<IngressRule>,
    egress: Vec<EgressRule>,
}

impl KeyValueFrom<NetworkPolicy> for Policy {
    type Key = keys::Object;

    fn key_from(v: &NetworkPolicy) -> Option<Self::Key> {
        keys::Object::try_from(&v.metadata).ok()
    }

    fn value_from(v: &NetworkPolicy) -> Option<Self> {
        let spec = v.spec.as_ref()?;
        Some(Self {
            namespace: v.metadata.namespace.clone()?,
            is_ingress: match spec.policy_types {
                Some(ref v) => v.iter().any(|v| v == "Ingress"),
                // (ref) all policies (whether or not they contain an ingress section) are assumed to affect ingress
                None => true,
            },
            is_egress: match spec.policy_types {
                Some(ref v) => v.iter().any(|v| v == "Egress"),
                // (ref) policies that contain an egress section are assumed to affect egress
                None => spec.egress.is_some(),
            },
            pod_selector: spec.pod_selector.clone().unwrap_or_default(),
            ingress: spec.ingress.clone().unwrap_or_default(),
            egress: spec.egress.clone().unwrap_or_default(),
        })
    }
}
