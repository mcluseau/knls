pub mod nftables;

use crate::{
    memstore::KeyValueFrom,
    selector::Selector,
    state::{Pod, Protocol, keys},
};

use cidr::IpCidr;
use eyre::{Context, Result, eyre};
use k8s_openapi::{
    api::networking::v1::{
        NetworkPolicy, NetworkPolicyEgressRule, NetworkPolicyIngressRule, NetworkPolicyPeer,
        NetworkPolicyPort,
    },
    apimachinery::pkg::util::intstr::IntOrString,
};
use log::warn;
use std::ops::RangeInclusive;

pub const ANN_REJECT: &str = "netpol.knls.eu/reject";
pub const ANN_EGRESS_REJECT: &str = "netpol.knls.eu/egress-reject";

/// The fallback action applied by a pod chain when no netpol rule matches.
///
/// Netpol only ever refuses traffic, so there is no `accept`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RejectAction {
    Drop,
    #[default]
    Reject,
}

impl RejectAction {
    /// Parses an annotation value, defaulting (with a log) on unknown input.
    pub fn from_annotation(value: &str) -> Self {
        match value {
            "drop" => Self::Drop,
            "reject" => Self::Reject,
            _ => {
                warn!("invalid netpol reject action {value:?}, using default");
                Self::default()
            }
        }
    }
}

/// A pre-parsed [`NetworkPolicyPort`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyPort {
    proto: Protocol,
    port: PortSelect,
}

/// The port selector of a [`PolicyPort`].
#[derive(Clone, Debug, PartialEq, Eq)]
enum PortSelect {
    /// Any port (only the protocol is constrained).
    Any,
    /// An inclusive numeric range.
    Range(RangeInclusive<u16>),
    /// A named container port, resolved against the pods at render time.
    Named(String),
}

impl PolicyPort {
    /// The constrained protocol.
    pub fn proto(&self) -> Protocol {
        self.proto
    }

    /// The constrained numeric port range, if any.
    pub fn port(&self) -> Option<&RangeInclusive<u16>> {
        match &self.port {
            PortSelect::Range(r) => Some(r),
            _ => None,
        }
    }

    /// The named port, if any.
    pub fn named(&self) -> Option<&str> {
        match &self.port {
            PortSelect::Named(name) => Some(name),
            _ => None,
        }
    }
}

impl TryFrom<&NetworkPolicyPort> for PolicyPort {
    type Error = eyre::Error;

    fn try_from(port: &NetworkPolicyPort) -> Result<Self> {
        let proto = Protocol::try_from(&port.protocol)?;

        let port = match port.port.as_ref() {
            None => PortSelect::Any,
            Some(IntOrString::String(name)) => PortSelect::Named(name.clone()),
            Some(IntOrString::Int(start)) => {
                let start = *start as u16;
                let end = port.end_port.map_or(start, |end| end as u16);
                PortSelect::Range(start..=end)
            }
        };

        Ok(Self { proto, port })
    }
}

/// A pre-parsed [`NetworkPolicyPeer`].
///
/// A `Selector` peer still needs the live pod/namespace set to be resolved into
/// addresses; that happens at render time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Peer {
    IpBlock {
        cidr: IpCidr,
        except: Vec<IpCidr>,
    },
    Selector {
        namespace: Option<Selector>,
        pod: Option<Selector>,
    },
}

impl TryFrom<&NetworkPolicyPeer> for Peer {
    type Error = eyre::Error;

    fn try_from(peer: &NetworkPolicyPeer) -> Result<Self> {
        if let Some(ref ip_block) = peer.ip_block {
            let cidr = ip_block
                .cidr
                .parse::<IpCidr>()
                .wrap_err_with(|| format!("invalid ip block: {}", ip_block.cidr))?;

            let except = (ip_block.except.as_deref().unwrap_or_default())
                .iter()
                .map(|cidr| {
                    cidr.parse::<IpCidr>()
                        .wrap_err_with(|| format!("invalid ip block except: {cidr}"))
                })
                .collect::<Result<_>>()?;

            return Ok(Self::IpBlock { cidr, except });
        }

        Ok(Self::Selector {
            namespace: peer
                .namespace_selector
                .as_ref()
                .map(Selector::try_from)
                .transpose()?,
            pod: peer
                .pod_selector
                .as_ref()
                .map(Selector::try_from)
                .transpose()?,
        })
    }
}

/// A pre-parsed netpol rule (an ingress or egress rule).
///
/// Empty `ports`/`peers` mean "no constraint" (match all), matching the k8s
/// semantics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyRule {
    ports: Vec<PolicyPort>,
    peers: Vec<Peer>,
}

impl PolicyRule {
    /// The port alternatives (empty means "all ports").
    pub fn ports(&self) -> &[PolicyPort] {
        &self.ports
    }

    /// The peer alternatives (empty means "all peers").
    pub fn peers(&self) -> &[Peer] {
        &self.peers
    }

    /// Parses the ports/peers of one rule.
    fn parse(
        ports: &Option<Vec<NetworkPolicyPort>>,
        peers: &Option<Vec<NetworkPolicyPeer>>,
    ) -> Result<Self> {
        let ports = (ports.as_deref().unwrap_or_default())
            .iter()
            .map(PolicyPort::try_from)
            .collect::<Result<_>>()?;

        let peers = (peers.as_deref().unwrap_or_default())
            .iter()
            .map(Peer::try_from)
            .collect::<Result<_>>()?;

        Ok(Self { ports, peers })
    }
}

impl TryFrom<&NetworkPolicyIngressRule> for PolicyRule {
    type Error = eyre::Error;

    fn try_from(rule: &NetworkPolicyIngressRule) -> Result<Self> {
        Self::parse(&rule.ports, &rule.from)
    }
}

impl TryFrom<&NetworkPolicyEgressRule> for PolicyRule {
    type Error = eyre::Error;

    fn try_from(rule: &NetworkPolicyEgressRule) -> Result<Self> {
        Self::parse(&rule.ports, &rule.to)
    }
}

#[derive(Clone)]
pub struct Policy {
    namespace: String,
    is_ingress: bool,
    is_egress: bool,
    pod_selector: Selector,
    ingress: Vec<PolicyRule>,
    egress: Vec<PolicyRule>,
}

impl Policy {
    /// Whether this policy affects ingress.
    pub fn is_ingress(&self) -> bool {
        self.is_ingress
    }

    /// Whether this policy affects egress.
    pub fn is_egress(&self) -> bool {
        self.is_egress
    }

    /// The parsed ingress rules.
    pub fn ingress(&self) -> &[PolicyRule] {
        &self.ingress
    }

    /// The parsed egress rules.
    pub fn egress(&self) -> &[PolicyRule] {
        &self.egress
    }

    /// Whether this policy selects `pod` (in `key`'s namespace).
    pub fn matches_pod(&self, key: &keys::Object, pod: &Pod) -> bool {
        key.namespace == self.namespace && self.pod_selector.matches(&pod.labels)
    }
}

impl TryFrom<&NetworkPolicy> for Policy {
    type Error = eyre::Error;

    fn try_from(v: &NetworkPolicy) -> Result<Self> {
        let spec = v.spec.as_ref().ok_or_else(|| eyre!("no spec"))?;

        let ingress: Vec<_> = (spec.ingress.as_deref().unwrap_or_default())
            .iter()
            .map(PolicyRule::try_from)
            .collect::<Result<_>>()?;
        let egress: Vec<_> = (spec.egress.as_deref().unwrap_or_default())
            .iter()
            .map(PolicyRule::try_from)
            .collect::<Result<_>>()?;

        Ok(Self {
            namespace: v
                .metadata
                .namespace
                .clone()
                .ok_or_else(|| eyre!("no namespace"))?,
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
            pod_selector: spec
                .pod_selector
                .as_ref()
                .map(Selector::try_from)
                .transpose()?
                .unwrap_or_default(),
            ingress,
            egress,
        })
    }
}

impl KeyValueFrom<NetworkPolicy> for Policy {
    type Key = keys::Object;

    fn key_from(v: &NetworkPolicy) -> Option<Self::Key> {
        keys::Object::try_from(&v.metadata).ok()
    }

    fn value_from(v: &NetworkPolicy) -> Option<Self> {
        Self::try_from(v)
            .inspect_err(|e| {
                warn!(
                    "ignoring invalid network policy {:?}/{:?}: {e}",
                    v.metadata.namespace.as_deref().unwrap_or("<?>"),
                    v.metadata.name.as_deref().unwrap_or("<?>")
                )
            })
            .ok()
    }
}
