pub mod nftables;

use crate::{
    memstore::KeyValueFrom,
    selector::Selector,
    state::{Pod, keys},
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

/// A layer-4 protocol a netpol may constrain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum L4Proto {
    Tcp,
    Udp,
    Sctp,
}

impl L4Proto {
    /// The IP protocol number (`IPPROTO_*`).
    pub fn ip_proto(&self) -> u8 {
        match self {
            Self::Tcp => 6,
            Self::Udp => 17,
            Self::Sctp => 132,
        }
    }
}

impl TryFrom<Option<&str>> for L4Proto {
    type Error = eyre::Error;

    fn try_from(protocol: Option<&str>) -> Result<Self> {
        match protocol.unwrap_or("TCP").to_lowercase().as_str() {
            "tcp" => Ok(Self::Tcp),
            "udp" => Ok(Self::Udp),
            "sctp" => Ok(Self::Sctp),
            other => Err(eyre!("unsupported protocol {other:?}")),
        }
    }
}

/// A pre-parsed [`NetworkPolicyPort`].
///
/// `port` is `None` for an any-port match (only the protocol is constrained).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyPort {
    proto: L4Proto,
    port: Option<RangeInclusive<u16>>,
}

impl PolicyPort {
    /// The constrained protocol.
    pub fn proto(&self) -> L4Proto {
        self.proto
    }

    /// The constrained port range, or `None` for an any-port match.
    pub fn port(&self) -> Option<&RangeInclusive<u16>> {
        self.port.as_ref()
    }
}

impl TryFrom<&NetworkPolicyPort> for PolicyPort {
    type Error = eyre::Error;

    fn try_from(port: &NetworkPolicyPort) -> Result<Self> {
        let proto = L4Proto::try_from(port.protocol.as_deref())?;

        let port = match port.port.as_ref() {
            None => None,
            Some(IntOrString::String(name)) => {
                return Err(eyre!("named port {name:?} is not supported"));
            }
            Some(IntOrString::Int(start)) => {
                let start = *start as u16;
                let end = port.end_port.map_or(start, |end| end as u16);
                Some(start..=end)
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
