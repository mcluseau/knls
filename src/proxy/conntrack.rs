use eyre::{Result, format_err};
use futures::{StreamExt, TryStreamExt};
use k8s_openapi::api::core::v1 as core;
use log::{debug, error, trace};
use netlink_packet_core::{
    DefaultNla, Emitable, NLA_TYPE_MASK, NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST, NetlinkHeader,
    NetlinkMessage, NetlinkPayload, Nla,
};
use netlink_packet_netfilter::{
    NetfilterHeader, NetfilterMessage, NetfilterMessageInner, NetfilterProtoFamily,
    conntrack::{ConntrackAttribute, ConntrackMessage, IPTuple, ProtoTuple, Protocol, Tuple},
};
use netlink_packet_route::address::AddressAttribute;
use nix::errno::Errno;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    net::{IpAddr, SocketAddr},
};

use crate::{
    ips, keys,
    kube_watch::Event,
    netlink::{Netlink, netfilter},
    rtnl_exts::ErrorExt,
    store::{HashIndex, Store},
};

/// `CTA_ID` is not exposed as a typed variant by `netlink-packet-netfilter`, so
/// it is kept as an opaque attribute and replayed as-is on delete.
const CTA_ID: u16 = 12;

/// `CTA_FILTER` (`enum ctattr_type`), the nested dump-filter attribute.
const CTA_FILTER: u16 = 23;
/// `CTA_FILTER_ORIG_FLAGS` / `CTA_FILTER_REPLY_FLAGS` (`enum ctattr_filter`).
const CTA_FILTER_ORIG_FLAGS: u16 = 1;
const CTA_FILTER_REPLY_FLAGS: u16 = 2;
/// `CTA_FILTER_F_CTA_PROTO_NUM` (`nf_internals.h`): match the L4 protocol.
const CTA_FILTER_F_PROTO_NUM: u32 = 1 << 3;

/// The attributes restricting a conntrack dump to UDP flows.
///
/// kube-proxy only evicts stale *UDP* flows (TCP entries expire on their own),
/// so ask the kernel to filter the dump by L4 protocol instead of dumping every
/// family and protocol and discarding the rest here: a `CTA_FILTER` selecting
/// the original tuple's protocol number, plus the UDP `CTA_TUPLE_ORIG` to match.
fn udp_dump_filter() -> Vec<ConntrackAttribute> {
    // `CTA_FILTER_*_FLAGS` is a native-endian `u32` (`NLA_U32`, read with
    // `nla_get_u32`; libnetfilter_conntrack writes it with `mnl_attr_put_u32`).
    let mut filter = Vec::new();
    for (kind, flags) in [
        (CTA_FILTER_ORIG_FLAGS, CTA_FILTER_F_PROTO_NUM),
        (CTA_FILTER_REPLY_FLAGS, 0),
    ] {
        let nla = DefaultNla::new(kind, flags.to_ne_bytes().to_vec());
        let mut buf = vec![0u8; nla.buffer_len()];
        nla.emit(&mut buf);
        filter.extend_from_slice(&buf);
    }

    vec![
        ConntrackAttribute::CtaTupleOrig(vec![Tuple::Proto(vec![ProtoTuple::Protocol(
            Protocol::Udp,
        )])]),
        ConntrackAttribute::Other(DefaultNla::new(CTA_FILTER, filter)),
    ]
}

pub async fn cleanup(state: &State) -> Result<()> {
    let mut stale = Vec::new();
    // per-service deletion counts, only tracked when debug logging is enabled
    let mut per_svc = BTreeMap::<_, usize>::new();

    // hostNetwork endpoints may imply `redirect`, so any local address can be
    // the reply address. List local IPs to check those cases.
    let local_ips = state.local_ips().await?;

    for flow in state.dump().await? {
        let svc = flow.origin.dst;
        let ep = flow.reply.src;
        let reply_is_local = local_ips.contains(&ep.ip());

        // A flow is valid if its destination matches a service and its reply
        // (endpoint IP *and* target port) is still a current endpoint of that
        // service. The port matters: changing a service's target port must
        // invalidate the old flows.
        let mut matched = false;
        let mut valid = false;

        for target in [Target::IpPort(svc), Target::NodePort(svc.port())] {
            let Some(svc_keys) = state.svc_targets.get_rev(&target) else {
                continue;
            };

            for svc_key in svc_keys {
                matched = true;

                // resolve the flow's destination port to the service port name
                let Some(name) = state
                    .svc_ports
                    .get(svc_key)
                    .and_then(|ports| ports.name_for(&target))
                else {
                    continue;
                };

                for (_, eps) in
                    (state.svc_eps).range(svc_key.to_parent()..svc_key.to_parent().end())
                {
                    let Some(target_port) = eps.target_port(name) else {
                        continue;
                    };
                    if ep.port() != target_port {
                        continue;
                    }

                    // also check the hostNetwork/local address case
                    valid |= eps.contains(&ep.ip())
                        || (reply_is_local && eps.into_iter().any(|ip| local_ips.contains(ip)));
                }
            }
        }

        if !matched || valid {
            continue;
        }

        trace!("removing flow {flow} ({svc} mapped to {ep})");
        if log::log_enabled!(log::Level::Debug) {
            *per_svc.entry(svc).or_default() += 1;
        }
        stale.push(flow);
    }

    debug!("{} flows to delete", stale.len());

    // delete every stale flow in a single netlink batch
    state.delete(stale).await;

    for (svc, n) in per_svc {
        debug!("deleted {n} flows to {svc}");
    }

    Ok(())
}

/// resolved conntrack Flow entry for our use
struct Flow {
    id: DefaultNla,
    origin: IpTuple,
    reply: IpTuple,
}

impl fmt::Display for Flow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        write!(f, "{}→{}", self.origin, self.reply)
    }
}

impl Flow {
    fn from_attrs(attrs: Vec<ConntrackAttribute>) -> Option<Self> {
        let mut id = None;
        let mut origin = None;
        let mut reply = None;

        for attr in attrs {
            match attr {
                ConntrackAttribute::CtaTupleOrig(tuples) => origin = IpTuple::from_tuple(&tuples),
                ConntrackAttribute::CtaTupleReply(tuples) => reply = IpTuple::from_tuple(&tuples),
                ConntrackAttribute::Other(nla) if nla.kind() & NLA_TYPE_MASK == CTA_ID => {
                    id = Some(nla)
                }
                _ => {}
            }
        }

        Some(Self {
            id: id?,
            origin: origin?,
            reply: reply?,
        })
    }

    fn into_delete(self) -> NetlinkMessage<NetfilterMessage> {
        let family = match self.origin.src.ip() {
            IpAddr::V4(_) => NetfilterProtoFamily::IPv4,
            IpAddr::V6(_) => NetfilterProtoFamily::IPv6,
        };

        // the original tuple locates the entry, the id makes the match exact
        let attrs = vec![
            ConntrackAttribute::CtaTupleOrig(self.origin.ct_tuple()),
            ConntrackAttribute::Other(self.id),
        ];

        let mut header = NetlinkHeader::default();
        header.flags = NLM_F_REQUEST | NLM_F_ACK;

        NetlinkMessage::new(
            header,
            NetfilterMessage::new(
                NetfilterHeader::new(family, 0, 0),
                ConntrackMessage::Delete(attrs),
            )
            .into(),
        )
    }
}

struct IpTuple {
    src: SocketAddr,
    dst: SocketAddr,
}

impl fmt::Display for IpTuple {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        write!(f, "({}→{})", self.src, self.dst)
    }
}

impl IpTuple {
    fn from_tuple(tuples: &[Tuple]) -> Option<Self> {
        let mut src = None;
        let mut dst = None;
        let mut udp = false;
        let mut sport = None;
        let mut dport = None;

        for tuple in tuples {
            match tuple {
                Tuple::Ip(ips) => {
                    for ip in ips {
                        match ip {
                            IPTuple::SourceAddress(ip) => src = Some(*ip),
                            IPTuple::DestinationAddress(ip) => dst = Some(*ip),
                            _ => {}
                        }
                    }
                }
                Tuple::Proto(protos) => {
                    for proto in protos {
                        match proto {
                            ProtoTuple::Protocol(Protocol::Udp) => udp = true,
                            ProtoTuple::SourcePort(port) => sport = Some(*port),
                            ProtoTuple::DestinationPort(port) => dport = Some(*port),
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }

        if !udp {
            return None; // UDP only
        }

        Some(Self {
            src: SocketAddr::new(src?, sport?),
            dst: SocketAddr::new(dst?, dport?),
        })
    }

    /// the tuple attributes (IP + UDP proto) identifying this flow's side
    fn ct_tuple(&self) -> Vec<Tuple> {
        vec![
            Tuple::Ip(vec![
                IPTuple::SourceAddress(self.src.ip()),
                IPTuple::DestinationAddress(self.dst.ip()),
            ]),
            Tuple::Proto(vec![
                ProtoTuple::Protocol(Protocol::Udp),
                ProtoTuple::SourcePort(self.src.port()),
                ProtoTuple::DestinationPort(self.dst.port()),
            ]),
        ]
    }
}

pub struct State {
    nl: Netlink<NetfilterMessage>,
    rtnl: rtnetlink::Handle,
    svc_targets: HashIndex<core::Service, keys::Obj, Target>,
    svc_ports: Store<keys::Obj, ServiceUdpPorts>,
    svc_eps: Store<keys::ByParent, ips::Endpoint>,
}

impl State {
    pub async fn new() -> Result<Self> {
        let nl = netfilter::new_link()?;

        let (rtnl_conn, rtnl, _) = rtnetlink::new_connection()?;
        tokio::spawn(rtnl_conn);

        Ok(Self {
            nl,
            rtnl,
            svc_targets: HashIndex::new(svc_targets),
            svc_ports: Store::new(),
            svc_eps: Store::new(),
        })
    }

    /// all IP addresses configured on the host (any interface)
    async fn local_ips(&self) -> Result<BTreeSet<IpAddr>> {
        let mut addrs = (self.rtnl.address().get()).execute();

        let mut local = BTreeSet::new();
        while let Some(msg) = addrs.try_next().await? {
            local.extend(msg.attributes.iter().filter_map(|attr| match attr {
                AddressAttribute::Address(ip) => Some(*ip),
                _ => None,
            }));
        }

        Ok(local)
    }

    /// dump all UDP conntrack entries
    ///
    /// Only UDP is asked for ([`udp_dump_filter`]); the kernel filter needs a
    /// concrete L3 family, so one dump is sent per family.
    async fn dump(&self) -> Result<Vec<Flow>> {
        let mut flows = Vec::new();

        for family in [NetfilterProtoFamily::IPv4, NetfilterProtoFamily::IPv6] {
            let mut header = NetlinkHeader::default();
            header.flags = NLM_F_REQUEST | NLM_F_DUMP;

            let msg = NetlinkMessage::new(
                header,
                NetfilterMessage::new(
                    NetfilterHeader::new(family, 0, 0),
                    ConntrackMessage::Get(udp_dump_filter()),
                )
                .into(),
            );

            let mut responses = self.nl.handle().request(msg, self.nl.dest())?;

            while let Some(message) = responses.next().await {
                match message.payload {
                    NetlinkPayload::InnerMessage(NetfilterMessage {
                        inner: NetfilterMessageInner::Conntrack(message),
                        ..
                    }) => {
                        let attrs = match message {
                            ConntrackMessage::New(attrs) | ConntrackMessage::Get(attrs) => attrs,
                            _ => continue,
                        };
                        if let Some(flow) = Flow::from_attrs(attrs) {
                            flows.push(flow);
                        }
                    }
                    NetlinkPayload::Error(e) if e.code.is_some() => {
                        return Err(format_err!("conntrack dump error: {e:?}"));
                    }
                    _ => {}
                }
            }
        }

        Ok(flows)
    }

    /// delete flows by their original tuple and id
    ///
    /// Errors are only logged.
    async fn delete(&self, flows: Vec<Flow>) {
        let mut responses = self
            .nl
            .send_batched(flows.into_iter().map(Flow::into_delete));

        while let Some(response) = responses.next().await {
            let Ok(message) =
                response.inspect_err(|e| error!("conntrack delete send error: {e:?}"))
            else {
                continue;
            };

            if let NetlinkPayload::Error(err) = message.payload
                && err.code.is_some()
                && !err.is_errno(Errno::ENOENT)
            {
                debug!("conntrack delete error: {err:?}");
            }
        }
    }

    pub fn is_ready(&self) -> bool {
        self.svc_targets.is_ready() && self.svc_ports.is_ready() && self.svc_eps.is_ready()
    }

    pub fn ingest(&mut self, e: &Event) -> bool {
        use Event::{EndpointSlice, Service};
        match e {
            Service(e) => {
                self.svc_targets.ingest(e);
                self.svc_ports.ingest(e);
                true
            }
            EndpointSlice(e) => {
                self.svc_eps.ingest(e);
                true
            }
            _ => false,
        }
    }
}

/// A Service's UDP ports: service port -> (node port, name), used to resolve a
/// flow's destination port to the service port name (and so its target port).
#[derive(Default)]
struct ServiceUdpPorts {
    ports: BTreeMap<u16, (Option<u16>, String)>,
}

impl ServiceUdpPorts {
    /// The name of the service port a flow's destination matches.
    fn name_for(&self, target: &Target) -> Option<&str> {
        match target {
            Target::IpPort(addr) => self.ports.get(&addr.port()).map(|(_, name)| name.as_str()),
            Target::NodePort(node_port) => self
                .ports
                .values()
                .find(|(node, _)| node == &Some(*node_port))
                .map(|(_, name)| name.as_str()),
        }
    }
}

impl From<&core::Service> for ServiceUdpPorts {
    fn from(svc: &core::Service) -> Self {
        let ports = (svc.spec.iter().flat_map(|spec| spec.ports.iter().flatten()))
            .filter(|p| p.protocol.as_deref() == Some("UDP"))
            .map(|p| {
                (
                    p.port as u16,
                    (
                        p.node_port.map(|p| p as u16),
                        p.name.clone().unwrap_or_default(),
                    ),
                )
            })
            .collect();

        Self { ports }
    }
}

impl crate::store::IntoKey<core::Service> for keys::Obj {
    fn into_key(svc: &core::Service) -> Option<Self> {
        Some(keys::Obj::from(svc))
    }
}

fn svc_targets(svc: &core::Service) -> BTreeSet<Target> {
    let mut set = BTreeSet::new();

    let Some(spec) = svc.spec.as_ref() else {
        return set;
    };

    let ports: Vec<_> = (spec.ports.iter().flatten())
        .filter(|p| p.protocol.as_deref() == Some("UDP")) // UDP only
        .map(|p| (p.port as u16, p.node_port.map(|p| p as u16)))
        .collect();

    if ports.is_empty() {
        return set;
    }

    for ip in ips::Service::from(svc).all() {
        for (port, _) in &ports {
            set.insert(Target::ip(ip, *port));
        }
    }

    for (_, node_port) in &ports {
        let Some(node_port) = node_port else {
            continue;
        };
        set.insert(Target::NodePort(*node_port));
    }

    set
}

#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
enum Target {
    IpPort(SocketAddr),
    NodePort(u16),
}

impl Target {
    fn ip(ip: IpAddr, port: u16) -> Self {
        Self::IpPort(SocketAddr::new(ip, port))
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    fn flow(src: IpAddr, dst: IpAddr) -> Flow {
        let origin = IpTuple {
            src: SocketAddr::new(src, 1234),
            dst: SocketAddr::new(dst, 53),
        };
        let reply = IpTuple {
            src: SocketAddr::new(dst, 53),
            dst: SocketAddr::new(src, 1234),
        };
        Flow {
            id: DefaultNla::new(CTA_ID, 4u32.to_be_bytes().to_vec()),
            origin,
            reply,
        }
    }

    #[test]
    fn delete_msg_size() {
        let v4 = flow(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        );
        // netlink header (16) + netfilter header (4) + orig tuple (52) + id (8)
        assert_eq!(v4.into_delete().buffer_len(), 80);

        let v6 = flow(
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        );
        // +24 bytes for the two 16-byte addresses instead of two 4-byte ones
        assert_eq!(v6.into_delete().buffer_len(), 104);
    }

    /// The dump filter must select the original tuple's protocol number for UDP
    /// (`CTA_FILTER` with native-endian flags, matching the kernel's
    /// `nla_get_u32` and libnetfilter_conntrack's `mnl_attr_put_u32`).
    #[test]
    fn udp_dump_filter_encoding() {
        let attrs = udp_dump_filter();

        let ConntrackAttribute::CtaTupleOrig(tuples) = &attrs[0] else {
            panic!("first attribute is not CTA_TUPLE_ORIG");
        };
        assert!(tuples.iter().any(|t| matches!(t, Tuple::Proto(protos)
            if protos.iter().any(|p| matches!(p, ProtoTuple::Protocol(Protocol::Udp))))));

        let ConntrackAttribute::Other(nla) = &attrs[1] else {
            panic!("second attribute is not CTA_FILTER");
        };
        assert_eq!(nla.kind(), CTA_FILTER);

        let mut buf = vec![0u8; nla.buffer_len()];
        nla.emit(&mut buf);

        // the outer `CTA_FILTER` nla, then its nested flags (native endian)
        let mut expected = Vec::new();
        expected.extend_from_slice(&(4u16 + 16).to_ne_bytes());
        expected.extend_from_slice(&CTA_FILTER.to_ne_bytes());
        for (kind, flags) in [
            (CTA_FILTER_ORIG_FLAGS, CTA_FILTER_F_PROTO_NUM),
            (CTA_FILTER_REPLY_FLAGS, 0u32),
        ] {
            expected.extend_from_slice(&8u16.to_ne_bytes());
            expected.extend_from_slice(&kind.to_ne_bytes());
            expected.extend_from_slice(&flags.to_ne_bytes());
        }
        assert_eq!(buf, expected);
    }

    /// The kernel must accept the UDP dump filter: a malformed `CTA_FILTER` is
    /// rejected (`EINVAL`/`EOPNOTSUPP`), so a clean dump proves the filter is
    /// well-formed. That it actually selects UDP-only is covered by the e2e
    /// `Conntrack` suite, which has real (trackable) flows.
    ///
    /// Requires `CAP_NET_ADMIN`; run with `sudo -E cargo test -- --ignored`.
    #[ignore = "requires CAP_NET_ADMIN and a real kernel"]
    #[tokio::test]
    async fn dump_filter_is_accepted() {
        let state = State::new().await.expect("netlink");
        let _flows = state.dump().await.expect("dump");
    }
}
