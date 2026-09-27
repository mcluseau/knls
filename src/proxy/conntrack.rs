use eyre::{Result, format_err};
use futures::{StreamExt, TryStreamExt};
use k8s_openapi::api::core::v1 as core;
use log::{debug, error, trace};
use netlink_packet_core::{
    DefaultNla, NLA_TYPE_MASK, NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST, NetlinkHeader, NetlinkMessage,
    NetlinkPayload, Nla,
};
use netlink_packet_netfilter::{
    NetfilterHeader, NetfilterMessage, NetfilterMessageInner, NetfilterProtoFamily,
    conntrack::{ConntrackAttribute, ConntrackMessage, IPTuple, ProtoTuple, Protocol, Tuple},
};
use netlink_packet_route::address::AddressAttribute;
use netlink_proto::{
    ConnectionHandle, new_connection,
    sys::{SocketAddr as NetlinkSocketAddr, protocols::NETLINK_NETFILTER},
};
use nix::errno::Errno;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    net::{IpAddr, SocketAddr},
};

use crate::{
    ips, keys,
    kube_watch::Event,
    netlink,
    rtnl_exts::ErrorExt,
    store::{HashIndex, Store},
};

/// `CTA_ID` is not exposed as a typed variant by `netlink-packet-netfilter`, so
/// it is kept as an opaque attribute and replayed as-is on delete.
const CTA_ID: u16 = 12;

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

        let mut any_ip = false;
        let mut any_ep = false;

        for svc_key in [Target::IpPort(svc), Target::NodePort(svc.port())]
            .iter()
            .filter_map(|target| state.svc_targets.get_rev(target))
            .flatten()
        {
            any_ip = true; // matches a service

            for (_, eps) in (state.svc_eps).range(svc_key.to_parent()..svc_key.to_parent().end()) {
                any_ep |= eps.contains(&ep.ip());
                // also check the hostNetwork/local IP case
                any_ep |= reply_is_local && eps.into_iter().any(|ip| local_ips.contains(ip));
            }

            if any_ep {
                break; // flow is valid
            }
        }

        if !any_ip || any_ep {
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
    handle: ConnectionHandle<NetfilterMessage>,
    kernel: NetlinkSocketAddr,
    rtnl: rtnetlink::Handle,
    svc_targets: HashIndex<core::Service, keys::Obj, Target>,
    svc_eps: Store<keys::ByParent, ips::Endpoint>,
}

impl State {
    pub async fn new() -> Result<Self> {
        let (conn, handle, _) = new_connection::<NetfilterMessage>(NETLINK_NETFILTER)?;
        tokio::spawn(conn);

        let (rtnl_conn, rtnl, _) = rtnetlink::new_connection()?;
        tokio::spawn(rtnl_conn);

        Ok(Self {
            handle,
            kernel: NetlinkSocketAddr::new(0, 0),
            rtnl,
            svc_targets: HashIndex::new(svc_targets),
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

    /// dump all conntrack entries, resolving only UDP flows
    async fn dump(&self) -> Result<Vec<Flow>> {
        let mut header = NetlinkHeader::default();
        header.flags = NLM_F_REQUEST | NLM_F_DUMP;

        let msg = NetlinkMessage::new(
            header,
            NetfilterMessage::new(
                NetfilterHeader::new(NetfilterProtoFamily::Unspec, 0, 0),
                ConntrackMessage::Get(Vec::new()),
            )
            .into(),
        );

        let mut responses = self.handle.request(msg, self.kernel)?;
        let mut flows = Vec::new();

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

        Ok(flows)
    }

    /// delete flows by their original tuple and id
    ///
    /// Errors are only logged.
    async fn delete(&self, flows: Vec<Flow>) {
        let mut responses = netlink::send_batched(
            &self.handle,
            self.kernel,
            flows.into_iter().map(Flow::into_delete),
        );

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
        self.svc_targets.is_ready() && self.svc_eps.is_ready()
    }

    pub fn ingest(&mut self, e: &Event) -> bool {
        use Event::{EndpointSlice, Service};
        match e {
            Service(e) => {
                self.svc_targets.ingest(e);
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
}
