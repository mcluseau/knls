use cidr::{IpCidr, IpInet};
use eyre::{Result, eyre, format_err};
use futures::TryStreamExt;
use k8s_openapi::api::core::v1 as core;
use kube::ResourceExt;
use log::{debug, error, info, warn};
use netlink_packet_route::{
    address::{AddressAttribute, AddressMessage},
    link::{LinkAttribute::Mtu, LinkMessage},
    route::RouteHeader,
};
use nix::errno::Errno;
use serde_json::json;
use std::collections::BTreeMap as Map;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::RangeInclusive;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::netlink::netfilter::{self, NetlinkExt as _};
use crate::netlink::wireguard::{self as nlwg, Peer as WgPeer};
use crate::nftables::{
    chain::{self, Chain, ChainType, InetHookNumber},
    rules,
    rules::{Dir, Family, Verdict},
    table_sync::{BaseChain, ChainSync, SetSync, TableState, TableSync},
};
use crate::rtnl_exts::ErrorExt;
use crate::state::wireguard::{Key, Node, decode_key, encode_key};
use crate::{
    actions, change, keys, kube_watch::EventReceiver, memstore::KeyValueFrom, patch_params,
};
use netlink_packet_netfilter::nftables::{MetaKey, Register};

crate::multimap!(
    State{
        nodes: Node(core::Node) => Node,
        pods: Pod(core::Pod) => Pod,
    }
);

#[derive(Clone, Debug)]
struct Pod {
    ips: Vec<IpAddr>,
    external_ipv4: Option<IpAddr>,
    external_ipv6: Option<IpAddr>,
}
impl KeyValueFrom<core::Pod> for Pod {
    type Key = keys::Obj;
    fn key_from(v: &core::Pod) -> Option<Self::Key> {
        Some(keys::Obj::from(v))
    }
    fn value_from(v: &core::Pod) -> Option<Self> {
        // TODO document labels
        let ip = |label| v.labels().get(label).and_then(|ip| ip.parse().ok());
        let external_ipv4 = ip("knls.eu/external-ipv4");
        let external_ipv6 = ip("knls.eu/external-ipv6");

        if external_ipv4.is_none() && external_ipv6.is_none() {
            return None;
        }

        let ips = (v.status.as_ref()?.pod_ips.as_ref()?.iter())
            .filter_map(|ip| ip.ip.parse().ok())
            .collect();

        Some(Pod {
            ips,
            external_ipv4,
            external_ipv6,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct Config {
    /// Activate node connectivity through wireguard using this interface
    ifname: String,
    /// Wireguard private key file (will be created as needed).
    key_path: String,
    /// CNI config path
    cni_config: String,
    /// Action to run when the link is created (ie: nft rules with iif/oif matches)
    on_create: Vec<crate::actions::Action>,
    /// Manually defined node (intended for testing)
    manual_node: Option<Node>,
    /// Link MTU to set
    mtu: Option<u16>,
    /// Chain the CNI `portmap` plugin so pods' `hostPort`s are reachable.
    host_ports: bool,
    /// Masquerade pod traffic leaving the cluster (destinations other than
    /// local pods or pods reachable through the wireguard interface).
    masquerade: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            ifname: "kwg".into(),
            key_path: "/var/lib/knls/wireguard.key".into(),
            cni_config: "/etc/cni/net.d/10-knls.conf".into(),
            on_create: Vec::new(),
            manual_node: None,
            mtu: None,
            host_ports: false,
            masquerade: true,
        }
    }
}

async fn setup_link(
    rtnl: &rtnetlink::Handle,
    ifname: &str,
    mtu: Option<u16>,
) -> Result<LinkMessage> {
    use rtnetlink::LinkWireguard;

    let link = if let Some(link) = get_link(rtnl, ifname).await? {
        info!("link {ifname} exists");
        link
    } else {
        info!("creating link {ifname}");
        let mut builder = LinkWireguard::new(ifname);
        if let Some(mtu) = mtu {
            builder = builder.mtu(mtu.into());
        }
        rtnl.link().add(builder.up().build()).execute().await?;

        get_link(rtnl, ifname)
            .await?
            .expect("link {ifname} should exist")
    };

    if let Some(mtu) = mtu
        && link_mtu(&link) != Some(mtu)
    {
        info!("updating link {ifname} mtu to {mtu}");
        set_mtu(rtnl, link.header.index, mtu.into()).await?;
    }

    Ok(link)
}

/// Update the MTU of the link with the given index.
async fn set_mtu(rtnl: &rtnetlink::Handle, index: u32, mtu: u32) -> Result<()> {
    use rtnetlink::LinkUnspec;
    rtnl.link()
        .set(LinkUnspec::new_with_index(index).mtu(mtu).build())
        .execute()
        .await?;
    Ok(())
}

async fn get_link(
    rtnl: &rtnetlink::Handle,
    ifname: impl Into<String>,
) -> Result<Option<LinkMessage>> {
    let ifname = ifname.into();
    let mut links = rtnl.link().get().match_name(ifname.clone()).execute();
    match links.try_next().await {
        Ok(link) => Ok(link),
        Err(e) if e.is_errno(Errno::ENODEV) => Ok(None),
        Err(e) => Err(eyre!("ip link get failed: {e}")),
    }
}

fn link_mtu(link: &LinkMessage) -> Option<u16> {
    (link.attributes.iter()).find_map(|attr| match attr {
        Mtu(mtu) => Some(*mtu as u16),
        _ => None,
    })
}

pub async fn watch(ctx: Arc<crate::Context>, cfg: Config, mut events: EventReceiver) -> Result<()> {
    let node_name = ctx.node_name.as_str();
    let kube = ctx.kube.clone();

    let ifname = cfg.ifname;
    let key_path = cfg.key_path;
    // containerd keys the CNI config *format* off the file extension: a plugin
    // list must be named `*.conflist`, a single plugin `*.conf`.
    let (cni_config_path, cni_config_stale) = cni_config_paths(cfg.host_ports, &cfg.cni_config);

    let default_port = 51820u16;

    let (conn, rtnl, _) = rtnetlink::new_connection()?;
    tokio::spawn(conn);

    let link = setup_link(&rtnl, &ifname, cfg.mtu).await?;
    let link_id = link.header.index;

    actions::run_event(module_path!(), "on_create", &cfg.on_create).await?;

    // The external-IP snat chain used to live in the `knls` table and was
    // created by this code. Delete it from there now that the connectivity
    // table owns it.
    remove_legacy_external_ips_chain("knls").await;

    let if_addrs = IfAddrs {
        id: link_id,
        rtnl: rtnl.clone(),
    };

    let private_key = get_private_key(&key_path).await?;
    let pubkey: PublicKey = (&StaticSecret::from(private_key)).into();

    let wg = nlwg::Wireguard::new().await?;

    info!("loading existing peers");
    let mut current_listen_port;
    let mut current_pubkey;
    let mut peers = change::Tracker::new();

    {
        let host = wg.get(&ifname).await?;
        current_listen_port = Some(host.listen_port);
        current_pubkey = host.private_key.map(PublicKey::from);

        for raw_peer in host.peers {
            let key = raw_peer.public_key;
            debug!("existing peer: {}", encode_key(&key));
            let peer = Peer {
                endpoint: raw_peer.endpoint,
                allowed_ips: raw_peer.allowed_ips,
            };
            if let Some(change) = peers.check(key, &peer) {
                change.set(peer);
            }
        }
        peers.update_done();
    }

    info!("loading existing routes");
    let mut routes = change::Tracker::new();

    let oif_routes = OifRoutes {
        oif: link_id,
        default_hdr: {
            use netlink_packet_route::route::*;
            RouteHeader {
                table: RouteHeader::RT_TABLE_MAIN,
                scope: RouteScope::Link,
                kind: RouteType::Unicast,
                protocol: RouteProtocol::Boot,
                ..Default::default()
            }
        },
        rtnl: rtnl.clone(),
    };

    // start watch
    let mut warned_about_pubkey = false;
    let mut prev_cni_config = None;
    let mut connectivity_applied: Option<ConnectivityKey> = None;
    let mut connectivity_table = TableState::new(CONNECTIVITY_TABLE);
    let mut state = State::new();

    loop {
        use std::ops::ControlFlow::*;
        match state.ingest_events(&mut events).await {
            Some(Break(())) => return Ok(()),
            Some(Continue(())) => continue,
            None => {}
        }
        if !state.is_ready() {
            continue;
        }

        let nodes = state.nodes.map();
        let Some(my_node) = cfg.manual_node.as_ref().or_else(|| nodes.get(node_name)) else {
            continue;
        };

        let vpn_ips: Vec<_> = [
            my_node.if_addr4().map(IpInet::V4),
            my_node.if_addr6().map(IpInet::V6),
        ]
        .into_iter()
        .flatten()
        .collect();

        if_addrs.sync(&vpn_ips).await?;

        // CNI config
        let ptp = CniPtp {
            r#type: "ptp",
            ipam: CniIpam {
                r#type: "host-local",
                ranges: vec![(my_node.pod_cidrs.iter()).map(CniRange::from).collect()],
                routes: (vpn_ips.iter())
                    .map(|inet| CniRoute::default_for(inet.family()))
                    .collect(),
            },
            dns: CniDns {
                nameservers: vpn_ips.iter().map(|ip| ip.to_string()).collect(),
            },
            mtu: (link.attributes.iter())
                .find_map(|attr| match attr {
                    Mtu(mtu) => Some(*mtu),
                    _ => None,
                })
                .unwrap_or(1420),
        };

        let cni_config = cni_config(cfg.host_ports, ptp);

        if cfg.manual_node.is_none() {
            if prev_cni_config.as_ref() != Some(&cni_config) {
                let value = serde_json::to_vec(&cni_config)?;
                // remove the other-format file so containerd loads only one
                let _ = fs::remove_file(&cni_config_stale).await;
                fs::write(&cni_config_path, value).await.map_err(|e| {
                    format_err!(
                        "failed to write CNI config ({}): {e}",
                        cni_config_path.display()
                    )
                })?;
                prev_cni_config = Some(cni_config);
            }

            // publish public key
            if my_node.pubkey != Some(*pubkey.as_bytes()) {
                info!("updating node's pubkey");
                use crate::state::wireguard::ANN_PUBKEY;
                let pubkey = encode_key(pubkey.as_bytes());
                let patch = json!(
                    {"metadata":{"annotations":{ ANN_PUBKEY: pubkey}}}
                );

                use k8s_openapi::api::core::v1::Node;
                use kube::api::Patch;

                let nodes = kube::api::Api::<Node>::all(kube.clone());
                if let Err(e) = nodes
                    .patch(node_name, &patch_params(), &Patch::Strategic(&patch))
                    .await
                    && !warned_about_pubkey
                {
                    let patch_str = serde_json::to_string(&patch).expect("patch should serialize");
                    error!(
                        "failed to update node's pubkey: {e}\nkubectl patch node {node_name} -p {patch_str:?}"
                    );
                    warned_about_pubkey = true;
                }
            }
        }

        let listen_port = my_node.listen_port.unwrap_or(default_port);
        if current_listen_port != Some(listen_port) || current_pubkey != Some(pubkey) {
            wg.set_device(&ifname, listen_port, private_key).await?;

            current_listen_port = Some(listen_port);
            current_pubkey = Some(pubkey);
        }

        for (name, node) in nodes.iter().filter(|(name, _)| **name != node_name) {
            let Some(pubkey) = node.pubkey else {
                continue;
            };

            let peer = Peer {
                endpoint: node.get_endpoint_from(&my_node.zone, default_port),
                allowed_ips: (node.pod_cidrs.iter().copied())
                    // Also allow the peer's own node addresses, so node-sourced
                    // traffic is not dropped by WireGuard's cryptokey-routing
                    // ingress filter (the proxy's `Local` policy short-circuit
                    // keeps the local node address as source).
                    .chain(node.ips.iter().copied().map(IpCidr::new_host))
                    .collect(),
            };

            if let Some(change) = peers.check(pubkey, &peer) {
                match change.kind {
                    change::Kind::Created => {
                        info!("adding peer {name}");
                    }
                    change::Kind::Modified => {
                        info!("updating peer {name}");
                    }
                };
                wg.set_peer(
                    &ifname,
                    &WgPeer {
                        public_key: pubkey,
                        endpoint: peer.endpoint,
                        allowed_ips: peer.allowed_ips.clone(),
                    },
                )
                .await?;
                change.set(peer);
            }

            for route in &node.pod_cidrs {
                if let Some(change) = routes.check(*route, &()) {
                    info!("adding route to {route}");
                    if let Err(e) = oif_routes.add(route).await {
                        error!("failed to add route to {route}: {e}");
                        continue;
                    }
                    change.set(());
                }
            }
        }

        for removed_peer in peers.deleted() {
            info!("deleting peer {}", encode_key(removed_peer));
            wg.del_peer(&ifname, *removed_peer).await?;
        }
        peers.update_done();

        for removed_route in routes.deleted() {
            info!("deleting route to {removed_route}");
            if let Err(e) = oif_routes.del(removed_route).await {
                error!("failed to delete route to {removed_route}: {e}");
                continue;
            }
        }
        routes.update_done();

        // Pods with an external IP get a source-NAT rule too. Collect those
        // before rendering: the connectivity table owns both the external-IP
        // chain and the pod-egress masquerade chain.
        let mut external_ips: Vec<ExternalIpSnat> = Vec::new();
        for (_, pod) in state.pods.iter() {
            if let Some(v4) = pod.external_ipv4
                && my_node.external_ips.contains(&v4)
            {
                for ip in pod.ips.iter().filter(|ip| ip.is_ipv4()) {
                    external_ips.push((*ip, v4));
                }
            }
            if let Some(v6) = pod.external_ipv6
                && my_node.external_ips.contains(&v6)
            {
                for ip in pod.ips.iter().filter(|ip| ip.is_ipv6()) {
                    external_ips.push((*ip, v6));
                }
            }
        }

        let connectivity_key = (
            cfg.masquerade,
            link_id,
            my_node.pod_cidrs.clone(),
            external_ips.clone(),
        );
        if connectivity_applied.as_ref() != Some(&connectivity_key) {
            let next = render_connectivity_table(
                link_id,
                cfg.masquerade,
                &my_node.pod_cidrs,
                &external_ips,
            );
            match connectivity_table.update(next).await {
                Ok(()) => connectivity_applied = Some(connectivity_key),
                Err(e) => error!("failed to update the connectivity table: {e}"),
            }
        }
    }
}

const CONNECTIVITY_TABLE: &str = "knls-connectivity";
const SNAT_CHAIN: &str = "snat";
const EXTERNAL_IPS_CHAIN: &str = "external-ips";
const LEGACY_EXTERNAL_IPS_CHAIN: &str = "wireguard-external-ips";
const LOCAL_PODS_V4: &str = "local_pods4";
const LOCAL_PODS_V6: &str = "local_pods6";

type ExternalIpSnat = (IpAddr, IpAddr);
type ConnectivityKey = (bool, u32, Vec<IpCidr>, Vec<ExternalIpSnat>);

/// Deletes the external-IP snat chain this code used to render in the `knls`
/// table. Missing table/chain is expected and ignored.
async fn remove_legacy_external_ips_chain(table: &str) {
    let chain = Chain::new(table, LEGACY_EXTERNAL_IPS_CHAIN);
    match netfilter::new_link() {
        Ok(nl) => {
            if let Err(e) = nl.send_as_transactions([chain.delete()].into_iter()).await {
                debug!("no legacy external-IP chain to remove: {e}");
            }
        }
        Err(e) => debug!("could not open netfilter netlink to remove legacy chain: {e}"),
    }
}

fn pod_ranges4(pod_cidrs: &[IpCidr]) -> Vec<RangeInclusive<Ipv4Addr>> {
    (pod_cidrs.iter())
        .filter_map(|cidr| match cidr {
            IpCidr::V4(c) => Some(c.first_address()..=c.last_address()),
            IpCidr::V6(_) => None,
        })
        .collect()
}

fn pod_ranges6(pod_cidrs: &[IpCidr]) -> Vec<RangeInclusive<Ipv6Addr>> {
    (pod_cidrs.iter())
        .filter_map(|cidr| match cidr {
            IpCidr::V4(_) => None,
            IpCidr::V6(c) => Some(c.first_address()..=c.last_address()),
        })
        .collect()
}

/// Renders the connectivity-owned `knls-connectivity` table.
///
/// It contains two nat postrouting chains:
///
/// - `external-ips` (priority 100): source-NAT each pod IP to the node-assigned
///   external IP, unless the traffic already egresses the wireguard interface.
/// - `snat` (priority 999): masquerade pod traffic whose destination is neither
///   a local pod nor a pod reached through the wireguard interface.
///
/// Node-sourced traffic is not touched by `snat`: peer `allowed_ips` include
/// node addresses, and the proxy already handles the `externalTrafficPolicy:
/// Local` short-circuit.
fn render_connectivity_table(
    ifindex: u32,
    enabled: bool,
    pod_cidrs: &[IpCidr],
    external_ips: &[ExternalIpSnat],
) -> TableSync {
    let comment = Some("local pod CIDRs".to_string());
    let sets = Map::from([
        (
            LOCAL_PODS_V4.into(),
            SetSync::interval(pod_ranges4(pod_cidrs), comment.clone()),
        ),
        (
            LOCAL_PODS_V6.into(),
            SetSync::interval(pod_ranges6(pod_cidrs), comment),
        ),
    ]);

    let mut external_ip_rules = vec![vec![
        rules::meta(MetaKey::Oif, Register::Reg1),
        rules::eq(Register::Reg1, ifindex.to_ne_bytes().to_vec()),
        rules::verdict(Verdict::Return),
    ]];
    external_ip_rules.extend(
        external_ips
            .iter()
            .map(|&(saddr, ext)| snat_rule(saddr, ext)),
    );

    let mut snat_rules = Vec::new();
    if enabled {
        for (family, set) in [(Family::V4, LOCAL_PODS_V4), (Family::V6, LOCAL_PODS_V6)] {
            let mut rule = rules::ip_set(family, Dir::Src, set, false);
            rule.push(rules::meta(MetaKey::Oif, Register::Reg1));
            rule.push(rules::eq(Register::Reg1, ifindex.to_ne_bytes().to_vec()));
            rule.push(rules::verdict(Verdict::Return));
            snat_rules.push(rule);

            let mut rule = rules::ip_set(family, Dir::Src, set, false);
            rule.extend(rules::ip_set(family, Dir::Dst, set, false));
            rule.push(rules::verdict(Verdict::Return));
            snat_rules.push(rule);

            let mut rule = rules::ip_set(family, Dir::Src, set, false);
            rule.push(rules::masquerade(false));
            snat_rules.push(rule);
        }
    }

    let chains = Map::from([
        (
            EXTERNAL_IPS_CHAIN.into(),
            ChainSync {
                base: Some(BaseChain {
                    chain_type: ChainType::Nat,
                    hook: InetHookNumber::PostRouting,
                    priority: 100,
                    policy: chain::ACCEPT,
                }),
                rules: external_ip_rules,
                anon_sets: Vec::new(),
            },
        ),
        (
            SNAT_CHAIN.into(),
            ChainSync {
                base: Some(BaseChain {
                    chain_type: ChainType::Nat,
                    hook: InetHookNumber::PostRouting,
                    priority: 999,
                    policy: chain::ACCEPT,
                }),
                rules: snat_rules,
                anon_sets: Vec::new(),
            },
        ),
    ]);

    TableSync { chains, sets }
}

/// `ip|ip6 saddr <saddr> snat to <ext>`.
fn snat_rule(saddr: IpAddr, ext: IpAddr) -> chain::Rule {
    let (family, prefix) = match ext {
        IpAddr::V4(_) => (Family::V4, 32),
        IpAddr::V6(_) => (Family::V6, 128),
    };

    let mut rule = rules::ip_prefix(family, Dir::Src, prefix, octets(saddr), false);
    rule.push(rules::load_immediate(Register::Reg1, octets(ext)));
    rule.push(rules::snat(family, Register::Reg1));
    rule
}

fn octets(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(ip) => ip.octets().to_vec(),
    }
}

struct IfAddrs {
    id: u32,
    rtnl: rtnetlink::Handle,
}

impl IfAddrs {
    async fn list(&self) -> Result<Vec<(IpInet, AddressMessage)>> {
        let mut addrs = Vec::new();
        let mut link_addrs = (self.rtnl.address().get())
            .set_link_index_filter(self.id)
            .execute();

        while let Some(link_addr) = link_addrs.try_next().await? {
            let Some(addr) = link_addr.attributes.iter().find_map(|attr| match attr {
                AddressAttribute::Address(ip) => Some(*ip),
                _ => None,
            }) else {
                continue;
            };

            let inet = IpInet::new(addr, link_addr.header.prefix_len)
                .expect("kernel cidr should be valid");
            addrs.push((inet, link_addr));
        }

        Ok(addrs)
    }

    async fn sync(&self, wanted: &[IpInet]) -> Result<()> {
        let curr_inets = self.list().await?;

        for (inet, addr_msg) in &curr_inets {
            if !wanted.contains(inet) {
                self.del(addr_msg.clone()).await?;
            }
        }

        for inet in wanted {
            if !curr_inets.iter().any(|(curr, _)| curr == inet) {
                self.add(*inet).await?;
            }
        }

        Ok(())
    }

    async fn add(&self, inet: IpInet) -> Result<()> {
        let (addr, len) = (inet.address(), inet.network_length());
        Ok((self.rtnl.address())
            .add(self.id, addr, len)
            .execute()
            .await?)
    }

    async fn del(&self, addr_msg: AddressMessage) -> Result<()> {
        Ok(self.rtnl.address().del(addr_msg).execute().await?)
    }
}

struct OifRoutes {
    oif: u32,
    default_hdr: RouteHeader,
    rtnl: rtnetlink::Handle,
}
impl OifRoutes {
    async fn add(&self, dest: &IpCidr) -> eyre::Result<()> {
        let msg = self.dest_route_msg(dest);
        self.rtnl.route().add(msg).replace().execute().await?;
        Ok(())
    }

    async fn del(&self, dest: &IpCidr) -> eyre::Result<()> {
        let msg = self.dest_route_msg(dest);
        self.rtnl.route().del(msg).execute().await?;
        Ok(())
    }

    fn route_msg<T>(
        &self,
        builder: rtnetlink::RouteMessageBuilder<T>,
    ) -> netlink_packet_route::route::RouteMessage {
        builder
            .table_id(self.default_hdr.table as u32) // TODO fix upstream?
            .protocol(self.default_hdr.protocol)
            .scope(self.default_hdr.scope)
            .kind(self.default_hdr.kind)
            .output_interface(self.oif)
            .build()
    }

    fn dest_route_msg(&self, dest: &IpCidr) -> netlink_packet_route::route::RouteMessage {
        use rtnetlink::RouteMessageBuilder as B;

        let prefix_len = dest.network_length();

        match dest.first_address() {
            IpAddr::V4(addr) => {
                self.route_msg(B::<Ipv4Addr>::new().destination_prefix(addr, prefix_len))
            }
            IpAddr::V6(addr) => {
                self.route_msg(B::<Ipv6Addr>::new().destination_prefix(addr, prefix_len))
            }
        }
    }
}

async fn get_private_key(key_path: &String) -> Result<Key> {
    match fs::read(key_path).await {
        Ok(encoded_key) => decode_key(encoded_key.trim_ascii()),
        Err(e) => {
            warn!("failed to read private key: {e}");
            info!("creating a new key");
            create_private_key(key_path).await
        }
    }
}

async fn create_private_key(key_path: &String) -> Result<Key> {
    let key = urandom::new().next::<Key>();
    fs::write(key_path, &encode_key(&key)).await?;
    Ok(key)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Peer {
    endpoint: Option<std::net::SocketAddr>,
    allowed_ips: Vec<IpCidr>,
}

/// The CNI config file's contents. Without `host_ports`, a single `ptp` plugin
/// config; with it, a plugin list chaining `portmap` so pod `hostPort`s get
/// DNATed on the node.
#[derive(Eq, PartialEq, serde::Serialize)]
#[serde(untagged)]
enum CniConfig<'t> {
    Single(CniSingle<'t>),
    Conflist(CniConflist<'t>),
}

/// Builds the CNI config for `ptp`, chaining the `portmap` plugin when
/// `host_ports` is set.
fn cni_config<'t>(host_ports: bool, ptp: CniPtp<'t>) -> CniConfig<'t> {
    if host_ports {
        CniConfig::Conflist(CniConflist {
            cni_version: "0.3.1",
            name: "knls",
            plugins: vec![
                CniPlugin::Ptp(ptp),
                CniPlugin::Portmap(CniPortmap {
                    r#type: "portmap",
                    capabilities: CniCapabilities {
                        port_mappings: true,
                    },
                }),
            ],
        })
    } else {
        CniConfig::Single(CniSingle {
            cni_version: "0.3.1",
            name: "knls",
            plugin: ptp,
        })
    }
}

/// The CNI config file path for the current format, and the path of the
/// other-format file to remove (so containerd does not load both).
fn cni_config_paths(host_ports: bool, base: &str) -> (PathBuf, PathBuf) {
    let base = Path::new(base);
    let conflist = base.with_extension("conflist");
    if host_ports {
        (conflist, base.to_owned())
    } else {
        (base.to_owned(), conflist)
    }
}

/// A single-plugin CNI config (`{cniVersion, name, type, …}`).
#[derive(Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct CniSingle<'t> {
    cni_version: &'t str,
    name: &'t str,
    #[serde(flatten)]
    plugin: CniPtp<'t>,
}

/// A CNI plugin list (`{cniVersion, name, plugins: […]}`).
#[derive(Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct CniConflist<'t> {
    cni_version: &'t str,
    name: &'t str,
    plugins: Vec<CniPlugin<'t>>,
}

#[derive(Eq, PartialEq, serde::Serialize)]
#[serde(untagged)]
enum CniPlugin<'t> {
    Ptp(CniPtp<'t>),
    Portmap(CniPortmap),
}

/// The `ptp` (point-to-point) plugin configuring the pod interface.
#[derive(Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct CniPtp<'t> {
    r#type: &'t str,
    ipam: CniIpam<'t>,
    dns: CniDns,
    mtu: u32,
}

/// The `portmap` plugin, which DNATs node `hostPort`s to the pod.
#[derive(Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct CniPortmap {
    r#type: &'static str,
    capabilities: CniCapabilities,
}

#[derive(Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct CniCapabilities {
    port_mappings: bool,
}

#[derive(Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct CniIpam<'t> {
    r#type: &'t str,
    ranges: Vec<Vec<CniRange>>,
    routes: Vec<CniRoute>,
}

#[derive(Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct CniDns {
    nameservers: Vec<String>,
}

#[derive(Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct CniRange {
    subnet: String,
}

impl From<&cidr::IpCidr> for CniRange {
    fn from(cidr: &cidr::IpCidr) -> Self {
        Self {
            subnet: cidr.to_string(),
        }
    }
}

#[derive(Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct CniRoute {
    dst: String,
}

impl CniRoute {
    fn default_for(fam: cidr::Family) -> Self {
        let cidr = cidr::IpCidr::new(fam.unspecified_address(), 0)
            .expect("prefix len = 0 should be valid");
        Self {
            dst: cidr.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ptp() -> CniPtp<'static> {
        CniPtp {
            r#type: "ptp",
            ipam: CniIpam {
                r#type: "host-local",
                ranges: vec![vec![CniRange {
                    subnet: "10.244.0.0/24".into(),
                }]],
                routes: vec![CniRoute {
                    dst: "0.0.0.0/0".into(),
                }],
            },
            dns: CniDns {
                nameservers: vec!["10.244.0.1".into()],
            },
            mtu: 1420,
        }
    }

    /// Without `host_ports`, the config is the single `ptp` plugin (unchanged).
    #[test]
    fn cni_config_without_host_ports_is_single_plugin() {
        let v = serde_json::to_value(cni_config(false, ptp())).expect("serialize");
        assert_eq!(v["type"], "ptp");
        assert_eq!(v["ipam"]["type"], "host-local");
        assert!(v.get("plugins").is_none());
    }

    /// With `host_ports`, `portmap` is chained after `ptp`.
    #[test]
    fn cni_config_with_host_ports_chains_portmap() {
        let v = serde_json::to_value(cni_config(true, ptp())).expect("serialize");
        let plugins = v["plugins"].as_array().expect("plugins");
        assert_eq!(plugins.len(), 2);
        assert_eq!(plugins[0]["type"], "ptp");
        assert_eq!(plugins[1]["type"], "portmap");
        assert_eq!(plugins[1]["capabilities"]["portMappings"], true);
    }

    /// containerd keys the format off the extension, so a plugin list must be
    /// written to `*.conflist`, and the other-format file removed.
    #[test]
    fn cni_config_paths_switch_extension_with_host_ports() {
        let conf = "/etc/cni/net.d/10-knls.conf";
        let conflist = "/etc/cni/net.d/10-knls.conflist";
        assert_eq!(
            cni_config_paths(false, conf),
            (PathBuf::from(conf), PathBuf::from(conflist))
        );
        assert_eq!(
            cni_config_paths(true, conf),
            (PathBuf::from(conflist), PathBuf::from(conf))
        );
    }

    fn masq_pod_cidrs() -> Vec<IpCidr> {
        ["10.244.0.0/24", "fd00::/64"]
            .into_iter()
            .map(|cidr| cidr.parse().expect("cidr"))
            .collect()
    }

    #[test]
    fn masquerade_defaults_true_and_can_be_disabled() {
        let default: Config = serde_yaml::from_str("{}").expect("config");
        assert!(default.masquerade);

        let disabled: Config = serde_yaml::from_str("masquerade: false").expect("config");
        assert!(!disabled.masquerade);
    }

    #[test]
    fn masq_ranges_are_split_by_family() {
        let cidrs = masq_pod_cidrs();

        assert_eq!(
            pod_ranges4(&cidrs),
            vec![Ipv4Addr::new(10, 244, 0, 0)..=Ipv4Addr::new(10, 244, 0, 255)]
        );
        assert_eq!(
            pod_ranges6(&cidrs),
            vec![
                "fd00::".parse::<Ipv6Addr>().expect("ip")
                    ..="fd00:0:0:0:ffff:ffff:ffff:ffff"
                        .parse::<Ipv6Addr>()
                        .expect("ip")
            ]
        );
    }

    fn external_ip_entries() -> Vec<ExternalIpSnat> {
        vec![
            (
                "10.244.0.5".parse().expect("ip"),
                "203.0.113.5".parse().expect("ip"),
            ),
            (
                "fd00::1".parse().expect("ip"),
                "2001:db8::5".parse().expect("ip"),
            ),
        ]
    }

    /// The opt-out renders the same base chains and sets, but no snat rules.
    #[test]
    fn masq_opt_out_emits_no_rules() {
        let cidrs = masq_pod_cidrs();

        let enabled = render_connectivity_table(7, true, &cidrs, &[]);
        let disabled = render_connectivity_table(7, false, &cidrs, &[]);

        assert_eq!(enabled.chains[SNAT_CHAIN].rules.len(), 6);
        assert!(disabled.chains[SNAT_CHAIN].rules.is_empty());
        assert_eq!(enabled.chains[EXTERNAL_IPS_CHAIN].rules.len(), 1);
        assert_eq!(disabled.chains[EXTERNAL_IPS_CHAIN].rules.len(), 1);
    }

    /// A [`test_harness::System`] driving the connectivity table through a
    /// [`TableState`], like the watch loop does.
    struct MasqSystem {
        enabled: bool,
        state: TableState,
    }

    impl crate::nftables::test_harness::System for MasqSystem {
        fn new(table: String) -> Self {
            Self {
                enabled: true,
                state: TableState::new(table),
            }
        }

        fn custom(&mut self, id: usize) {
            self.enabled = id != 1;
        }

        async fn apply(&mut self, _table: &str) {
            self.state
                .update(render_connectivity_table(
                    7,
                    self.enabled,
                    &masq_pod_cidrs(),
                    &[],
                ))
                .await
                .expect("apply connectivity table");
        }
    }

    /// The old code-managed external-IP chain is deleted from the `knls` table.
    ///
    /// Requires `CAP_NET_ADMIN`; run with `sudo -E cargo test -- --ignored`.
    #[ignore = "requires CAP_NET_ADMIN and a real kernel"]
    #[tokio::test]
    async fn legacy_external_ips_chain_is_removed() {
        let table = "knls-test-legacy-ext";
        let _ = std::process::Command::new("nft")
            .args(["delete", "table", "inet", table])
            .stderr(std::process::Stdio::null())
            .status();
        crate::nftables::apply_script(format!(
            "table inet {table} {{\n\
             chain wireguard-external-ips {{\n\
             type nat hook postrouting priority srcnat; policy accept;\n\
             }}\n\
             }}"
        ))
        .await
        .expect("create legacy chain");

        remove_legacy_external_ips_chain(table).await;

        let listed = std::process::Command::new("nft")
            .args(["list", "chain", "inet", table, "wireguard-external-ips"])
            .output()
            .expect("nft");
        assert!(!listed.status.success(), "legacy chain still exists");

        let _ = std::process::Command::new("nft")
            .args(["delete", "table", "inet", table])
            .stderr(std::process::Stdio::null())
            .status();
    }

    /// Golden test for the pod-egress masquerade chain, including the opt-out.
    ///
    /// Requires `CAP_NET_ADMIN`; run with `sudo -E cargo test -- --ignored`.
    #[ignore = "requires CAP_NET_ADMIN and a real kernel"]
    #[tokio::test]
    async fn masq_golden() {
        crate::nftables::test_harness::golden_dir::<MasqSystem>(
            "test_assets/golden-nftables/wireguard-masq",
            "knls-test-wg-masq-",
        )
        .await;
    }

    /// A [`test_harness::System`] rendering the external-IP snat chain through
    /// the same connectivity table.
    struct ExternalIpsSystem {
        state: TableState,
    }

    impl crate::nftables::test_harness::System for ExternalIpsSystem {
        fn new(table: String) -> Self {
            Self {
                state: TableState::new(table),
            }
        }

        async fn apply(&mut self, _table: &str) {
            self.state
                .update(render_connectivity_table(
                    7,
                    false,
                    &masq_pod_cidrs(),
                    &external_ip_entries(),
                ))
                .await
                .expect("apply connectivity table");
        }
    }

    /// Golden test for the external-IP snat chain.
    ///
    /// Requires `CAP_NET_ADMIN`; run with `sudo -E cargo test -- --ignored`.
    #[ignore = "requires CAP_NET_ADMIN and a real kernel"]
    #[tokio::test]
    async fn external_ips_golden() {
        crate::nftables::test_harness::golden_dir::<ExternalIpsSystem>(
            "test_assets/golden-nftables/wireguard",
            "knls-test-wg-",
        )
        .await;
    }
}
