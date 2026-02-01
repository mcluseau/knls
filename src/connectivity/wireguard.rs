use cidr::{IpCidr, IpInet};
use defguard_wireguard_rs::{self as wg, net::IpAddrMask, netlink};
use eyre::{Result, format_err};
use futures::TryStreamExt;
use k8s_openapi::api::core::v1 as core;
use log::{debug, error, info, warn};
use netlink_packet_route::{
    address::{AddressAttribute, AddressMessage},
    link::LinkAttribute::Mtu,
    route::{RouteAddress, RouteHeader},
};
use serde_json::json;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use tokio::fs;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::state::wireguard::{Key, Node, decode_key, encode_key};
use crate::{actions, change, kube_watch::EventReceiver, patch_params};

crate::multimap!(
    State{
        nodes: Node(core::Node) => Node,
    }
);

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct Config {
    /// Activate node connectivity through wireguard using this interface
    #[serde(default = "defaults::ifname")]
    ifname: String,

    /// Wireguard private key file (will be created as needed).
    #[serde(default = "defaults::key_path")]
    key_path: String,

    /// CNI config path
    #[serde(default = "defaults::cni_config")]
    cni_config: String,

    #[serde(default)]
    on_create: Vec<crate::actions::Action>,

    #[serde(default)]
    manual_node: Option<Node>,
}

mod defaults {
    pub fn ifname() -> String {
        "kwg".into()
    }
    pub fn key_path() -> String {
        "/var/lib/knls/wireguard.key".into()
    }
    pub fn cni_config() -> String {
        "/etc/cni/net.d/10-knls.conf".into()
    }
}

pub async fn watch(ctx: Arc<crate::Context>, cfg: Config, mut events: EventReceiver) -> Result<()> {
    let node_name = ctx.node_name.as_str();
    let kube = ctx.kube.clone();

    let ifname = cfg.ifname;
    let key_path = cfg.key_path;
    let cni_config_path = cfg.cni_config;

    let default_port = 51820u16;

    let (conn, rtnl, _) = rtnetlink::new_connection()?;
    tokio::spawn(conn);

    netlink::create_interface(&ifname)?;
    actions::run_event(module_path!(), "on_create", &cfg.on_create).await?;

    let link = {
        let mut links = rtnl.link().get().match_name(ifname.clone()).execute();
        links
            .try_next()
            .await?
            .expect("at least one link should exist")
    };
    let link_id = link.header.index;

    let if_addrs = IfAddrs {
        id: link_id,
        rtnl: rtnl.clone(),
    };

    let private_key = get_private_key(&key_path).await?;
    let pubkey: PublicKey = (&StaticSecret::from(private_key)).into();

    // load existing peers
    let mut current_listen_port;
    let mut current_pubkey;
    let mut peers = change::Tracker::new();

    {
        let host = netlink::get_host(&ifname)?;
        current_listen_port = Some(host.listen_port);
        current_pubkey = host.private_key.map(|k| PublicKey::from(k.as_array()));

        for (key, raw_peer) in host.peers {
            debug!("existing peer: {key}");
            let key = Key::from(key.as_array());
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

    // load existing routes
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

    for dest in oif_routes.list().await? {
        debug!("existing route: {dest}");
        if let Some(change) = routes.check(dest, &()) {
            change.set(());
        }
    }
    routes.update_done();

    // start watch
    let mut warned_about_pubkey = false;

    let mut prev_cni_config = None;

    let mut state = State::new();

    loop {
        let Some(updated) = state.ingest_events(&mut events).await else {
            return Ok(());
        };
        if !updated || !state.is_ready() {
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
        let cni_config = CniConfig {
            cni_version: "0.3.1",
            name: "knls",
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

        if cfg.manual_node.is_none() {
            if prev_cni_config.as_ref() != Some(&cni_config) {
                let value = serde_json::to_vec(&cni_config)?;
                std::fs::write(&cni_config_path, value).map_err(|e| {
                    format_err!("failed to write CNI config ({cni_config_path}): {e}")
                })?;
                prev_cni_config = Some(cni_config);
            }

            // publish public key
            if my_node.pubkey != Some(*pubkey.as_bytes()) {
                info!("updating node's pubkey");
                use crate::state::wireguard::ANN_PUBKEY;
                let pubkey = wg::key::Key::new(*pubkey.as_bytes()).to_string();
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
            // FIXME? we read the whole interface config just to allow set_host to work,
            // which is much more than what we want to update.
            let mut host = netlink::get_host(&ifname)?;
            host.listen_port = listen_port;
            host.private_key = Some(wg::key::Key::new(private_key));
            netlink::set_host(&ifname, &host)?;

            current_listen_port = Some(listen_port);
            current_pubkey = Some(pubkey);
        }

        for (name, node) in nodes.iter().filter(|(name, _)| **name != node_name) {
            let Some(pubkey) = node.pubkey else {
                continue;
            };

            let peer = Peer {
                endpoint: node.get_endpoint_from(&my_node.zone, default_port),
                allowed_ips: (node.pod_cidrs.iter())
                    .map(|cidr| IpAddrMask::new(cidr.first_address(), cidr.network_length()))
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
                netlink::set_peer(&ifname, &peer.clone().into_wg_peer(pubkey))?;
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
            let pubkey = &wg::key::Key::new(*removed_peer);
            info!("deleting peer {pubkey}");
            netlink::delete_peer(&ifname, pubkey)?;
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
    async fn list(&self) -> eyre::Result<Vec<IpCidr>> {
        use rtnetlink::RouteMessageBuilder as B;

        let mut routes = Vec::new();

        for route_filter in [
            self.route_msg(B::<Ipv4Addr>::new()),
            self.route_msg(B::<Ipv6Addr>::new()),
        ]
        .into_iter()
        {
            use netlink_packet_route::route::RouteAttribute;

            let mut route_list = self.rtnl.route().get(route_filter).execute();
            while let Some(route) = route_list.try_next().await? {
                if route.header.table != self.default_hdr.table
                    || route.header.protocol != self.default_hdr.protocol
                    || route.header.scope != self.default_hdr.scope
                    || route.header.kind != self.default_hdr.kind
                {
                    continue;
                }

                let mut oif = None;
                let mut dest = None;

                for attr in route.attributes {
                    match attr {
                        RouteAttribute::Oif(i) => oif = Some(i),
                        RouteAttribute::Destination(d) => dest = Some(d),
                        _ => {}
                    }
                }

                if oif != Some(self.oif) {
                    continue;
                };

                let dest = match dest {
                    Some(RouteAddress::Inet(addr)) => IpAddr::V4(addr),
                    Some(RouteAddress::Inet6(addr)) => IpAddr::V6(addr),
                    _ => {
                        continue;
                    }
                };

                let dest = IpCidr::new(dest, route.header.destination_prefix_length)
                    .expect("kernel IpCidr should be valid");
                routes.push(dest);
            }
        }
        Ok(routes)
    }

    async fn add(&self, dest: &IpCidr) -> eyre::Result<()> {
        let msg = self.dest_route_msg(dest);
        self.rtnl.route().add(msg).execute().await?;
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
    allowed_ips: Vec<wg::net::IpAddrMask>,
}
impl Peer {
    fn into_wg_peer(self, pubkey: Key) -> wg::peer::Peer {
        wg::peer::Peer {
            public_key: wg::key::Key::new(pubkey),
            endpoint: self.endpoint,
            allowed_ips: self.allowed_ips,
            ..Default::default()
        }
    }
}

#[derive(Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct CniConfig<'t> {
    cni_version: &'t str,
    name: &'t str,
    r#type: &'t str,
    ipam: CniIpam<'t>,
    dns: CniDns,
    mtu: u32,
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
