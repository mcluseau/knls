use defguard_wireguard_rs::{self as wg, net::IpAddrMask, netlink};
use eyre::Result;
use futures::TryStreamExt;
use log::{debug, error, info, warn};
use netlink_packet_route::{
    address::AddressAttribute,
    link::LinkAttribute::Mtu,
    route::{RouteAddress, RouteHeader},
};
use serde_json::json;
use std::collections::BTreeMap as Map;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use tokio::fs;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::state::wireguard::{Key, decode_key, encode_key};
use crate::{actions, change, patch_params};

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

fn nodes_from_state(
    state: &crate::state::State,
) -> Option<Map<String, crate::state::wireguard::Node>> {
    if !state.wg_nodes.is_ready() {
        return None;
    }
    let nodes = state
        .wg_nodes
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    Some(nodes)
}

pub async fn watch(
    ctx: Arc<crate::Context>,
    cfg: Config,
    mut watcher: crate::watcher::Watcher,
) -> Result<()> {
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
        links.try_next().await?.unwrap()
    };
    let link_id = link.header.index;

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

    loop {
        let Some(nodes) = watcher.next(nodes_from_state).await? else {
            continue;
        };

        let Some(my_node) = nodes.get(node_name) else {
            continue;
        };

        let vpn_ip = my_node.pod_cidrs.first().map(|cidr| match cidr.ip {
            IpAddr::V4(ip) => IpAddr::V4(Ipv4Addr::from_bits(ip.to_bits() + 1)),
            IpAddr::V6(ip) => IpAddr::V6(Ipv6Addr::from_bits(ip.to_bits() + 1)),
        });

        // interface IP
        {
            let mut found = false;
            let mut addrs = (rtnl.address().get().set_link_index_filter(link_id)).execute();
            while let Some(addr) = addrs.try_next().await? {
                let Some(ip) = addr.attributes.iter().find_map(|attr| match attr {
                    AddressAttribute::Address(ip) => Some(ip),
                    _ => None,
                }) else {
                    continue;
                };

                if Some(ip) == vpn_ip.as_ref() {
                    found = true;
                } else {
                    rtnl.address().del(addr).execute().await?;
                }
            }

            if !found && let Some(ip) = vpn_ip {
                let prefix_len = match ip {
                    IpAddr::V4(_) => 32u8,
                    IpAddr::V6(_) => 128u8,
                };
                rtnl.address()
                    .add(link_id, ip, prefix_len)
                    .execute()
                    .await?;
            }
        }

        // CNI config
        let cni_config = CniConfig {
            cni_version: "0.3.1",
            name: "knls",
            r#type: "ptp",
            ipam: CniIpam {
                r#type: "host-local",
                ranges: vec![
                    (my_node.pod_cidrs.iter())
                        .map(|cidr| CniRange {
                            subnet: cidr.to_string(),
                        })
                        .collect(),
                ],
                routes: vec![CniRoute {
                    dst: "0.0.0.0/0".to_string(),
                }],
            },
            dns: CniDns {
                nameservers: vpn_ip.iter().map(|ip| ip.to_string()).collect(),
            },
            mtu: (link.attributes.iter())
                .find_map(|attr| match attr {
                    Mtu(mtu) => Some(*mtu),
                    _ => None,
                })
                .unwrap_or(1420),
        };

        if prev_cni_config.as_ref() != Some(&cni_config) {
            let value = serde_json::to_vec(&cni_config)?;
            std::fs::write(&cni_config_path, value)?;
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
                .patch(&node_name, &patch_params(), &Patch::Strategic(&patch))
                .await
            {
                if !warned_about_pubkey {
                    let patch_str = serde_json::to_string(&patch).unwrap();
                    error!(
                        "failed to update node's pubkey: {e}\nkubectl patch node {node_name} -p {patch_str:?}"
                    );
                    warned_about_pubkey = true;
                }
            }
        }

        let listen_port = my_node.listen_port.unwrap_or(default_port);
        if current_listen_port != Some(listen_port) || current_pubkey != Some(pubkey) {
            // TODO we read the whole interface config just to allow set_host to work,
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
                allowed_ips: node.pod_cidrs.clone(),
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
                netlink::set_peer(&ifname, &peer.clone().to_wg_peer(pubkey))?;
                change.set(peer);
            }

            for route in &node.pod_cidrs {
                if let Some(change) = routes.check(route.clone(), &()) {
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
            let pubkey = &wg::key::Key::new(removed_peer.clone());
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

struct OifRoutes {
    oif: u32,
    default_hdr: RouteHeader,
    rtnl: rtnetlink::Handle,
}
impl OifRoutes {
    async fn list(&self) -> eyre::Result<Vec<IpAddrMask>> {
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

                if !oif.is_some_and(|oif| oif == self.oif) {
                    continue;
                };

                let dest = match dest {
                    Some(RouteAddress::Inet(addr)) => IpAddr::V4(addr),
                    Some(RouteAddress::Inet6(addr)) => IpAddr::V6(addr),
                    _ => {
                        continue;
                    }
                };

                let dest = IpAddrMask::new(dest.into(), route.header.destination_prefix_length);
                routes.push(dest);
            }
        }
        Ok(routes)
    }

    async fn add(&self, dest: &IpAddrMask) -> eyre::Result<()> {
        let msg = self.dest_route_msg(dest);
        self.rtnl.route().add(msg).execute().await?;
        Ok(())
    }

    async fn del(&self, dest: &IpAddrMask) -> eyre::Result<()> {
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

    fn dest_route_msg(&self, dest: &IpAddrMask) -> netlink_packet_route::route::RouteMessage {
        use rtnetlink::RouteMessageBuilder as B;

        match dest.ip {
            IpAddr::V4(ip) => {
                self.route_msg(B::<Ipv4Addr>::new().destination_prefix(ip, dest.cidr))
            }
            IpAddr::V6(ip) => {
                self.route_msg(B::<Ipv6Addr>::new().destination_prefix(ip, dest.cidr))
            }
        }
    }
}

async fn get_private_key(key_path: &String) -> Result<Key> {
    match fs::read(key_path).await {
        Ok(encoded_key) => decode_key(&encoded_key.trim_ascii()),
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
    fn to_wg_peer(self, pubkey: Key) -> wg::host::Peer {
        wg::host::Peer {
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

#[derive(Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct CniRoute {
    dst: String,
}
