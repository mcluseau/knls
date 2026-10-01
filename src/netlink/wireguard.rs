use super::Netlink;
use cidr::IpCidr;
use eyre::{bail, eyre, Result};
use futures::StreamExt;
use log::debug;
use netlink_packet_core::{NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST};
use netlink_packet_generic::{
    ctrl::{nlas::GenlCtrlAttrs, GenlCtrl, GenlCtrlCmd},
    GenlMessage,
};
use netlink_packet_wireguard::{
    WireguardAddressFamily, WireguardAllowedIp, WireguardAllowedIpAttr, WireguardAttribute,
    WireguardCmd, WireguardMessage, WireguardPeer, WireguardPeerAttribute, WireguardPeerFlags,
};
use netlink_proto::sys::protocols::NETLINK_GENERIC;
use std::net::{IpAddr, SocketAddr};

/// A WireGuard key (public or private), as a raw 32-byte key.
pub type Key = [u8; 32];

/// A generic netlink message carrying a [`WireguardMessage`] payload.
pub type Message = GenlMessage<WireguardMessage>;

/// Generic netlink family name.
const FAMILY: &str = "wireguard";

/// A WireGuard peer, as configured on (or read from) an interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peer {
    pub public_key: Key,
    pub endpoint: Option<SocketAddr>,
    pub allowed_ips: Vec<IpCidr>,
}

/// The read-back configuration of a WireGuard interface.
#[derive(Clone, Debug, Default)]
pub struct Host {
    pub ifname: Option<String>,
    pub ifindex: Option<u32>,
    pub private_key: Option<Key>,
    pub listen_port: u16,
    pub peers: Vec<Peer>,
}

/// A handle to the WireGuard generic netlink family.
///
/// The family is resolved once from the generic netlink controller; all
/// subsequent requests reuse the same connection.
pub struct Wireguard {
    nl: Netlink<Message>,
    family_id: u16,
}

impl Wireguard {
    /// Resolve the family and open the netlink connection.
    pub async fn new() -> Result<Self> {
        let family_id = resolve_family_id().await?;
        debug!("wireguard generic netlink family id: {family_id}");
        let nl = Netlink::<Message>::new(NETLINK_GENERIC)?;
        Ok(Self { nl, family_id })
    }

    /// Send a request and collect every inner reply.
    ///
    /// `WG_CMD_SET_DEVICE` replies are acknowledgements only (no inner
    /// message), while `WG_CMD_GET_DEVICE` replies carry the device state,
    /// possibly split over several messages.
    async fn request(
        &self,
        flags: u16,
        cmd: WireguardCmd,
        attributes: Vec<WireguardAttribute>,
    ) -> Result<Vec<WireguardMessage>> {
        let payload = WireguardMessage { cmd, attributes };
        let mut genl = GenlMessage::from_payload(payload);
        genl.set_resolved_family_id(self.family_id);

        let mut message = NetlinkMessage::from(genl);
        message.header.flags = flags;

        let mut stream = self
            .nl
            .handle()
            .request(message, self.nl.dest())
            .map_err(|_| eyre!("failed to send wireguard netlink request"))?;

        let mut replies = Vec::new();
        while let Some(message) = stream.next().await {
            match message.payload {
                NetlinkPayload::InnerMessage(genl) => replies.push(genl.payload),
                // An acknowledgement holds no error code.
                NetlinkPayload::Error(err) if err.code.is_none() => {}
                NetlinkPayload::Error(err) => {
                    bail!("wireguard netlink error: {}", errno(&err));
                }
                NetlinkPayload::Done(done) if done.code == 0 => {}
                // A dump reports its error code in the message ending it.
                NetlinkPayload::Done(done) => {
                    bail!(
                        "wireguard netlink dump failed: {}",
                        std::io::Error::from_raw_os_error(-done.code)
                    );
                }
                NetlinkPayload::Noop => {}
                NetlinkPayload::Overrun(_) => bail!("wireguard netlink overrun"),
                _ => {}
            }
        }

        Ok(replies)
    }

    /// Read the whole configuration of `ifname`.
    pub async fn get(&self, ifname: &str) -> Result<Host> {
        let replies = self
            .request(
                NLM_F_REQUEST | NLM_F_DUMP,
                WireguardCmd::GetDevice,
                vec![WireguardAttribute::IfName(ifname.into())],
            )
            .await?;

        let mut host = Host::default();
        for message in replies {
            for attr in message.attributes {
                match attr {
                    WireguardAttribute::IfName(name) => host.ifname = Some(name),
                    WireguardAttribute::IfIndex(index) => host.ifindex = Some(index),
                    WireguardAttribute::PrivateKey(key) => host.private_key = Some(key),
                    WireguardAttribute::ListenPort(port) => host.listen_port = port,
                    WireguardAttribute::Peers(peers) => {
                        for peer in peers {
                            if let Some(peer) = peer_from_attrs(&peer.0) {
                                push_peer(&mut host.peers, peer);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        Ok(host)
    }

    /// Set the device listen port and private key, leaving peers untouched.
    pub async fn set_device(&self, ifname: &str, listen_port: u16, private_key: Key) -> Result<()> {
        let attributes = vec![
            WireguardAttribute::IfName(ifname.into()),
            WireguardAttribute::PrivateKey(private_key),
            WireguardAttribute::ListenPort(listen_port),
        ];
        self.request(
            NLM_F_REQUEST | NLM_F_ACK,
            WireguardCmd::SetDevice,
            attributes,
        )
        .await?;
        Ok(())
    }

    /// Add or update a peer, replacing its allowed IPs.
    pub async fn set_peer(&self, ifname: &str, peer: &Peer) -> Result<()> {
        let mut attrs = vec![
            WireguardPeerAttribute::PublicKey(peer.public_key),
            WireguardPeerAttribute::Flags(WireguardPeerFlags::ReplaceAllowedIps),
        ];
        if let Some(endpoint) = peer.endpoint {
            attrs.push(WireguardPeerAttribute::Endpoint(endpoint));
        }
        attrs.push(WireguardPeerAttribute::AllowedIps(
            peer.allowed_ips
                .iter()
                .filter_map(cidr_to_allowed_ip)
                .collect(),
        ));

        let attributes = vec![
            WireguardAttribute::IfName(ifname.into()),
            WireguardAttribute::Peers(vec![WireguardPeer(attrs)]),
        ];
        self.request(
            NLM_F_REQUEST | NLM_F_ACK,
            WireguardCmd::SetDevice,
            attributes,
        )
        .await?;
        Ok(())
    }

    /// Remove a peer by public key.
    pub async fn del_peer(&self, ifname: &str, public_key: Key) -> Result<()> {
        let peer = WireguardPeer(vec![
            WireguardPeerAttribute::PublicKey(public_key),
            WireguardPeerAttribute::Flags(WireguardPeerFlags::RemoveMe),
        ]);
        let attributes = vec![
            WireguardAttribute::IfName(ifname.into()),
            WireguardAttribute::Peers(vec![peer]),
        ];
        self.request(
            NLM_F_REQUEST | NLM_F_ACK,
            WireguardCmd::SetDevice,
            attributes,
        )
        .await?;
        Ok(())
    }
}

/// Render a netlink error without echoing the request (which may hold keys).
fn errno(err: &netlink_packet_core::ErrorMessage) -> String {
    err.code
        .map(|code| std::io::Error::from_raw_os_error(-code.get()).to_string())
        .unwrap_or_else(|| "unknown netlink error".into())
}

/// Resolve the dynamic id of the `wireguard` generic netlink family.
async fn resolve_family_id() -> Result<u16> {
    let nl = Netlink::<GenlMessage<GenlCtrl>>::new(NETLINK_GENERIC)?;
    let mut message = NetlinkMessage::from(GenlMessage::from_payload(GenlCtrl {
        cmd: GenlCtrlCmd::GetFamily,
        nlas: vec![GenlCtrlAttrs::FamilyName(FAMILY.into())],
    }));
    message.header.flags = NLM_F_REQUEST | NLM_F_ACK;

    let mut stream = (nl.handle().request(message, nl.dest()))
        .map_err(|e| eyre!("failed to send generic netlink control request: {e}"))?;

    while let Some(message) = stream.next().await {
        if let NetlinkPayload::InnerMessage(genl) = message.payload {
            for nla in &genl.payload.nlas {
                if let GenlCtrlAttrs::FamilyId(id) = nla {
                    return Ok(*id);
                }
            }
        }
    }

    bail!("generic netlink family {FAMILY:?} not found")
}

fn peer_from_attrs(attrs: &[WireguardPeerAttribute]) -> Option<Peer> {
    let mut public_key = None;
    let mut endpoint = None;
    let mut allowed_ips = Vec::new();

    for attr in attrs {
        match attr {
            WireguardPeerAttribute::PublicKey(key) => public_key = Some(*key),
            WireguardPeerAttribute::Endpoint(ep) => endpoint = Some(*ep),
            WireguardPeerAttribute::AllowedIps(ips) => {
                allowed_ips.extend(ips.iter().filter_map(allowed_ip_to_cidr));
            }
            _ => {}
        }
    }

    Some(Peer {
        public_key: public_key?,
        endpoint,
        allowed_ips,
    })
}

/// Merge a peer split over several messages into the matching existing one.
fn push_peer(peers: &mut Vec<Peer>, peer: Peer) {
    if let Some(existing) = (peers.iter_mut()).find(|p| p.public_key == peer.public_key) {
        existing.allowed_ips.extend(peer.allowed_ips);
        if peer.endpoint.is_some() {
            existing.endpoint = peer.endpoint;
        }
    } else {
        peers.push(peer);
    }
}

fn allowed_ip_to_cidr(allowed_ip: &WireguardAllowedIp) -> Option<IpCidr> {
    let mut addr = None;
    let mut cidr = None;
    for attr in &allowed_ip.0 {
        match attr {
            WireguardAllowedIpAttr::IpAddr(ip) => addr = Some(*ip),
            WireguardAllowedIpAttr::Cidr(len) => cidr = Some(*len),
            _ => {}
        }
    }
    IpCidr::new(addr?, cidr?).ok()
}

fn cidr_to_allowed_ip(cidr: &IpCidr) -> Option<WireguardAllowedIp> {
    let (addr, len) = match cidr {
        IpCidr::V4(c) => (IpAddr::V4(c.first_address()), c.network_length()),
        IpCidr::V6(c) => (IpAddr::V6(c.first_address()), c.network_length()),
    };
    let family = if addr.is_ipv4() {
        WireguardAddressFamily::Ipv4
    } else {
        WireguardAddressFamily::Ipv6
    };
    Some(WireguardAllowedIp(vec![
        WireguardAllowedIpAttr::Family(family),
        WireguardAllowedIpAttr::IpAddr(addr),
        WireguardAllowedIpAttr::Cidr(len),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn allowed_ip_roundtrip() {
        let cidr: IpCidr = "10.0.0.0/24".parse().expect("valid cidr");
        let allowed = cidr_to_allowed_ip(&cidr).expect("convertible");
        assert_eq!(allowed_ip_to_cidr(&allowed), Some(cidr));
    }

    #[test]
    fn cidr_uses_network_address() {
        let cidr: IpCidr = "10.0.0.0/24".parse().expect("valid cidr");
        let allowed = cidr_to_allowed_ip(&cidr).expect("convertible");
        let addr = allowed
            .0
            .iter()
            .find_map(|a| match a {
                WireguardAllowedIpAttr::IpAddr(ip) => Some(*ip),
                _ => None,
            })
            .expect("has address");
        assert_eq!(addr, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)));
    }

    #[test]
    fn peers_with_same_key_are_merged() {
        let key = [1u8; 32];
        let mut peers = Vec::new();
        push_peer(
            &mut peers,
            Peer {
                public_key: key,
                endpoint: None,
                allowed_ips: vec!["10.0.0.0/24".parse().expect("valid cidr")],
            },
        );
        push_peer(
            &mut peers,
            Peer {
                public_key: key,
                endpoint: None,
                allowed_ips: vec!["10.0.1.0/24".parse().expect("valid cidr")],
            },
        );

        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].allowed_ips.len(), 2);
    }

    #[test]
    fn wireguard_family_name_is_stable() {
        use netlink_packet_generic::GenlFamily;
        assert_eq!(WireguardMessage::family_name(), FAMILY);
    }
}
