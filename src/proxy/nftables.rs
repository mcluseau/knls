use cidr::IpCidr;
use eyre::Result;
use log::{debug, error};
use netlink_packet_netfilter::nftables::{Register, SetAttribute, SetFlags};
use std::collections::{BTreeMap as Map, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::RangeInclusive;
use std::sync::Arc;

use crate::nftables::{
    chain::{self, ChainType, InetHookNumber, Rule},
    rules,
    rules::{Dir, Dnat, Family, Verdict as RuleVerdict},
    set::Verdict,
    table_sync::{BaseChain, ChainSync, SetMeta, SetSync, TableState, TableSync},
    userdata,
};

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct Config {
    /// nftables table's name
    #[serde(default = "default_table")]
    table: String,
    /// Disable node ports (since they are forced for load balancers at API level for non-technical reasons)
    #[serde(default)]
    disable_nodeports: bool,
}
fn default_table() -> String {
    "kube-proxy".into()
}

use super::conntrack;
use crate::kube_watch::{EventReceiver, ingest_events};
use crate::state::{
    LocalEndpoint, LocalEndpointSlice, Node, ProtoPort, Protocol, SessionAffinity, State, keys,
    proxy,
};

const MASQ_MARK: u32 = 1 << 14;

const SERVICE_IPS: &str = "service_ips";
const SERVICE_NODEPORTS: &str = "service_nodeports";
const NEED_MASQ_V4: &str = "need_masquerade";
const NEED_MASQ_V6: &str = "need_masquerade6";

pub async fn watch(ctx: Arc<crate::Context>, cfg: Config, mut events: EventReceiver) -> Result<()> {
    let mut table = TableState::new(cfg.table.clone());
    let mut state = State::new(ctx.node_name.clone());

    let mut ct_state = conntrack::State::new().await?;

    loop {
        use std::ops::ControlFlow::*;
        match ingest_events(&mut events, |e| {
            let mut updated = false;
            updated |= state.ingest(&e);
            updated |= ct_state.ingest(&e);
            updated
        })
        .await
        {
            Some(Break(_)) => break,
            Some(Continue(_)) => continue,
            None => {}
        };
        if !state.is_ready() {
            continue;
        }

        let Some(my_node) = state.my_node.get() else {
            continue;
        };
        let Some(svc) = proxy::from_state(&state, cfg.disable_nodeports) else {
            continue;
        };

        if let Err(e) = table.update(render(my_node, &svc)).await {
            error!("proxy table update failed: {e}");
        }

        if !ct_state.is_ready() {
            debug!("ct not ready");
            continue;
        }
        if let Err(e) = conntrack::cleanup(&ct_state).await {
            error!("conntrack cleanup failed: {e}");
        }
    }

    Ok(())
}

fn obj_chain(prefix: &str, key: &keys::Object) -> String {
    format!("{prefix}_{}_{}", key.namespace, key.name)
}

fn svc_chain(key: &keys::Object) -> String {
    obj_chain("svc", key)
}

fn svc_chain_ext(key: &keys::Object, svc: &proxy::Service) -> String {
    let mut base = svc_chain(key);
    if svc.needs_ext_chain() {
        base.push_str("_ext")
    }
    base
}

fn affinity_set(key: &keys::Object, ip_version: char) -> String {
    obj_chain(&format!("affinity{ip_version}"), key)
}

// ---------------------------------------------------------------------------
// TableSync rendering (pure netlink)
// ---------------------------------------------------------------------------

const SERVICE_IPS_COMMENT: &str = "ClusterIP, ExternalIP and LoadBalancer IP traffic";
const SERVICE_NODEPORTS_COMMENT: &str = "NodePort traffic";
/// `NFT_DATA_VERDICT`: the data type of a verdict map.
const NFT_DATA_VERDICT: u32 = 0xffffff00;

/// `TYPE_INTEGER` (`nftables/include/datatype.h`): nft's unnamed integer
/// datatype, the key type a `numgen` result is stored as.
const TYPE_INTEGER: u32 = 4;

/// The metadata of a per-service endpoint dispatch map: keyed by the `numgen`
/// result (`typeof numgen random mod 1 : verdict`).
fn dispatch_map_meta() -> SetMeta {
    SetMeta {
        flags: SetFlags::Map,
        attributes: vec![
            SetAttribute::KeyType(TYPE_INTEGER),
            SetAttribute::KeyLen(4),
            SetAttribute::DataType(NFT_DATA_VERDICT),
            SetAttribute::DataLen(16),
            SetAttribute::UserData(userdata::numgen_verdict_map(1)),
        ],
        comment: None,
    }
}

/// Renders the whole proxy table for `cfg` as a target [`TableSync`].
pub fn render(my_node: &Node, cfg: &proxy::State) -> TableSync {
    Builder::new(my_node, cfg).build()
}

fn proto_num(protocol: Protocol) -> u8 {
    match protocol {
        Protocol::TCP => 6,
        Protocol::UDP => 17,
        Protocol::SCTP => 132,
    }
}

fn ip_octets(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(ip) => ip.octets().to_vec(),
    }
}

/// The `dnat`/`redirect` rule for endpoint `ip` on service port `port`,
/// targeting `target` (the slice's target port).
fn dnat_rule(
    ip: IpAddr,
    port: &ProtoPort,
    target: u16,
    node_port: bool,
    my_ips: &[IpAddr],
) -> Rule {
    let (proto, port) = port.protocol_port();
    let family = match ip {
        IpAddr::V4(_) => Family::V4,
        IpAddr::V6(_) => Family::V6,
    };
    let target = if my_ips.contains(&ip) {
        Dnat::Redirect(target)
    } else {
        Dnat::Masquerade {
            ip,
            port: target,
            mark: MASQ_MARK,
        }
    };
    rules::dnat_rule(family, proto_num(proto), port, node_port, target)
}

/// Adds the `need_masquerade{,6}` elements for a node-local endpoint whose IP is
/// not one of the node's own IPs (`ips` are the service's cluster or external
/// IPs).
fn add_need_masq<'t>(
    v4: &mut BTreeSet<(Ipv4Addr, Ipv4Addr, Ipv4Addr)>,
    v6: &mut BTreeSet<(Ipv6Addr, Ipv6Addr, Ipv6Addr)>,
    ep: &LocalEndpoint,
    ips: impl Iterator<Item = &'t IpAddr>,
    my_ips: &[IpAddr],
) {
    for svc_ip in ips {
        match svc_ip {
            IpAddr::V4(svc_ip) => {
                let Some(ep_ip) = ep.ipv4 else {
                    continue;
                };
                if my_ips.contains(&IpAddr::V4(ep_ip)) {
                    continue;
                }
                v4.insert((ep_ip, ep_ip, *svc_ip));
            }
            IpAddr::V6(svc_ip) => {
                let Some(ep_ip) = ep.ipv6 else {
                    continue;
                };
                if my_ips.contains(&IpAddr::V6(ep_ip)) {
                    continue;
                }
                v6.insert((ep_ip, ep_ip, *svc_ip));
            }
        }
    }
}

/// Accumulates the sets and chains of one proxy table.
struct Builder<'a> {
    my_node: &'a Node,
    cfg: &'a proxy::State,
    sets: Map<String, SetSync>,
    chains: Map<String, ChainSync>,
}

impl<'a> Builder<'a> {
    fn new(my_node: &'a Node, cfg: &'a proxy::State) -> Self {
        Self {
            my_node,
            cfg,
            sets: Map::new(),
            chains: Map::new(),
        }
    }

    fn build(mut self) -> TableSync {
        self.service_ips_map();
        self.service_nodeports_map();
        self.need_masquerade();

        let cfg = self.cfg;
        for (key, svc) in cfg.iter() {
            self.service(key, svc);
        }

        self.dispatch();
        self.hooks();

        TableSync {
            chains: self.chains,
            sets: self.sets,
        }
    }

    fn add_chain(&mut self, name: impl Into<String>, rules: Vec<Rule>, anon_sets: Vec<SetSync>) {
        self.chains.insert(
            name.into(),
            ChainSync {
                base: None,
                rules,
                anon_sets,
            },
        );
    }

    fn add_base_chain(
        &mut self,
        name: &str,
        chain_type: ChainType,
        hook: InetHookNumber,
        priority: i32,
        rules: Vec<Rule>,
    ) {
        self.chains.insert(
            name.into(),
            ChainSync {
                base: Some(BaseChain {
                    chain_type,
                    hook,
                    priority,
                    policy: chain::ACCEPT,
                }),
                rules,
                anon_sets: Vec::new(),
            },
        );
    }

    fn service_ips_map(&mut self) {
        let mut entries = Vec::new();
        for (key, svc) in self
            .cfg
            .iter()
            .filter(|(_, svc)| !svc.cluster_ips.is_empty())
        {
            let svc_chain = svc_chain(key);
            let svc_chain_ext = svc_chain_ext(key, svc);

            for (port, _) in &svc.ports {
                let (proto, port) = port.protocol_port();
                let proto = proto_num(proto);
                for ip in &svc.cluster_ips {
                    if let IpAddr::V4(ip) = ip {
                        entries.push(((*ip, proto, port), Verdict::Goto(svc_chain.clone())));
                    }
                }
                for ip in &svc.external_ips {
                    if let IpAddr::V4(ip) = ip {
                        entries.push(((*ip, proto, port), Verdict::Goto(svc_chain_ext.clone())));
                    }
                }
            }
        }

        self.sets.insert(
            SERVICE_IPS.into(),
            SetSync::verdict_map(entries, Some(SERVICE_IPS_COMMENT.into())),
        );
    }

    fn service_nodeports_map(&mut self) {
        let mut entries = Vec::new();
        for (key, svc) in self
            .cfg
            .iter()
            .filter(|(_, svc)| !svc.cluster_ips.is_empty())
        {
            let svc_chain_ext = svc_chain_ext(key, svc);
            for (port, _) in &svc.node_ports {
                let (proto, port) = port.protocol_port();
                entries.push((
                    (proto_num(proto), port),
                    Verdict::Goto(svc_chain_ext.clone()),
                ));
            }
        }

        self.sets.insert(
            SERVICE_NODEPORTS.into(),
            SetSync::verdict_map(entries, Some(SERVICE_NODEPORTS_COMMENT.into())),
        );
    }

    fn need_masquerade(&mut self) {
        let mut v4 = BTreeSet::new();
        let mut v6 = BTreeSet::new();

        for (_, svc) in self
            .cfg
            .iter()
            .filter(|(_, svc)| !svc.cluster_ips.is_empty())
        {
            for ep in svc.internal_endpoints().filter(|ep| ep.node_local) {
                add_need_masq(
                    &mut v4,
                    &mut v6,
                    ep,
                    svc.cluster_ips.iter(),
                    &self.my_node.ips,
                );
            }
            for ep in svc.external_endpoints().filter(|ep| ep.node_local) {
                add_need_masq(
                    &mut v4,
                    &mut v6,
                    ep,
                    svc.external_ips.iter(),
                    &self.my_node.ips,
                );
            }
        }

        self.sets
            .insert(NEED_MASQ_V4.into(), SetSync::simple(v4, None));
        self.sets
            .insert(NEED_MASQ_V6.into(), SetSync::simple(v6, None));
    }

    fn dispatch(&mut self) {
        self.add_chain(
            "dispatch",
            vec![
                rules::ip_daddr_ip_proto_dport_vmap(SERVICE_IPS),
                rules::fib_daddr_local_ip_proto_dport_vmap(SERVICE_NODEPORTS),
            ],
            Vec::new(),
        );
    }

    fn hooks(&mut self) {
        self.add_base_chain(
            "a_hook_dnat_prerouting",
            ChainType::Nat,
            InetHookNumber::PreRouting,
            0,
            vec![vec![rules::jump("dispatch")]],
        );
        self.add_base_chain(
            "a_hook_dnat_output",
            ChainType::Nat,
            InetHookNumber::LocalOut,
            0,
            vec![vec![rules::jump("dispatch")]],
        );

        let mut post = vec![
            rules::ct_masquerade(Family::V4, NEED_MASQ_V4),
            rules::ct_masquerade(Family::V6, NEED_MASQ_V6),
        ];

        for cidr in &self.my_node.pod_cidrs {
            if let Ok(cidr) = cidr.parse::<IpCidr>() {
                let (family, prefix, network) = match &cidr {
                    IpCidr::V4(c) => (
                        Family::V4,
                        c.network_length(),
                        c.first_address().octets().to_vec(),
                    ),
                    IpCidr::V6(c) => (
                        Family::V6,
                        c.network_length(),
                        c.first_address().octets().to_vec(),
                    ),
                };
                for dir in [Dir::Src, Dir::Dst] {
                    let mut rule = rules::ip_prefix(family, dir, prefix, network.clone(), false);
                    rule.push(rules::verdict(RuleVerdict::Return));
                    post.push(rule);
                }
            }
        }

        let mut mark_return = rules::mark_and_eq_zero(Register::Reg1, MASQ_MARK);
        mark_return.push(rules::verdict(RuleVerdict::Return));
        post.push(mark_return);

        let mut masq = rules::mark_xor(Register::Reg1, MASQ_MARK);
        masq.push(rules::masquerade(true));
        post.push(masq);

        self.add_base_chain(
            "a_hook_dnat_postrouting",
            ChainType::Nat,
            InetHookNumber::PostRouting,
            0,
            post,
        );
    }

    fn service(&mut self, key: &keys::Object, svc: &proxy::Service) {
        self.service_slices(key, svc, false, &svc.internal_slices);
        if svc.needs_ext_chain() {
            self.service_slices(key, svc, true, svc.external_slices());
        }
    }

    /// Renders one endpoint-dispatch map (named after the chain it feeds) and
    /// its chain, for either the internal or the external slices.
    fn service_slices(
        &mut self,
        key: &keys::Object,
        svc: &proxy::Service,
        ext: bool,
        slices: &[LocalEndpointSlice],
    ) {
        let svc_chain = if ext {
            svc_chain_ext(key, svc)
        } else {
            svc_chain(key)
        };

        let affinity = match svc.session_affinity {
            SessionAffinity::ClientIP { timeout } => Some(timeout),
            SessionAffinity::None => None,
        };
        if let Some(timeout) = affinity {
            let ms = timeout as u64 * 1000;
            let meta4 = SetMeta::from_elem::<(Ipv4Addr, Ipv4Addr)>(None).with_timeout(ms);
            self.sets.entry(affinity_set(key, '4')).or_insert_with(|| {
                SetSync::simple_with_meta::<(Ipv4Addr, Ipv4Addr)>(meta4, std::iter::empty())
            });
            let meta6 = SetMeta::from_elem::<(Ipv6Addr, Ipv6Addr)>(None).with_timeout(ms);
            self.sets.entry(affinity_set(key, '6')).or_insert_with(|| {
                SetSync::simple_with_meta::<(Ipv6Addr, Ipv6Addr)>(meta6, std::iter::empty())
            });
        }

        let mut anon_sets = Vec::new();
        let mut pre_rules: Vec<Rule> = Vec::new();
        if ext && let Some(allow) = &svc.external_allow_list {
            pre_rules.extend(allow_list_rules(&mut anon_sets, allow));
        }

        let mut entries: Vec<(u32, Verdict)> = Vec::new();
        let mut n4 = 0u32;
        let mut n6 = 0u32;

        for slice in slices {
            for ep in &slice.endpoints {
                for ip in ep.ips() {
                    let family = match ip {
                        IpAddr::V4(_) => Family::V4,
                        IpAddr::V6(_) => Family::V6,
                    };
                    let ep_chain = format!("{svc_chain}_ep_{}", hex::encode(ip_octets(ip)));

                    let mut rules = Vec::new();
                    if affinity.is_some() {
                        let aff = affinity_set(key, if family == Family::V4 { '4' } else { '6' });
                        rules.push(rules::affinity_update(family, &aff, ip));
                        pre_rules.push(rules::affinity_goto(family, &aff, ip, &ep_chain));
                    }

                    for (port, name) in &svc.ports {
                        if let Some(&target) = slice.target_ports.get(name) {
                            rules.push(dnat_rule(ip, port, target, false, &self.my_node.ips));
                        }
                    }
                    for (port, name) in &svc.node_ports {
                        if let Some(&target) = slice.target_ports.get(name) {
                            rules.push(dnat_rule(ip, port, target, true, &self.my_node.ips));
                        }
                    }

                    self.add_chain(ep_chain.clone(), rules, Vec::new());

                    let n = match family {
                        Family::V4 => &mut n4,
                        Family::V6 => &mut n6,
                    };
                    entries.push((*n, Verdict::Goto(ep_chain)));
                    *n += 1;
                }
            }
        }

        // An affinity set referenced by an `update` rule must carry
        // `NFT_SET_EVAL` (`dynamic`); one with no endpoint of its family is
        // only `timeout`. nft normally derives this while parsing the script.
        for (family, n) in [(Family::V4, n4), (Family::V6, n6)] {
            if affinity.is_some() && n > 0 {
                let name = affinity_set(key, if family == Family::V4 { '4' } else { '6' });
                if let Some(set) = self.sets.get_mut(&name) {
                    set.meta_mut().flags |= SetFlags::Eval;
                }
            }
        }

        let mut rules = pre_rules;
        for (family, n) in [(Family::V4, n4), (Family::V6, n6)] {
            if n == 0 {
                rules.push(rules::nfproto_reject(family));
            } else {
                rules.push(rules::numgen_vmap(family, n, &svc_chain));
            }
        }
        self.add_chain(svc_chain.clone(), rules, anon_sets);

        // A `numgen` result is a host-endian 4-byte integer; key the map the
        // same way so the lookup matches.
        let entries = entries
            .into_iter()
            .map(|(n, verdict)| (n.to_ne_bytes().to_vec(), verdict));
        self.sets.insert(
            svc_chain,
            SetSync::verdict_map_raw(dispatch_map_meta(), entries),
        );
    }
}

/// The rules rejecting traffic not originating from `allow` (an external
/// Service's `loadBalancerSourceRanges`): a singleton CIDR becomes an inline
/// prefix match, several become the anonymous interval set nft would build.
fn allow_list_rules(anon_sets: &mut Vec<SetSync>, allow: &BTreeSet<String>) -> Vec<Rule> {
    let mut v4: Vec<(u8, Ipv4Addr, RangeInclusive<Ipv4Addr>)> = Vec::new();
    let mut v6: Vec<(u8, Ipv6Addr, RangeInclusive<Ipv6Addr>)> = Vec::new();

    for cidr in allow {
        match cidr.parse::<IpCidr>() {
            Ok(IpCidr::V4(c)) => v4.push((
                c.network_length(),
                c.first_address(),
                c.first_address()..=c.last_address(),
            )),
            Ok(IpCidr::V6(c)) => v6.push((
                c.network_length(),
                c.first_address(),
                c.first_address()..=c.last_address(),
            )),
            Err(_) => {}
        }
    }

    let mut rules = Vec::new();
    if v4.len() == 1 {
        let (prefix, first, _) = &v4[0];
        let mut rule =
            rules::ip_prefix(Family::V4, Dir::Src, *prefix, first.octets().to_vec(), true);
        rule.push(rules::reject_icmp(Family::V4));
        rules.push(rule);
    } else if !v4.is_empty() {
        let ranges: Vec<_> = v4.iter().map(|(_, _, r)| r.clone()).collect();
        rules.push(anon_range_rule(
            anon_sets,
            Family::V4,
            SetSync::interval(ranges, None),
        ));
    }

    if v6.len() == 1 {
        let (prefix, first, _) = &v6[0];
        let mut rule =
            rules::ip_prefix(Family::V6, Dir::Src, *prefix, first.octets().to_vec(), true);
        rule.push(rules::reject_icmp(Family::V6));
        rules.push(rule);
    } else if !v6.is_empty() {
        let ranges: Vec<_> = v6.iter().map(|(_, _, r)| r.clone()).collect();
        rules.push(anon_range_rule(
            anon_sets,
            Family::V6,
            SetSync::interval(ranges, None),
        ));
    }

    rules
}

fn anon_range_rule(anon_sets: &mut Vec<SetSync>, family: Family, mut set: SetSync) -> Rule {
    set.set_anonymous();
    let index = anon_sets.len() as u32;
    anon_sets.push(set);

    let mut rule = rules::ip_set_anon(family, Dir::Src, index, true);
    rule.push(rules::reject_icmp(family));
    rule
}

#[cfg(test)]
mod tests;
