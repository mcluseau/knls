use super::{ANN_EGRESS_REJECT, ANN_REJECT, Peer, Policy, PolicyPort, PolicyRule, RejectAction};
use crate::{
    kube_watch::EventReceiver,
    netlink::netfilter::{self, NetlinkExt as _},
    nftables::{
        Message,
        chain::{self, Chain, Rule},
        rules,
        rules::{Dir, Expr, Family, Reject},
        set,
        set::{Verdict, VerdictElem},
        table,
    },
    state::{Namespace, Pod},
};
use cidr::IpCidr;
use eyre::Result;
use k8s_openapi::{api::core::v1 as core, api::networking::v1 as networking};
use log::error;
use std::collections::BTreeSet as Set;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::RangeInclusive;
use std::sync::Arc;
use xxhash_rust::xxh3;

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct Config {
    /// nftables table's name
    table: String,
    /// reject action (for ingress rules)
    reject: RejectAction,
    /// reject action (for egress rules)
    egress_reject: RejectAction,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            table: "kube-netpol".into(),
            reject: RejectAction::Reject,
            egress_reject: RejectAction::Reject,
        }
    }
}

crate::multimap!(
    State {
        netpols: NetworkPolicy(networking::NetworkPolicy) => Policy,
        pods: Pod(core::Pod) => Pod,
        nses: Namespace(core::Namespace) => Namespace,
    }
);

pub async fn watch(ctx: Arc<crate::Context>, cfg: Config, mut events: EventReceiver) -> Result<()> {
    let mut prev = 0u128;

    let node_name = ctx.node_name.as_str();

    let mut state = State::new();

    let nl = netfilter::new_link()?;

    loop {
        let Some(updated) = state.ingest_events(&mut events).await else {
            return Ok(());
        };
        if !updated || !state.is_ready() {
            continue;
        }

        let rendered = render(&state, &cfg, node_name);

        let h = rendered.hash();

        if prev == h {
            continue;
        }
        prev = h;

        // Everything in one atomic batch: the message order satisfies every
        // reference (sets before the rules using them, chains before the vmap
        // elements that `goto` them).
        if let Err(e) = nl.send_as_transactions(rendered.messages.into_iter()).await {
            error!("netpol update failed: {e}");
        }
    }
}

/// The rendered netpol table: the netlink messages to apply.
struct Rendered {
    messages: Vec<Message>,
}

impl Rendered {
    /// The full-content hash, so an element-only change is not missed.
    fn hash(&self) -> u128 {
        let mut hasher = xxh3::Xxh3::new();
        for msg in &self.messages {
            let mut msg = msg.clone();
            msg.finalize();
            let mut buf = vec![0u8; msg.buffer_len()];
            msg.serialize(&mut buf);
            hasher.update(&buf);
        }
        hasher.digest128()
    }
}

/// Renders the netpol table for `state` as netlink messages.
fn render(state: &State, cfg: &Config, node_name: &str) -> Rendered {
    let mut b = Builder::new(cfg);

    b.pod_chains(state, node_name);
    b.netpol_chains(state);
    b.base_chain();

    Rendered {
        messages: b.into_messages(),
    }
}

/// A chain plus whether it is a base chain (needs the hook on creation).
struct BuiltChain<'t> {
    chain: Chain<'t>,
    base: bool,
}

/// Accumulates the sets, maps and chains of one netpol table.
struct Builder<'t> {
    cfg: &'t Config,
    sets: NamedSets,
    chains: Vec<BuiltChain<'t>>,
}

impl<'t> Builder<'t> {
    fn new(cfg: &'t Config) -> Self {
        Self {
            cfg,
            sets: NamedSets::new(&cfg.table),
            chains: Vec::new(),
        }
    }

    /// Adds a regular chain and returns it for filling.
    fn chain(&mut self, name: String) -> &mut Chain<'t> {
        self.chains.push(BuiltChain {
            chain: Chain::new(self.cfg.table.as_str(), name),
            base: false,
        });
        &mut self.chains.last_mut().expect("just pushed").chain
    }

    fn pod_chains(&mut self, state: &State, node_name: &str) {
        for (pod_key, pod) in state.pods.iter() {
            if pod.host_network {
                continue; // no filtering on host-network pods
            }
            if pod.node != node_name {
                continue;
            };

            let (ns, name) = pod_key.as_str();

            let netpols: Vec<_> = (state.netpols.iter())
                .filter(|(_, np)| np.matches_pod(pod_key, pod))
                .collect();

            if netpols.is_empty() {
                continue; // no netpols apply to the pod, don't filter its traffic
            }

            let ingress: Vec<_> = (netpols.iter())
                .filter(|(_, np)| np.is_ingress())
                .map(|(k, _)| k.as_str())
                .collect();
            if !ingress.is_empty() {
                let chain_name = format!("ingress_pod_{ns}_{name}");
                for ip in &pod.ipsv4 {
                    self.sets.pods_ingress.items.push((*ip, chain_name.clone()));
                }
                for ip in &pod.ipsv6 {
                    self.sets
                        .pods_ingress6
                        .items
                        .push((*ip, chain_name.clone()));
                }

                let mut rules: Vec<Rule> = ingress
                    .iter()
                    .map(|(np_ns, np_name)| {
                        vec![rules::jump(format!("ingress_netpol_{np_ns}_{np_name}"))]
                    })
                    .collect();
                rules.push(action_rule(pod, ANN_REJECT, self.cfg.reject));
                self.chain(chain_name).extend(rules);
            }

            let egress: Vec<_> = (netpols.iter())
                .filter(|(_, np)| np.is_egress())
                .map(|(k, _)| k.as_str())
                .collect();
            if !egress.is_empty() {
                let chain_name = format!("egress_pod_{ns}_{name}");
                for ip in &pod.ipsv4 {
                    self.sets.pods_egress.items.push((*ip, chain_name.clone()));
                }
                for ip in &pod.ipsv6 {
                    self.sets.pods_egress6.items.push((*ip, chain_name.clone()));
                }

                let mut rules: Vec<Rule> = egress
                    .iter()
                    .map(|(np_ns, np_name)| {
                        vec![rules::jump(format!("egress_netpol_{np_ns}_{np_name}"))]
                    })
                    .collect();
                rules.push(action_rule(pod, ANN_EGRESS_REJECT, self.cfg.egress_reject));
                self.chain(chain_name).extend(rules);
            }
        }
    }

    fn netpol_chains(&mut self, state: &State) {
        // Only netpols matching a pod on this node are materialized.
        let mut used = Set::new();
        for (pod_key, pod) in state.pods.iter() {
            for (k, np) in state.netpols.iter() {
                if np.matches_pod(pod_key, pod) {
                    used.insert(k.as_str());
                }
            }
        }

        for (np_key, np) in state.netpols.iter() {
            let (ns, name) = np_key.as_str();
            if !used.contains(&(ns, name)) {
                continue;
            }

            if np.is_ingress() {
                let chain = format!("ingress_netpol_{ns}_{name}");
                let mut helper = Helper {
                    state,
                    sets: &mut self.sets,
                    prefix: format!("np_{ns}_{name}_i"),
                    idx: 0,
                };
                let rules: Vec<Rule> = np
                    .ingress()
                    .iter()
                    .flat_map(|rule| helper.rule(rule, Dir::Src))
                    .collect();
                self.chain(chain).extend(rules);
            }

            if np.is_egress() {
                let chain = format!("egress_netpol_{ns}_{name}");
                let mut helper = Helper {
                    state,
                    sets: &mut self.sets,
                    prefix: format!("np_{ns}_{name}_e"),
                    idx: 0,
                };
                let rules: Vec<Rule> = np
                    .egress()
                    .iter()
                    .flat_map(|rule| helper.rule(rule, Dir::Dst))
                    .collect();
                self.chain(chain).extend(rules);
            }
        }
    }

    fn base_chain(&mut self) {
        let pods_ingress = &self.sets.pods_ingress;
        let pods_ingress6 = &self.sets.pods_ingress6;
        let pods_egress = &self.sets.pods_egress;
        let pods_egress6 = &self.sets.pods_egress6;

        let mut chain = Chain::new(self.cfg.table.as_str(), "pods_filter");

        let maps: [(Family, Dir, &PodMap<Ipv4Addr>); 2] = [
            (Family::V4, Dir::Dst, pods_ingress),
            (Family::V4, Dir::Src, pods_egress),
        ];
        for (family, dir, map) in maps {
            if !map.is_empty() {
                chain.extend(std::iter::once(rules::ip_vmap(family, dir, &map.name)));
            }
        }
        let maps6: [(Family, Dir, &PodMap<Ipv6Addr>); 2] = [
            (Family::V6, Dir::Dst, pods_ingress6),
            (Family::V6, Dir::Src, pods_egress6),
        ];
        for (family, dir, map) in maps6 {
            if !map.is_empty() {
                chain.extend(std::iter::once(rules::ip_vmap(family, dir, &map.name)));
            }
        }

        self.chains.push(BuiltChain { chain, base: true });
    }

    fn into_messages(self) -> Vec<Message> {
        let Self { sets, chains, .. } = self;

        let mut out = Vec::new();

        // 1. table + sets/maps, all before any rule references them.
        out.extend(table::recreate(&sets.table));
        out.extend(sets.set_messages());

        // 2. chains (base gets its hook), then their rules.
        for c in &chains {
            out.push(if c.base {
                c.chain
                    .create_base(chain::InetHookNumber::Forward, 0, chain::ACCEPT)
            } else {
                c.chain.create()
            });
        }
        for c in &chains {
            out.extend(c.chain.fill());
        }

        // 3. vmap elements, now that the chains they `goto` exist.
        out.extend(sets.vmap_fill_messages());

        out
    }
}

/// The rule a pod chain applies when no netpol rule matched.
fn action_rule(pod: &Pod, annotation: &str, default: RejectAction) -> Rule {
    let action = pod
        .annotations
        .get(annotation)
        .map(|v| RejectAction::from_annotation(v))
        .unwrap_or(default);
    match action {
        RejectAction::Drop => vec![rules::drop()],
        RejectAction::Reject => vec![Reject::default().into()],
    }
}

/// Builds the rules of one netpol rule, registering its named sets.
struct Helper<'t> {
    state: &'t State,
    sets: &'t mut NamedSets,
    prefix: String,
    idx: u32,
}

impl Helper<'_> {
    /// Builds the rules of one netpol rule: one rule per peer clause, all
    /// `accept`. Each generated rule gets its own anonymous port set (the
    /// kernel binds an anonymous set to a single rule).
    fn rule(&mut self, rule: &PolicyRule, dir: Dir) -> Vec<Rule> {
        self.idx += 1;

        let peer_clauses = self.peers(dir, rule.peers());

        let mut out = Vec::new();
        for clause in &peer_clauses {
            for mut pred in self.port_preds(rule.ports()) {
                pred.extend(clause.iter().cloned());
                pred.push(rules::accept());
                out.push(pred);
            }
        }
        out
    }

    /// One predicate per port alternative; no ports (or none specified) matches
    /// all, as an empty predicate.
    ///
    /// The specific port/range alternatives become a fresh anonymous
    /// `inet_proto . inet_service` concat set (printed inline by nft). An
    /// alternative without a port is a full `0-65535` range so it can join the
    /// same set, rather than a separate protocol-only predicate.
    fn port_preds(&mut self, ports: &[PolicyPort]) -> Vec<Vec<Expr>> {
        if ports.is_empty() {
            return vec![Vec::new()];
        }

        let mut ranges: Vec<RangeInclusive<(u8, u16)>> = Vec::with_capacity(ports.len());

        for port in ports {
            let proto = port.proto().ip_proto();
            match port.port() {
                // any port: the full range
                None => ranges.push((proto, 0)..=(proto, u16::MAX)),
                Some(port) => {
                    ranges.push((proto, port.start().to_owned())..=(proto, port.end().to_owned()));
                }
            }
        }

        let name = self.sets.push_anon_ports(ranges);
        vec![rules::l4proto_dport_set(&name)]
    }

    /// One clause per peer (OR'd by the caller); none specified matches all.
    fn peers(&mut self, dir: Dir, peers: &[Peer]) -> Vec<Vec<Expr>> {
        if peers.is_empty() {
            return vec![Vec::new()];
        }

        let mut clauses = Vec::new();
        let mut ipsv4: Set<Ipv4Addr> = Set::new();
        let mut ipsv6: Set<Ipv6Addr> = Set::new();

        for peer in peers {
            match peer {
                Peer::IpBlock { cidr, except } => {
                    // match the block's prefix inline, then exclude the `except`
                    // ranges via an anonymous interval set (`!= { … }`)
                    let mut clause = ip_prefix_clause(cidr, dir);
                    clause.extend(self.except_clause(except, dir));
                    clauses.push(clause);
                }
                Peer::Selector { namespace, pod } => {
                    let ns_filter: Option<Set<&str>> = namespace.as_ref().map(|sel| {
                        (self.state.nses.iter())
                            .filter(|(_, ns)| sel.matches(&ns.labels))
                            .map(|(ns, _)| ns.as_str())
                            .collect()
                    });

                    for (key, pod_state) in self.state.pods.iter() {
                        if let Some(ref ns_filter) = ns_filter
                            && !ns_filter.contains(key.namespace.as_str())
                        {
                            continue;
                        }

                        if let Some(filter) = pod
                            && !filter.matches(&pod_state.labels)
                        {
                            continue;
                        }

                        ipsv4.extend(&pod_state.ipsv4);
                        ipsv6.extend(&pod_state.ipsv6);
                    }
                }
            }
        }

        if !ipsv4.is_empty() {
            let name = format!("{}_{}_pods_v4", self.prefix, self.idx);
            self.sets
                .push_simple_v4(name.clone(), ipsv4.iter().copied().collect());
            clauses.push(rules::ip_set(Family::V4, dir, &name, false));
        }
        if !ipsv6.is_empty() {
            let name = format!("{}_{}_pods_v6", self.prefix, self.idx);
            self.sets
                .push_simple_v6(name.clone(), ipsv6.iter().copied().collect());
            clauses.push(rules::ip_set(Family::V6, dir, &name, false));
        }

        if clauses.is_empty() {
            vec![Vec::new()] // everything filtered out: match all, safest
        } else {
            clauses
        }
    }

    /// The exclusion clause for an `ipBlock`'s `except` list: an anonymous
    /// interval set of the excepted ranges, looked up inverted (`!= { … }`).
    ///
    /// `except` all share one address family in practice; a mixed list yields
    /// one clause per family (each its own set).
    fn except_clause(&mut self, except: &[IpCidr], dir: Dir) -> Vec<Expr> {
        let v4: Vec<_> = except
            .iter()
            .filter_map(|c| match c {
                IpCidr::V4(c) => Some(c.first_address()..=c.last_address()),
                _ => None,
            })
            .collect();
        let v6: Vec<_> = except
            .iter()
            .filter_map(|c| match c {
                IpCidr::V6(c) => Some(c.first_address()..=c.last_address()),
                _ => None,
            })
            .collect();

        let mut out = Vec::new();
        if !v4.is_empty() {
            let name = self.sets.push_anon_v4(v4);
            out.extend(rules::ip_set(Family::V4, dir, &name, true));
        }
        if !v6.is_empty() {
            let name = self.sets.push_anon_v6(v6);
            out.extend(rules::ip_set(Family::V6, dir, &name, true));
        }
        out
    }
}

/// The named peer sets, anonymous port/except sets and verdict maps a netpol
/// table references.
struct NamedSets {
    table: String,
    next_id: u32,
    anon_ports: Vec<NamedSet<RangeInclusive<(u8, u16)>>>,
    anon_v4: Vec<NamedSet<RangeInclusive<Ipv4Addr>>>,
    anon_v6: Vec<NamedSet<RangeInclusive<Ipv6Addr>>>,
    simple_v4: Vec<NamedSet<Ipv4Addr>>,
    simple_v6: Vec<NamedSet<Ipv6Addr>>,
    pods_ingress: PodMap<Ipv4Addr>,
    pods_ingress6: PodMap<Ipv6Addr>,
    pods_egress: PodMap<Ipv4Addr>,
    pods_egress6: PodMap<Ipv6Addr>,
}

/// Sorts inclusive ranges by their endpoints (`RangeInclusive` isn't `Ord`).
fn sort_ranges<T: Ord>(ranges: &mut [RangeInclusive<T>]) {
    ranges.sort_by(|a, b| a.start().cmp(b.start()).then_with(|| a.end().cmp(b.end())));
}

struct NamedSet<T> {
    id: u32,
    name: String,
    items: Vec<T>,
}

struct PodMap<A> {
    id: u32,
    name: String,
    items: Vec<(A, String)>,
}

impl<A> PodMap<A> {
    fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

impl NamedSets {
    fn new(table: &str) -> Self {
        let mut sets = Self {
            table: table.into(),
            next_id: 0,
            anon_ports: Vec::new(),
            anon_v4: Vec::new(),
            anon_v6: Vec::new(),
            simple_v4: Vec::new(),
            simple_v6: Vec::new(),
            pods_ingress: PodMap {
                id: 0,
                name: "pods_ingress".into(),
                items: Vec::new(),
            },
            pods_ingress6: PodMap {
                id: 0,
                name: "pods_ingress6".into(),
                items: Vec::new(),
            },
            pods_egress: PodMap {
                id: 0,
                name: "pods_egress".into(),
                items: Vec::new(),
            },
            pods_egress6: PodMap {
                id: 0,
                name: "pods_egress6".into(),
                items: Vec::new(),
            },
        };
        sets.pods_ingress.id = sets.next_id();
        sets.pods_ingress6.id = sets.next_id();
        sets.pods_egress.id = sets.next_id();
        sets.pods_egress6.id = sets.next_id();
        sets
    }

    fn next_id(&mut self) -> u32 {
        self.next_id += 1;
        self.next_id
    }

    /// Registers a fresh anonymous port set, returning its name.
    ///
    /// The kernel binds an anonymous set to a single rule, so one is created per
    /// rule that constrains ports; nft prints it inline (`{ tcp . 80, … }`).
    fn push_anon_ports(&mut self, mut items: Vec<RangeInclusive<(u8, u16)>>) -> String {
        let id = self.next_id();
        sort_ranges(&mut items);
        let name = format!("__set{id}");
        self.anon_ports.push(NamedSet {
            id,
            name: name.clone(),
            items,
        });
        name
    }
    fn push_simple_v4(&mut self, name: String, mut items: Vec<Ipv4Addr>) {
        let id = self.next_id();
        items.sort();
        items.dedup();
        self.simple_v4.push(NamedSet { id, name, items });
    }
    fn push_simple_v6(&mut self, name: String, mut items: Vec<Ipv6Addr>) {
        let id = self.next_id();
        items.sort();
        items.dedup();
        self.simple_v6.push(NamedSet { id, name, items });
    }

    /// Registers a fresh anonymous IPv4 interval set (an `ipBlock`'s `except`
    /// list), returning its name. nft prints it inline (`!= { … }`).
    fn push_anon_v4(&mut self, mut items: Vec<RangeInclusive<Ipv4Addr>>) -> String {
        let id = self.next_id();
        sort_ranges(&mut items);
        let name = format!("__set{id}");
        self.anon_v4.push(NamedSet {
            id,
            name: name.clone(),
            items,
        });
        name
    }

    /// Registers a fresh anonymous IPv6 interval set (an `ipBlock`'s `except`
    /// list), returning its name.
    fn push_anon_v6(&mut self, mut items: Vec<RangeInclusive<Ipv6Addr>>) -> String {
        let id = self.next_id();
        sort_ranges(&mut items);
        let name = format!("__set{id}");
        self.anon_v6.push(NamedSet {
            id,
            name: name.clone(),
            items,
        });
        name
    }

    /// Create + fill every named peer/port set, and create the pod maps.
    fn set_messages(&self) -> Vec<Message> {
        let mut out = Vec::new();

        for s in &self.anon_ports {
            let set = set::Set::<RangeInclusive<(u8, u16)>>::new(&self.table, &s.name, s.id);
            out.push(set.create_anonymous());
            out.extend(set.fill(s.items.iter().cloned()));
        }
        for s in &self.anon_v4 {
            let set = set::Set::<RangeInclusive<Ipv4Addr>>::new(&self.table, &s.name, s.id);
            out.push(set.create_anonymous());
            out.extend(set.fill(s.items.iter().cloned()));
        }
        for s in &self.anon_v6 {
            let set = set::Set::<RangeInclusive<Ipv6Addr>>::new(&self.table, &s.name, s.id);
            out.push(set.create_anonymous());
            out.extend(set.fill(s.items.iter().cloned()));
        }
        for s in &self.simple_v4 {
            let set = set::Set::<Ipv4Addr>::new(&self.table, &s.name, s.id);
            out.push(set.create(None));
            out.extend(set.fill(s.items.iter().copied()));
        }
        for s in &self.simple_v6 {
            let set = set::Set::<Ipv6Addr>::new(&self.table, &s.name, s.id);
            out.push(set.create(None));
            out.extend(set.fill(s.items.iter().copied()));
        }
        for map in [&self.pods_ingress, &self.pods_egress] {
            if !map.is_empty() {
                out.push(map.create_message(&self.table));
            }
        }
        for map in [&self.pods_ingress6, &self.pods_egress6] {
            if !map.is_empty() {
                out.push(map.create_message(&self.table));
            }
        }

        out
    }

    /// Fill the pod verdict maps (requires the target chains to exist).
    fn vmap_fill_messages(&self) -> Vec<Message> {
        let mut out = Vec::new();
        out.extend(self.pods_ingress.fill_messages(&self.table));
        out.extend(self.pods_ingress6.fill_messages(&self.table));
        out.extend(self.pods_egress.fill_messages(&self.table));
        out.extend(self.pods_egress6.fill_messages(&self.table));
        out
    }
}

impl<A: set::Data + Copy> PodMap<A> {
    fn create_message(&self, table: &str) -> Message {
        set::Set::<VerdictElem<A>>::new(table, &self.name, self.id).create(None)
    }

    fn fill_messages(&self, table: &str) -> Vec<Message> {
        if self.items.is_empty() {
            return Vec::new();
        }
        set::Set::<VerdictElem<A>>::new(table, &self.name, self.id)
            .fill(
                self.items
                    .iter()
                    .map(|(ip, chain)| VerdictElem(*ip, Verdict::Goto(chain.clone()))),
            )
            .collect()
    }
}

/// The clause matching a single CIDR, inline (no set).
fn ip_prefix_clause(cidr: &IpCidr, dir: Dir) -> Vec<Expr> {
    let prefix = cidr.network_length();
    match cidr {
        IpCidr::V4(c) => rules::ip_prefix(
            Family::V4,
            dir,
            prefix,
            c.first_address().octets().to_vec(),
            false,
        ),
        IpCidr::V6(c) => rules::ip_prefix(
            Family::V6,
            dir,
            prefix,
            c.first_address().octets().to_vec(),
            false,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        kube_watch::{Change, Event},
        nftables::test_harness,
    };
    use netlink_packet_core::NetlinkPayload;
    use netlink_packet_netfilter::{
        NetfilterMessage, NetfilterMessageInner,
        nftables::{
            ChainAttribute, Cmp, DataAttribute, ExpressionAttribute, Expressions, ListAttribute,
            Lookup, NfTablesMessage, RuleAttribute,
        },
    };
    use std::collections::BTreeMap as Map;
    use std::process::Command;
    use std::sync::Arc;

    fn pod(name: &str, namespace: &str, node: &str, labels: &str, ips: &[&str]) -> core::Pod {
        let ips: Vec<_> = ips
            .iter()
            .map(|ip| serde_json::json!({ "ip": ip }))
            .collect();
        serde_json::from_value(serde_json::json!({
            "metadata": { "name": name, "namespace": namespace, "labels": { "app": labels } },
            "spec": { "nodeName": node },
            "status": { "podIPs": ips },
        }))
        .expect("pod")
    }

    fn netpol(name: &str, selector: &str, ingress: serde_json::Value) -> networking::NetworkPolicy {
        serde_json::from_value(serde_json::json!({
            "metadata": { "name": name, "namespace": "default" },
            "spec": {
                "podSelector": { "matchLabels": { "app": selector } },
                "policyTypes": ["Ingress"],
                "ingress": ingress,
            },
        }))
        .expect("netpol")
    }

    fn state_with(pods: &[core::Pod], netpols: &[networking::NetworkPolicy]) -> State {
        let mut state = State::new();
        for p in pods {
            state.ingest(&Event::Pod(Change::InitApply(Arc::new(p.clone()))));
        }
        state.ingest(&Event::Pod(Change::InitDone));
        for np in netpols {
            state.ingest(&Event::NetworkPolicy(Change::InitApply(Arc::new(
                np.clone(),
            ))));
        }
        state.ingest(&Event::NetworkPolicy(Change::InitDone));
        state.ingest(&Event::Namespace(Change::InitDone));
        state
    }

    /// A minimal state: one pod `app=a` on n1 and one ingress netpol.
    fn basic_state(ingress: serde_json::Value) -> State {
        state_with(
            &[pod("a", "default", "n1", "a", &["10.0.0.1"])],
            &[netpol("np", "a", ingress)],
        )
    }

    fn default_cfg() -> Config {
        Config {
            table: "t".into(),
            ..Default::default()
        }
    }

    /// The chain names among `msgs`, in creation order.
    fn chain_names(msgs: &[Message]) -> Vec<String> {
        msgs.iter()
            .filter_map(|m| match &m.payload {
                NetlinkPayload::InnerMessage(NetfilterMessage {
                    inner: NetfilterMessageInner::NfTables(NfTablesMessage::NewChain(c)),
                    ..
                }) => c.attributes.iter().find_map(|a| match a {
                    ChainAttribute::Name(n) => Some(n.clone()),
                    _ => None,
                }),
                _ => None,
            })
            .collect()
    }

    /// Whether any message is a base chain (has a hook).
    fn has_base_chain(msgs: &[Message]) -> bool {
        msgs.iter().any(|m| {
            matches!(
                &m.payload,
                NetlinkPayload::InnerMessage(NetfilterMessage {
                    inner: NetfilterMessageInner::NfTables(NfTablesMessage::NewChain(c)),
                    ..
                }) if c.attributes.iter().any(|a| matches!(a, ChainAttribute::Hook(_)))
            )
        })
    }

    /// Every rule's expressions, per chain.
    fn rules(msgs: &[Message]) -> Vec<(String, Vec<RuleAttribute>)> {
        msgs.iter()
            .filter_map(|m| match &m.payload {
                NetlinkPayload::InnerMessage(NetfilterMessage {
                    inner: NetfilterMessageInner::NfTables(NfTablesMessage::NewRule(r)),
                    ..
                }) => {
                    let chain = r.attributes.iter().find_map(|a| match a {
                        RuleAttribute::Chain(c) => Some(c.clone()),
                        _ => None,
                    })?;
                    Some((chain, r.attributes.clone()))
                }
                _ => None,
            })
            .collect()
    }

    /// `(set_name, inverted)` for every lookup expression in `rule`.
    fn lookups(rule: &[RuleAttribute]) -> Vec<(String, bool)> {
        let Some(RuleAttribute::Expressions(exprs)) = rule
            .iter()
            .find(|a| matches!(a, RuleAttribute::Expressions(_)))
        else {
            return Vec::new();
        };
        exprs
            .iter()
            .filter_map(|e| match e {
                ListAttribute::Element(attrs) => attrs.iter().find_map(|a| match a {
                    ExpressionAttribute::Data(Expressions::Lookup(l)) => {
                        let set = l.iter().find_map(|x| match x {
                            Lookup::Set(s) => Some(s.clone()),
                            _ => None,
                        })?;
                        let inv = l.iter().any(|x| matches!(x, Lookup::Flags(1)));
                        Some((set, inv))
                    }
                    _ => None,
                }),
                _ => None,
            })
            .collect()
    }

    /// The names of every set created in `msgs`.
    fn set_names(msgs: &[Message]) -> Vec<String> {
        msgs.iter()
            .filter_map(|m| match &m.payload {
                NetlinkPayload::InnerMessage(NetfilterMessage {
                    inner: NetfilterMessageInner::NfTables(NfTablesMessage::NewSet(s)),
                    ..
                }) => s.attributes.iter().find_map(|a| match a {
                    netlink_packet_netfilter::nftables::SetAttribute::Name(n) => Some(n.clone()),
                    _ => None,
                }),
                _ => None,
            })
            .collect()
    }

    fn find_set<'a>(
        msgs: &'a [Message],
        name: &str,
    ) -> Option<&'a netlink_packet_netfilter::nftables::SetMessage> {
        msgs.iter().find_map(|m| {
            match &m.payload {
            NetlinkPayload::InnerMessage(NetfilterMessage {
                inner: NetfilterMessageInner::NfTables(NfTablesMessage::NewSet(s)),
                ..
            }) if s.attributes.iter().any(|a| {
                matches!(a, netlink_packet_netfilter::nftables::SetAttribute::Name(n) if n == name)
            }) => Some(s),
            _ => None,
        }
        })
    }

    /// Whether `rule` compares a register against `value` with equality (a
    /// `Cmp` on `value`).
    fn rule_has_prefix_eq(rule: &[RuleAttribute], value: &[u8]) -> bool {
        let Some(RuleAttribute::Expressions(exprs)) = rule
            .iter()
            .find(|a| matches!(a, RuleAttribute::Expressions(_)))
        else {
            return false;
        };
        let op = netlink_packet_netfilter::nftables::Operator::Equal;
        exprs.iter().any(|e| {
            let ListAttribute::Element(attrs) = e else {
                return false;
            };
            attrs.iter().any(|a| match a {
                ExpressionAttribute::Data(Expressions::Cmp(c)) => {
                    c.contains(&Cmp::Op(op))
                        && c.iter()
                            .any(|x| matches!(x, Cmp::Data(DataAttribute::Value(v)) if v == value))
                }
                _ => false,
            })
        })
    }

    #[test]
    fn renders_chains_base_and_vmap() {
        let state = basic_state(serde_json::json!([{ "from": [] }]));
        let r = render(&state, &default_cfg(), "n1");

        let names = chain_names(&r.messages);
        assert!(
            names.contains(&"pods_filter".to_string()),
            "base chain missing: {names:?}"
        );
        assert!(
            names.contains(&"ingress_pod_default_a".to_string()),
            "pod chain missing: {names:?}"
        );
        assert!(
            names.contains(&"ingress_netpol_default_np".to_string()),
            "netpol chain missing: {names:?}"
        );
        assert!(has_base_chain(&r.messages), "no base chain hook");

        // the pod map is filled with a goto to the pod chain
        let dump = format!("{:?}", r.messages);
        assert!(
            dump.contains("goto") || dump.contains("Goto"),
            "vmap goto missing"
        );
    }

    #[test]
    fn ipblock_and_except_match_inline() {
        let state = basic_state(serde_json::json!([{
            "from": [{ "ipBlock": { "cidr": "192.168.42.0/24", "except": ["192.168.42.5/32"] } }],
        }]));
        let r = render(&state, &default_cfg(), "n1");

        // an anonymous set holds the excluded range; the pod vmap is the other
        let names = set_names(&r.messages);
        assert!(
            names.contains(&"__set5".to_string()),
            "except set missing: {names:?}"
        );
        let set = find_set(&r.messages, "__set5").expect("except set");
        let flags = set.attributes.iter().find_map(|a| match a {
            netlink_packet_netfilter::nftables::SetAttribute::Flags(f) => Some(*f),
            _ => None,
        });
        let flags = flags.expect("flags");
        assert!(flags.contains(netlink_packet_netfilter::nftables::SetFlags::Anonymous));
        assert!(flags.contains(netlink_packet_netfilter::nftables::SetFlags::Interval));

        // the rule matches the cidr inline (byte-aligned /24 => payload+eq) and
        // excludes the anonymous set (inverted lookup)
        let (_, rule) = rules(&r.messages)
            .into_iter()
            .find(|(c, _)| c == "ingress_netpol_default_np")
            .expect("netpol rule");
        assert_eq!(lookups(&rule), vec![("__set5".to_string(), true)]);
        assert!(rule_has_prefix_eq(&rule, &[192, 168, 42]));
    }

    #[test]
    fn ports_become_a_concat_interval_set() {
        let state = basic_state(serde_json::json!([{
            "from": [],
            "ports": [ { "protocol": "TCP", "port": 80 }, { "protocol": "UDP", "port": 53 } ],
        }]));
        let r = render(&state, &default_cfg(), "n1");

        let set = find_set(&r.messages, "__set5").expect("port set");
        let flags = set.attributes.iter().find_map(|a| match a {
            netlink_packet_netfilter::nftables::SetAttribute::Flags(f) => Some(*f),
            _ => None,
        });
        let flags = flags.expect("flags");
        assert!(flags.contains(netlink_packet_netfilter::nftables::SetFlags::Interval));
        assert!(flags.contains(netlink_packet_netfilter::nftables::SetFlags::Concat));
        assert!(flags.contains(netlink_packet_netfilter::nftables::SetFlags::Anonymous));

        // dport 53/80 are stored as (proto, port) elements
        let (_, rule) = rules(&r.messages)
            .into_iter()
            .find(|(c, _)| c == "ingress_netpol_default_np")
            .expect("netpol rule");
        assert_eq!(lookups(&rule)[0].0, "__set5");
    }

    #[test]
    fn any_port_is_a_full_range() {
        // no port on the entry => a full 0-65535 range in the port set
        let state = basic_state(serde_json::json!([{
            "from": [],
            "ports": [ { "protocol": "TCP" } ],
        }]));
        let r = render(&state, &default_cfg(), "n1");

        let set = find_set(&r.messages, "__set5").expect("port set");
        let flags = set.attributes.iter().find_map(|a| match a {
            netlink_packet_netfilter::nftables::SetAttribute::Flags(f) => Some(*f),
            _ => None,
        });
        let flags = flags.expect("flags");
        assert!(flags.contains(netlink_packet_netfilter::nftables::SetFlags::Interval));
        assert!(flags.contains(netlink_packet_netfilter::nftables::SetFlags::Anonymous));

        // the rule looks the protocol . service set up
        let (_, rule) = rules(&r.messages)
            .into_iter()
            .find(|(c, _)| c == "ingress_netpol_default_np")
            .expect("netpol rule");
        assert_eq!(lookups(&rule)[0].0, "__set5");
    }

    #[test]
    fn mixed_any_port_and_specific_port() {
        // {TCP, any port} + {UDP, 53}: both go into one anonymous port set
        let state = basic_state(serde_json::json!([{
            "from": [],
            "ports": [ { "protocol": "TCP" }, { "protocol": "UDP", "port": 53 } ],
        }]));
        let r = render(&state, &default_cfg(), "n1");

        find_set(&r.messages, "__set5").expect("port set");

        let netpol_rules: Vec<_> = rules(&r.messages)
            .into_iter()
            .filter(|(c, _)| c == "ingress_netpol_default_np")
            .collect();
        // both alternatives share the one set
        assert_eq!(netpol_rules.len(), 1, "expected one rule");
        assert_eq!(lookups(&netpol_rules[0].1)[0].0, "__set5");
    }

    #[test]
    fn reject_action_defaults_and_overrides() {
        assert_eq!(RejectAction::from_annotation("drop"), RejectAction::Drop);
        assert_eq!(
            RejectAction::from_annotation("reject"),
            RejectAction::Reject
        );
        assert_eq!(RejectAction::from_annotation("bogus"), RejectAction::Reject);

        let mut p = Pod {
            labels: Map::new(),
            annotations: Map::new(),
            node: "n1".into(),
            ipsv4: Vec::new(),
            ipsv6: Vec::new(),
            host_network: false,
        };
        p.annotations.insert(ANN_REJECT.into(), "drop".into());
        let rule = action_rule(&p, ANN_REJECT, RejectAction::Reject);
        // `drop` is an immediate verdict, not a reject expression
        assert_eq!(rule.len(), 1);
    }

    #[test]
    fn hash_tracks_content() {
        let a = render(&state_with(&[], &[]), &default_cfg(), "n1");
        let b = render(&state_with(&[], &[]), &default_cfg(), "n1");
        assert_eq!(a.hash(), b.hash());

        let c = render(
            &basic_state(serde_json::json!([{ "from": [] }])),
            &default_cfg(),
            "n1",
        );
        assert_ne!(a.hash(), c.hash());
    }

    /// A netpol [`System`](test_harness::System) for the golden
    /// scenarios.
    struct TestSystem {
        state: State,
        cfg: Config,
    }

    impl test_harness::System for TestSystem {
        fn new(table: String) -> Self {
            Self {
                state: State::new(),
                cfg: Config {
                    table,
                    ..Default::default()
                },
            }
        }

        fn ingest(&mut self, event: Event) {
            self.state.ingest(&event);
        }

        fn render(&mut self) -> Vec<Message> {
            render(&self.state, &self.cfg, "n1").messages
        }
    }

    /// Golden tests: each `test_assets/golden-nftables/netpol/*.yaml` scenario
    /// (ipBlock/except, podSelector, ports), rendered and compared to
    /// `nft list` at each step.
    ///
    /// Requires `CAP_NET_ADMIN`; run with `sudo -E cargo test -- --ignored`.
    #[ignore = "requires CAP_NET_ADMIN and a real kernel"]
    #[tokio::test]
    async fn golden() {
        test_harness::golden_dir::<TestSystem>(
            "test_assets/golden-nftables/netpol",
            "knls-test-netpol-",
        )
        .await;
    }

    /// Applies a rendered table to the real kernel and checks the dump.
    ///
    /// Requires `CAP_NET_ADMIN`; run with `sudo -E cargo test -- --ignored`.
    #[ignore = "requires CAP_NET_ADMIN and a real kernel"]
    #[tokio::test]
    async fn render_applies_to_kernel() {
        let table = "knls-test-netpol";
        let _ = Command::new("nft")
            .args(["delete", "table", "inet", table])
            .status();

        let state = state_with(
            &[
                pod("a", "default", "n1", "a", &["10.0.0.1", "fd00::1"]),
                pod("b", "other", "n2", "b", &["10.0.0.2"]),
            ],
            &[netpol(
                "np",
                "a",
                serde_json::json!([{
                    "from": [{ "ipBlock": { "cidr": "192.168.32.0/20", "except": ["192.168.42.5/32"] } }],
                    "ports": [ { "protocol": "TCP", "port": 80 }, { "protocol": "SCTP" } ],
                }]),
            )],
        );
        let cfg = Config {
            table: table.into(),
            ..Default::default()
        };
        let rendered = render(&state, &cfg, "n1");

        let nl = netfilter::new_link().expect("netlink");
        nl.send_as_transactions(rendered.messages.into_iter())
            .await
            .expect("apply");

        let out = Command::new("nft")
            .args(["list", "table", "inet", table])
            .output()
            .expect("nft");
        let dump = String::from_utf8_lossy(&out.stdout);
        assert!(out.status.success(), "nft list failed: {dump}");
        assert!(
            dump.contains("192.168.32.0/20"),
            "inline block missing:\n{dump}"
        );
        assert!(
            dump.contains("goto ingress_pod_default_a"),
            "vmap missing:\n{dump}"
        );
        assert!(dump.contains("tcp . 80"), "port element missing:\n{dump}");
        // the any-port SCTP alternative matches the protocol alone
        assert!(dump.contains("sctp"), "protocol-only rule missing:\n{dump}");

        let _ = Command::new("nft")
            .args(["delete", "table", "inet", table])
            .status();
    }
}
