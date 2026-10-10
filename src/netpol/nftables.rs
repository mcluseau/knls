use super::{ANN_EGRESS_REJECT, ANN_REJECT, Peer, Policy, PolicyPort, PolicyRule, RejectAction};
use crate::{
    kube_watch::EventReceiver,
    nftables::{
        chain::{self, Rule},
        rules,
        rules::{Dir, Expr, Family, Reject},
        set::{Data, Verdict},
        table_sync::{BaseChain, ChainSync, SetSync, TableState, TableSync},
    },
    selector::Selector,
    state::{Namespace, Pod},
};
use cidr::IpCidr;
use eyre::Result;
use k8s_openapi::{api::core::v1 as core, api::networking::v1 as networking};
use log::error;
use netlink_packet_netfilter::nftables::Register;
use std::collections::{BTreeMap, BTreeSet as Set};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::RangeInclusive;
use std::sync::Arc;

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
    let node_name = ctx.node_name.as_str();

    let mut state = State::new();
    let mut table = TableState::new(cfg.table.clone());

    loop {
        let Some(updated) = state.ingest_events(&mut events).await else {
            return Ok(());
        };
        if !updated || !state.is_ready() {
            continue;
        }

        if let Err(e) = table.update(render(&state, &cfg, node_name)).await {
            error!("netpol update failed: {e}");
        }
    }
}

/// Renders the netpol table for `state` as a target [`TableSync`].
fn render(state: &State, cfg: &Config, node_name: &str) -> TableSync {
    let mut b = Builder::new(cfg);

    b.pod_chains(state, node_name);
    b.netpol_chains(state);
    b.base_chain();

    b.into_table()
}

/// Accumulates the sets, maps and chains of one netpol table.
struct Builder<'t> {
    cfg: &'t Config,
    sets: BTreeMap<String, SetSync>,
    chains: BTreeMap<String, ChainSync>,
}

impl<'t> Builder<'t> {
    fn new(cfg: &'t Config) -> Self {
        Self {
            cfg,
            sets: BTreeMap::new(),
            chains: BTreeMap::new(),
        }
    }

    /// Adds a regular chain with its rules and anonymous sets.
    fn add_chain(&mut self, name: String, rules: Vec<Rule>, anon_sets: Vec<SetSync>) {
        self.chains.insert(
            name,
            ChainSync {
                base: None,
                rules,
                anon_sets,
            },
        );
    }

    /// Adds the pod verdict-map entry `key -> goto chain`, creating the map on
    /// first use.
    fn vmap_entry<A: Data>(&mut self, map: &str, key: A, chain: String) {
        let entry = self
            .sets
            .entry(map.to_string())
            .or_insert_with(|| SetSync::verdict_map::<A>(std::iter::empty(), None));
        if let SetSync::VerdictMap(m) = entry {
            m.entries.insert(key.elem_data(), Verdict::Goto(chain));
        }
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
                    self.vmap_entry("pods_ingress", *ip, chain_name.clone());
                }
                for ip in &pod.ipsv6 {
                    self.vmap_entry("pods_ingress6", *ip, chain_name.clone());
                }

                let mut rules: Vec<Rule> = ingress
                    .iter()
                    .map(|(np_ns, np_name)| {
                        vec![rules::jump(format!("ingress_netpol_{np_ns}_{np_name}"))]
                    })
                    .collect();
                rules.push(action_rule(pod, ANN_REJECT, self.cfg.reject));
                self.add_chain(chain_name, rules, Vec::new());
            }

            let egress: Vec<_> = (netpols.iter())
                .filter(|(_, np)| np.is_egress())
                .map(|(k, _)| k.as_str())
                .collect();
            if !egress.is_empty() {
                let chain_name = format!("egress_pod_{ns}_{name}");
                for ip in &pod.ipsv4 {
                    self.vmap_entry("pods_egress", *ip, chain_name.clone());
                }
                for ip in &pod.ipsv6 {
                    self.vmap_entry("pods_egress6", *ip, chain_name.clone());
                }

                let mut rules: Vec<Rule> = egress
                    .iter()
                    .map(|(np_ns, np_name)| {
                        vec![rules::jump(format!("egress_netpol_{np_ns}_{np_name}"))]
                    })
                    .collect();
                rules.push(action_rule(pod, ANN_EGRESS_REJECT, self.cfg.egress_reject));
                self.add_chain(chain_name, rules, Vec::new());
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

            // A named port in an ingress rule is a container port of a *target*
            // pod, so named-port resolution needs the policy's selected pods.
            let target_pods: Vec<&Pod> = (state.pods.iter())
                .filter(|(k, p)| np.matches_pod(k, p))
                .map(|(_, p)| p)
                .collect();

            if np.is_ingress() {
                let chain = format!("ingress_netpol_{ns}_{name}");
                let (rules, anon_sets) = {
                    let mut helper = Helper {
                        state,
                        policy_ns: ns,
                        target_pods: &target_pods,
                        named: &mut self.sets,
                        prefix: format!("np_{ns}_{name}_i"),
                        idx: 0,
                        anon: Vec::new(),
                    };
                    let rules: Vec<Rule> = np
                        .ingress()
                        .iter()
                        .flat_map(|rule| helper.rule(rule, Dir::Src))
                        .collect();
                    (rules, helper.anon)
                };
                self.add_chain(chain, rules, anon_sets);
            }

            if np.is_egress() {
                let chain = format!("egress_netpol_{ns}_{name}");
                let (rules, anon_sets) = {
                    let mut helper = Helper {
                        state,
                        policy_ns: ns,
                        target_pods: &target_pods,
                        named: &mut self.sets,
                        prefix: format!("np_{ns}_{name}_e"),
                        idx: 0,
                        anon: Vec::new(),
                    };
                    let rules: Vec<Rule> = np
                        .egress()
                        .iter()
                        .flat_map(|rule| helper.rule(rule, Dir::Dst))
                        .collect();
                    (rules, helper.anon)
                };
                self.add_chain(chain, rules, anon_sets);
            }
        }
    }

    fn base_chain(&mut self) {
        let mut rules = Vec::new();

        let maps: [(Family, Dir, &str); 2] = [
            (Family::V4, Dir::Dst, "pods_ingress"),
            (Family::V4, Dir::Src, "pods_egress"),
        ];
        for (family, dir, map) in maps {
            if self.sets.contains_key(map) {
                rules.push(rules::ip_vmap(family, dir, map));
            }
        }
        let maps6: [(Family, Dir, &str); 2] = [
            (Family::V6, Dir::Dst, "pods_ingress6"),
            (Family::V6, Dir::Src, "pods_egress6"),
        ];
        for (family, dir, map) in maps6 {
            if self.sets.contains_key(map) {
                rules.push(rules::ip_vmap(family, dir, map));
            }
        }

        // Netpol only constrains *new* connections. Accept the reply/related
        // traffic of already-allowed flows up front, otherwise the lookups below
        // drop the replies of an allowed flow whenever the opposite direction
        // also has a policy (netpol is stateful, per the API).
        if !rules.is_empty() {
            let mut established = rules::ct_state_established_related(Register::Reg1);
            established.push(rules::accept());
            rules.insert(0, established);
        }

        self.chains.insert(
            "pods_filter".into(),
            ChainSync {
                base: Some(BaseChain {
                    chain_type: chain::ChainType::Filter,
                    hook: chain::InetHookNumber::Forward,
                    priority: 0,
                    policy: chain::ACCEPT,
                }),
                rules,
                anon_sets: Vec::new(),
            },
        );
    }

    fn into_table(self) -> TableSync {
        TableSync {
            chains: self.chains,
            sets: self.sets,
        }
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

/// Builds the rules of one netpol rule, registering its named and anonymous
/// sets.
struct Helper<'a> {
    state: &'a State,
    /// The namespace of the policy being rendered; a peer without a
    /// `namespaceSelector` is scoped to it.
    policy_ns: &'a str,
    /// The pods the policy selects: a named port in an *ingress* rule is a
    /// container port of one of these (the traffic's destination).
    target_pods: &'a [&'a Pod],
    /// Named peer sets, added to the table.
    named: &'a mut BTreeMap<String, SetSync>,
    prefix: String,
    idx: u32,
    /// Anonymous sets this chain's rules reference, referenced by position.
    ///
    /// Their names are generated by `sync`, not here.
    anon: Vec<SetSync>,
}

/// A peer clause: its address family (for pairing with a named-port predicate;
/// `None` when the rule matches any peer) and its expressions.
type Clause = (Option<Family>, Vec<Expr>);

/// A rule's peer clauses and the pods its selector peers matched.
type Peers<'a> = (Vec<Clause>, Vec<&'a Pod>);

impl<'a> Helper<'a> {
    /// Registers a fresh anonymous set and returns its position, which a rule
    /// references via [`rules::lookup_anon`].
    fn push_anon(&mut self, mut set: SetSync) -> u32 {
        set.set_anonymous();
        self.anon.push(set);
        (self.anon.len() - 1) as u32
    }

    /// Registers a fresh anonymous port set, returning its index.
    ///
    /// The kernel binds an anonymous set to a single rule, so one is created per
    /// rule that constrains ports; nft prints it inline (`{ tcp . 80, … }`).
    fn push_anon_ports(&mut self, ranges: Vec<RangeInclusive<(u8, u16)>>) -> u32 {
        self.push_anon(SetSync::interval(ranges, None))
    }

    /// Registers a fresh anonymous IPv4 interval set (an `ipBlock`'s `except`
    /// list), returning its index. nft prints it inline (`!= { … }`).
    fn push_anon_v4(&mut self, ranges: Vec<RangeInclusive<Ipv4Addr>>) -> u32 {
        self.push_anon(SetSync::interval(ranges, None))
    }

    /// Registers a fresh anonymous IPv6 interval set (an `ipBlock`'s `except`
    /// list), returning its index.
    fn push_anon_v6(&mut self, ranges: Vec<RangeInclusive<Ipv6Addr>>) -> u32 {
        self.push_anon(SetSync::interval(ranges, None))
    }

    fn push_simple_v4(&mut self, name: String, items: Vec<Ipv4Addr>) {
        self.named.insert(name, SetSync::simple(items, None));
    }

    fn push_simple_v6(&mut self, name: String, items: Vec<Ipv6Addr>) {
        self.named.insert(name, SetSync::simple(items, None));
    }

    /// Builds the rules of one netpol rule: one rule per peer clause, all
    /// `accept`. Each generated rule gets its own anonymous port set (the
    /// kernel binds an anonymous set to a single rule).
    fn rule(&mut self, rule: &PolicyRule, dir: Dir) -> Vec<Rule> {
        self.idx += 1;

        let (peer_clauses, peer_pods) = self.peers(dir, rule.peers());
        // A named port is a container port of the traffic's *destination*: the
        // target pod for ingress, the peer pod for egress. With no peer
        // specified, an egress rule allows any destination, so resolve against
        // every pod. Only a named port reads this, so the (possibly large)
        // every-pod set is built lazily.
        let has_named = rule.ports().iter().any(|p| p.named().is_some());
        let all_pods: Vec<&Pod>;
        let dst_pods: &[&Pod] = if dir == Dir::Src {
            self.target_pods
        } else if !rule.peers().is_empty() {
            &peer_pods
        } else if has_named {
            all_pods = (self.state.pods.iter()).map(|(_, pod)| pod).collect();
            &all_pods
        } else {
            &[]
        };

        let mut out = Vec::new();
        for (family, clause) in &peer_clauses {
            for mut pred in self.port_preds(rule.ports(), *family, dst_pods) {
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
    /// The numeric/range alternatives become a fresh anonymous
    /// `inet_proto . inet_service` concat set (printed inline by nft); an
    /// alternative without a port is a full `0-65535` range so it can join the
    /// same set, rather than a separate protocol-only predicate. A *named*
    /// alternative is resolved against the destination pods and becomes an
    /// `inet_family . inet_proto . inet_service` set (`<daddr> . <proto> .
    /// <port>`), so each pod is matched on its own container port. `family`
    /// restricts the address family to the peer clause's (or both when the rule
    /// applies to any peer).
    fn port_preds(
        &mut self,
        ports: &[PolicyPort],
        family: Option<Family>,
        dst_pods: &[&Pod],
    ) -> Vec<Vec<Expr>> {
        if ports.is_empty() {
            return vec![Vec::new()];
        }

        let mut out = Vec::new();

        // the numeric/range alternatives share one family-agnostic concat set
        let mut numeric: Vec<RangeInclusive<(u8, u16)>> = Vec::new();
        for port in ports {
            if port.named().is_some() {
                continue;
            }
            let ip_proto = port.proto().ip_proto();
            match port.port() {
                Some(range) => numeric.push((ip_proto, *range.start())..=(ip_proto, *range.end())),
                None => numeric.push((ip_proto, 0)..=(ip_proto, u16::MAX)),
            }
        }
        if !numeric.is_empty() {
            let index = self.push_anon_ports(numeric);
            out.push(rules::l4proto_dport_anon(index));
        }

        // each named alternative resolves per `(destination pod IP, container
        // port)`; an unresolvable name contributes nothing (fails closed)
        let families: &[Family] = match family {
            Some(Family::V4) => &[Family::V4],
            Some(Family::V6) => &[Family::V6],
            None => &[Family::V4, Family::V6],
        };
        for port in ports {
            let Some(name) = port.named() else { continue };
            let proto = port.proto();
            let ip_proto = proto.ip_proto();
            for &family in families {
                match family {
                    Family::V4 => {
                        let mut ranges = Vec::new();
                        for pod in dst_pods {
                            for (n, p, num) in &pod.ports {
                                if n == name && *p == proto {
                                    for ip in &pod.ipsv4 {
                                        ranges.push((*ip, ip_proto, *num)..=(*ip, ip_proto, *num));
                                    }
                                }
                            }
                        }
                        if !ranges.is_empty() {
                            let index = self.push_anon(SetSync::interval(ranges, None));
                            out.push(rules::addr_l4proto_dport_anon(Family::V4, index));
                        }
                    }
                    Family::V6 => {
                        let mut ranges = Vec::new();
                        for pod in dst_pods {
                            for (n, p, num) in &pod.ports {
                                if n == name && *p == proto {
                                    for ip in &pod.ipsv6 {
                                        ranges.push((*ip, ip_proto, *num)..=(*ip, ip_proto, *num));
                                    }
                                }
                            }
                        }
                        if !ranges.is_empty() {
                            let index = self.push_anon(SetSync::interval(ranges, None));
                            out.push(rules::addr_l4proto_dport_anon(Family::V6, index));
                        }
                    }
                }
            }
        }

        out
    }

    /// One clause per peer (OR'd by the caller); none specified matches all.
    ///
    /// Returns each clause tagged with its address family (for pairing with a
    /// named-port predicate) plus the pods the selector peers matched (the
    /// named-port destinations for egress).
    fn peers(&mut self, dir: Dir, peers: &[Peer]) -> Peers<'a> {
        if peers.is_empty() {
            return (vec![(None, Vec::new())], Vec::new());
        }

        let mut clauses = Vec::new();

        // `ipBlock` peers, in order.
        for peer in peers {
            if let Peer::IpBlock { cidr, except } = peer {
                let family = match cidr {
                    IpCidr::V4(_) => Family::V4,
                    IpCidr::V6(_) => Family::V6,
                };
                let mut clause = ip_prefix_clause(cidr, dir);
                clause.extend(self.except_clause(except, dir));
                clauses.push((Some(family), clause));
            }
        }

        // Selector peers, resolved in a single pass over the pods so a pod
        // matched by several peers is neither duplicated nor dropped. A peer
        // without a `namespaceSelector` selects the policy's own namespace; an
        // explicit (even empty) one selects namespaces.
        let selectors: Vec<(&Option<Selector>, Set<&str>)> = (peers.iter())
            .filter_map(|peer| match peer {
                Peer::Selector { namespace, pod } => Some((
                    pod,
                    match namespace {
                        Some(sel) => (self.state.nses.iter())
                            .filter(|(_, ns)| sel.matches(&ns.labels))
                            .map(|(ns, _)| ns.as_str())
                            .collect(),
                        None => Set::from([self.policy_ns]),
                    },
                )),
                Peer::IpBlock { .. } => None,
            })
            .collect();

        let mut pods = Vec::new();
        let mut ipsv4: Set<Ipv4Addr> = Set::new();
        let mut ipsv6: Set<Ipv6Addr> = Set::new();
        for (key, pod_state) in self.state.pods.iter() {
            let matched = selectors.iter().any(|(pod, ns_filter)| {
                ns_filter.contains(key.namespace.as_str())
                    && pod
                        .as_ref()
                        .is_none_or(|filter| filter.matches(&pod_state.labels))
            });
            if !matched {
                continue;
            }

            ipsv4.extend(&pod_state.ipsv4);
            ipsv6.extend(&pod_state.ipsv6);
            pods.push(pod_state);
        }

        if !ipsv4.is_empty() {
            let name = format!("{}_{}_pods_v4", self.prefix, self.idx);
            self.push_simple_v4(name.clone(), ipsv4.iter().copied().collect());
            clauses.push((
                Some(Family::V4),
                rules::ip_set(Family::V4, dir, &name, false),
            ));
        }
        if !ipsv6.is_empty() {
            let name = format!("{}_{}_pods_v6", self.prefix, self.idx);
            self.push_simple_v6(name.clone(), ipsv6.iter().copied().collect());
            clauses.push((
                Some(Family::V6),
                rules::ip_set(Family::V6, dir, &name, false),
            ));
        }

        if clauses.is_empty() {
            // Selector peers that matched no pod yield no clause: the caller
            // then emits no rule at all for this peer list, i.e. it matches
            // nothing (fails closed) rather than allowing everything.
            (vec![], pods)
        } else {
            (clauses, pods)
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
            let index = self.push_anon_v4(v4);
            out.extend(rules::ip_set_anon(Family::V4, dir, index, true));
        }
        if !v6.is_empty() {
            let index = self.push_anon_v6(v6);
            out.extend(rules::ip_set_anon(Family::V6, dir, index, true));
        }
        out
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
        netlink::netfilter::{self, NetlinkExt as _},
        nftables::{Message, table_sync::sync, test_harness},
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

    /// The full-render messages for `state` (a first-apply sync).
    fn messages(state: &State, cfg: &Config, node: &str) -> Vec<Message> {
        sync(&cfg.table, None, &render(state, cfg, node))
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
        let r = messages(&state, &default_cfg(), "n1");

        let names = chain_names(&r);
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
        assert!(has_base_chain(&r), "no base chain hook");

        // the pod map is filled with a goto to the pod chain
        let dump = format!("{:?}", r);
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
        let r = messages(&state, &default_cfg(), "n1");

        // the rule matches the cidr inline (byte-aligned /24 => payload+eq) and
        // excludes an anonymous interval set (inverted lookup)
        let (_, rule) = rules(&r)
            .into_iter()
            .find(|(c, _)| c == "ingress_netpol_default_np")
            .expect("netpol rule");
        let found = lookups(&rule);
        assert_eq!(found.len(), 1);
        let (name, inverted) = &found[0];
        assert!(*inverted, "except set lookup must be inverted");

        let names = set_names(&r);
        assert!(names.contains(name), "except set missing: {names:?}");
        let set = find_set(&r, name).expect("except set");
        let flags = set.attributes.iter().find_map(|a| match a {
            netlink_packet_netfilter::nftables::SetAttribute::Flags(f) => Some(*f),
            _ => None,
        });
        let flags = flags.expect("flags");
        assert!(flags.contains(netlink_packet_netfilter::nftables::SetFlags::Anonymous));
        assert!(flags.contains(netlink_packet_netfilter::nftables::SetFlags::Interval));

        assert!(rule_has_prefix_eq(&rule, &[192, 168, 42]));
    }

    #[test]
    fn ports_become_a_concat_interval_set() {
        let state = basic_state(serde_json::json!([{
            "from": [],
            "ports": [ { "protocol": "TCP", "port": 80 }, { "protocol": "UDP", "port": 53 } ],
        }]));
        let r = messages(&state, &default_cfg(), "n1");

        // dport 53/80 are stored as (proto, port) elements in the set the rule
        // looks up
        let (_, rule) = rules(&r)
            .into_iter()
            .find(|(c, _)| c == "ingress_netpol_default_np")
            .expect("netpol rule");
        let (name, _) = lookups(&rule).into_iter().next().expect("lookup");
        let set = find_set(&r, &name).expect("port set");
        let flags = set.attributes.iter().find_map(|a| match a {
            netlink_packet_netfilter::nftables::SetAttribute::Flags(f) => Some(*f),
            _ => None,
        });
        let flags = flags.expect("flags");
        assert!(flags.contains(netlink_packet_netfilter::nftables::SetFlags::Interval));
        assert!(flags.contains(netlink_packet_netfilter::nftables::SetFlags::Concat));
        assert!(flags.contains(netlink_packet_netfilter::nftables::SetFlags::Anonymous));
    }

    #[test]
    fn any_port_is_a_full_range() {
        // no port on the entry => a full 0-65535 range in the port set
        let state = basic_state(serde_json::json!([{
            "from": [],
            "ports": [ { "protocol": "TCP" } ],
        }]));
        let r = messages(&state, &default_cfg(), "n1");

        // the rule looks the protocol . service set up
        let (_, rule) = rules(&r)
            .into_iter()
            .find(|(c, _)| c == "ingress_netpol_default_np")
            .expect("netpol rule");
        let (name, _) = lookups(&rule).into_iter().next().expect("lookup");
        let set = find_set(&r, &name).expect("port set");
        let flags = set.attributes.iter().find_map(|a| match a {
            netlink_packet_netfilter::nftables::SetAttribute::Flags(f) => Some(*f),
            _ => None,
        });
        let flags = flags.expect("flags");
        assert!(flags.contains(netlink_packet_netfilter::nftables::SetFlags::Interval));
        assert!(flags.contains(netlink_packet_netfilter::nftables::SetFlags::Anonymous));
    }

    #[test]
    fn mixed_any_port_and_specific_port() {
        // {TCP, any port} + {UDP, 53}: both go into one anonymous port set
        let state = basic_state(serde_json::json!([{
            "from": [],
            "ports": [ { "protocol": "TCP" }, { "protocol": "UDP", "port": 53 } ],
        }]));
        let r = messages(&state, &default_cfg(), "n1");

        let netpol_rules: Vec<_> = rules(&r)
            .into_iter()
            .filter(|(c, _)| c == "ingress_netpol_default_np")
            .collect();
        // both alternatives share the one set
        assert_eq!(netpol_rules.len(), 1, "expected one rule");
        let (name, _) = lookups(&netpol_rules[0].1)
            .into_iter()
            .next()
            .expect("lookup");
        find_set(&r, &name).expect("port set");
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
            ports: Vec::new(),
        };
        p.annotations.insert(ANN_REJECT.into(), "drop".into());
        let rule = action_rule(&p, ANN_REJECT, RejectAction::Reject);
        // `drop` is an immediate verdict, not a reject expression
        assert_eq!(rule.len(), 1);
    }

    #[test]
    fn reference_tracks_content() {
        let a = render(&state_with(&[], &[]), &default_cfg(), "n1").reference("t");
        let b = render(&state_with(&[], &[]), &default_cfg(), "n1").reference("t");
        assert_eq!(a, b);

        let c = render(
            &basic_state(serde_json::json!([{ "from": [] }])),
            &default_cfg(),
            "n1",
        )
        .reference("t");
        assert_ne!(a, c);
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
            messages(&self.state, &self.cfg, "n1")
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

    /// Prints, for each `test_assets/golden-nftables/netpol/*.yaml` scenario, the
    /// kernel body its ingest events produce. Used to (re)generate the goldens.
    ///
    /// Requires `CAP_NET_ADMIN`; run with `sudo -E cargo test -- --ignored --nocapture`.
    #[ignore = "requires CAP_NET_ADMIN and a real kernel"]
    #[tokio::test]
    async fn print_goldens() {
        let dir = "test_assets/golden-nftables/netpol";
        let mut paths: Vec<_> = std::fs::read_dir(dir)
            .expect("golden dir")
            .map(|e| e.expect("golden dir entry").path())
            .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("yaml"))
            .collect();
        paths.sort();

        for path in paths {
            let stem = path
                .file_stem()
                .and_then(|s| s.to_str())
                .expect("golden file stem");
            let table = format!("knls-test-netpol-regen-{stem}");
            let cfg = Config {
                table: table.clone(),
                ..Default::default()
            };

            let yaml = std::fs::read_to_string(&path).expect("golden file read");
            let ops: Vec<test_harness::Op> =
                serde_yaml::from_str(&yaml).expect("bad scenario yaml");

            let mut state = State::new();
            for op in ops {
                if let test_harness::Op::Ingest(events) = op {
                    for event in events {
                        state.ingest(&event);
                    }
                }
            }

            let body = test_harness::capture(&table, messages(&state, &cfg, "n1")).await;
            println!("=== {stem} ===\n{body}\n");
        }
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
        let messages = sync(&cfg.table, None, &render(&state, &cfg, "n1"));

        let nl = netfilter::new_link().expect("netlink");
        nl.send_as_transactions(messages.into_iter())
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
