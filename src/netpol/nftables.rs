use super::{ANN_EGRESS_REJECT, ANN_REJECT, EgressRule, IngressRule, Policy};
use crate::{
    kube_watch::EventReceiver,
    netlink::netfilter::{self, NetlinkExt as _},
    nftables::{
        self, Message, set,
        set::{Verdict, VerdictElem},
        table,
    },
    state::{Namespace, Pod, keys},
};
use cidr::IpCidr;
use eyre::Result;
use k8s_openapi::{
    api::core::v1 as core,
    api::networking::v1::{self as networking, NetworkPolicyPeer, NetworkPolicyPort},
    apimachinery::pkg::apis::meta::v1::LabelSelector,
    apimachinery::pkg::util::intstr::IntOrString,
};
use log::error;
use std::collections::{BTreeMap as Map, BTreeSet as Set};
use std::fmt::Write;
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
    reject: String,
    /// reject action (for egress rules)
    egress_reject: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            table: "kube-netpol".into(),
            reject: "reject".into(),
            egress_reject: "reject".into(),
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

        log::debug!("applying nft netpol script:\n{}", rendered.script);

        if let Err(e) = apply(&nl, &cfg.table, rendered).await {
            error!("netpol update failed: {e}");
        }
    }
}

/// Applies a rendered netpol table to `table`.
///
/// Order matters: sets/maps must exist before the rules referencing them, and
/// the map elements (`goto <chain>`) before those chains are populated by the
/// script.
async fn apply(
    nl: &crate::netlink::Netlink<netlink_packet_netfilter::NetfilterMessage>,
    table_name: &str,
    rendered: Rendered,
) -> Result<()> {
    nl.send_as_transactions(table::recreate(table_name).into_iter())
        .await?;
    nl.send_as_transactions(rendered.peers.into_iter()).await?;
    nl.send_as_transactions(rendered.vmap_create.into_iter())
        .await?;

    nftables::apply_script(rendered.script)
        .await
        .map_err(|e| eyre::eyre!("applying netpol chains failed: {e}"))?;

    nl.send_as_transactions(rendered.vmap_fill.into_iter())
        .await?;
    Ok(())
}

/// The rendered netpol table: the chain/rule script and the netlink messages
/// for the named sets and verdict maps.
struct Rendered {
    script: String,
    peers: Vec<Message>,
    vmap_create: Vec<Message>,
    vmap_fill: Vec<Message>,
}

impl Rendered {
    /// The full-content hash, so an element-only change is not missed.
    fn hash(&self) -> u128 {
        let mut hasher = xxh3::Xxh3::new();
        hasher.update(self.script.as_bytes());
        for group in [&self.peers, &self.vmap_create, &self.vmap_fill] {
            for msg in group {
                let mut msg = msg.clone();
                msg.finalize();
                let mut buf = vec![0u8; msg.buffer_len()];
                msg.serialize(&mut buf);
                hasher.update(&buf);
            }
        }
        hasher.digest128()
    }
}

/// Renders the netpol table for `state`: the chain/rule script plus the named
/// peer sets and pod verdict maps to push over netlink.
fn render(state: &State, cfg: &Config, node_name: &str) -> Rendered {
    let mut script = String::new();
    let mut sets = NamedSets::new(&cfg.table);

    macro_rules! w {
        ($($tt:tt)*) => {
            script.write_fmt(format_args!($($tt)*)).unwrap();
            script.push('\n');
        };
    }

    w!("table inet {} {{", cfg.table);

    let mut used_netpols = Set::new();

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

        for (k, _) in &netpols {
            used_netpols.insert((k.namespace.as_str(), k.name.as_str()));
        }

        let mut recorded = false;
        for (np_ns, np_name) in (netpols.iter())
            .filter(|(_, np)| np.is_ingress)
            .map(|(k, _)| k.as_str())
        {
            if !recorded {
                recorded = true;
                let chain = format!("ingress_pod_{ns}_{name}");
                for ip in &pod.ipsv4 {
                    sets.pods_ingress.items.push((*ip, chain.clone()));
                }
                for ip in &pod.ipsv6 {
                    sets.pods_ingress6.items.push((*ip, chain.clone()));
                }
                w!("  chain {chain} {{");
            }
            w!("    jump ingress_netpol_{np_ns}_{np_name};");
        }
        if recorded {
            let reject = pod.annotations.get(ANN_REJECT).unwrap_or(&cfg.reject);
            w!("    {reject};");
            w!("  }}");
        }

        let mut recorded = false;
        for (np_ns, np_name) in (netpols.iter())
            .filter(|(_, np)| np.is_egress)
            .map(|(k, _)| k.as_str())
        {
            if !recorded {
                recorded = true;
                let chain = format!("egress_pod_{ns}_{name}");
                for ip in &pod.ipsv4 {
                    sets.pods_egress.items.push((*ip, chain.clone()));
                }
                for ip in &pod.ipsv6 {
                    sets.pods_egress6.items.push((*ip, chain.clone()));
                }
                w!("  chain {chain} {{");
            }
            w!("    jump egress_netpol_{np_ns}_{np_name};");
        }
        if recorded {
            let reject = pod
                .annotations
                .get(ANN_EGRESS_REJECT)
                .unwrap_or(&cfg.egress_reject);
            w!("    {reject};");
            w!("  }}");
        }
    }

    {
        let mut helper = NetpolHelper {
            state,
            sets: &mut sets,
            prefix: String::new(),
            idx: 0,
        };

        for (np_key, np) in state.netpols.iter() {
            let (ns, name) = np_key.as_str();
            if !used_netpols.contains(&(ns, name)) {
                continue;
            }

            if np.is_ingress {
                helper.begin(format!("np_{ns}_{name}_i"));
                w!("  chain ingress_netpol_{ns}_{name} {{");
                for rule in &np.ingress {
                    let r = helper.ingress_rules(rule);
                    w!("{r}");
                }
                w!("  }}");
            }

            if np.is_egress {
                helper.begin(format!("np_{ns}_{name}_e"));
                w!("  chain egress_netpol_{ns}_{name} {{");
                for rule in &np.egress {
                    let r = helper.egress_rules(rule);
                    w!("{r}");
                }
                w!("  }}");
            }
        }
    }

    w!("  chain pods_filter {{");
    w!("    type filter hook forward priority 0; policy accept;");
    if !sets.pods_ingress.is_empty() {
        w!("    ip daddr vmap @pods_ingress;");
    }
    if !sets.pods_egress.is_empty() {
        w!("    ip saddr vmap @pods_egress;");
    }
    if !sets.pods_ingress6.is_empty() {
        w!("    ip6 daddr vmap @pods_ingress6;");
    }
    if !sets.pods_egress6.is_empty() {
        w!("    ip6 saddr vmap @pods_egress6;");
    }
    w!("  }}");

    w!("}}");

    Rendered {
        peers: sets.peer_messages(),
        vmap_create: sets.vmap_create_messages(),
        vmap_fill: sets.vmap_fill_messages(),
        script,
    }
}

/// The named peer sets and pod verdict maps a netpol table references.
///
/// Rules are generated as text referencing sets by `@name`; their contents are
/// collected here and pushed to the kernel over netlink.
struct NamedSets {
    table: String,
    next_id: u32,
    interval_v4: Vec<NamedSet<RangeInclusive<Ipv4Addr>>>,
    interval_v6: Vec<NamedSet<RangeInclusive<Ipv6Addr>>>,
    simple_v4: Vec<NamedSet<Ipv4Addr>>,
    simple_v6: Vec<NamedSet<Ipv6Addr>>,
    pods_ingress: PodMap<Ipv4Addr>,
    pods_ingress6: PodMap<Ipv6Addr>,
    pods_egress: PodMap<Ipv4Addr>,
    pods_egress6: PodMap<Ipv6Addr>,
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
            interval_v4: Vec::new(),
            interval_v6: Vec::new(),
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

    fn push_interval_v4(&mut self, name: String, items: Vec<RangeInclusive<Ipv4Addr>>) {
        let id = self.next_id();
        self.interval_v4.push(NamedSet { id, name, items });
    }
    fn push_interval_v6(&mut self, name: String, items: Vec<RangeInclusive<Ipv6Addr>>) {
        let id = self.next_id();
        self.interval_v6.push(NamedSet { id, name, items });
    }
    fn push_simple_v4(&mut self, name: String, items: Vec<Ipv4Addr>) {
        let id = self.next_id();
        self.simple_v4.push(NamedSet { id, name, items });
    }
    fn push_simple_v6(&mut self, name: String, items: Vec<Ipv6Addr>) {
        let id = self.next_id();
        self.simple_v6.push(NamedSet { id, name, items });
    }

    /// Create + fill the peer sets (they have no dependencies).
    fn peer_messages(&self) -> Vec<Message> {
        let mut out = Vec::new();

        for s in &self.interval_v4 {
            let set = set::Set::<RangeInclusive<Ipv4Addr>>::new(&self.table, &s.name, s.id);
            out.push(set.create(None));
            out.extend(set.fill(s.items.iter().cloned()));
        }
        for s in &self.interval_v6 {
            let set = set::Set::<RangeInclusive<Ipv6Addr>>::new(&self.table, &s.name, s.id);
            out.push(set.create(None));
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

        out
    }

    /// Create the pod verdict maps (empty).
    fn vmap_create_messages(&self) -> Vec<Message> {
        let mut out = Vec::new();
        if !self.pods_ingress.is_empty() {
            out.push(vmap::<Ipv4Addr>(&self.table, &self.pods_ingress).create(None));
        }
        if !self.pods_ingress6.is_empty() {
            out.push(vmap::<Ipv6Addr>(&self.table, &self.pods_ingress6).create(None));
        }
        if !self.pods_egress.is_empty() {
            out.push(vmap::<Ipv4Addr>(&self.table, &self.pods_egress).create(None));
        }
        if !self.pods_egress6.is_empty() {
            out.push(vmap::<Ipv6Addr>(&self.table, &self.pods_egress6).create(None));
        }
        out
    }

    /// Fill the pod verdict maps (requires the target chains to exist).
    fn vmap_fill_messages(&self) -> Vec<Message> {
        let mut out = Vec::new();
        if !self.pods_ingress.is_empty() {
            out.extend(
                vmap::<Ipv4Addr>(&self.table, &self.pods_ingress).fill(
                    self.pods_ingress
                        .items
                        .iter()
                        .map(|(ip, chain)| VerdictElem(*ip, Verdict::Goto(chain.clone()))),
                ),
            );
        }
        if !self.pods_ingress6.is_empty() {
            out.extend(
                vmap::<Ipv6Addr>(&self.table, &self.pods_ingress6).fill(
                    self.pods_ingress6
                        .items
                        .iter()
                        .map(|(ip, chain)| VerdictElem(*ip, Verdict::Goto(chain.clone()))),
                ),
            );
        }
        if !self.pods_egress.is_empty() {
            out.extend(
                vmap::<Ipv4Addr>(&self.table, &self.pods_egress).fill(
                    self.pods_egress
                        .items
                        .iter()
                        .map(|(ip, chain)| VerdictElem(*ip, Verdict::Goto(chain.clone()))),
                ),
            );
        }
        if !self.pods_egress6.is_empty() {
            out.extend(
                vmap::<Ipv6Addr>(&self.table, &self.pods_egress6).fill(
                    self.pods_egress6
                        .items
                        .iter()
                        .map(|(ip, chain)| VerdictElem(*ip, Verdict::Goto(chain.clone()))),
                ),
            );
        }
        out
    }
}

/// A [`VerdictMapSet`](set::VerdictMapSet) handle for a pod map.
fn vmap<'t, A: set::Data>(table: &'t str, map: &'t PodMap<A>) -> set::VerdictMapSet<'t, A> {
    set::Set::new(table, &map.name, map.id)
}


struct NetpolHelper<'t> {
    state: &'t State,
    sets: &'t mut NamedSets,
    prefix: String,
    idx: u32,
}

impl NetpolHelper<'_> {
    fn begin(&mut self, prefix: String) {
        self.prefix = prefix;
        self.idx = 0;
    }

    fn ingress_rules(&mut self, rule: &IngressRule) -> String {
        let ports = self.ports(&rule.ports);
        self.rules(&ports, &rule.from, "saddr")
    }

    fn egress_rules(&mut self, rule: &EgressRule) -> String {
        let ports = self.ports(&rule.ports);
        self.rules(&ports, &rule.to, "daddr")
    }

    fn rules(
        &mut self,
        ports: &str,
        peers: &Option<Vec<NetworkPolicyPeer>>,
        addr_type: &str,
    ) -> String {
        self.idx += 1;
        let clauses = self.peers(addr_type, peers);

        let mut rules = String::new();
        for clause in clauses {
            rules.push_str(&format!("    {ports}{clause}accept;\n"));
        }
        rules
    }

    fn ports(&self, ports: &Option<Vec<NetworkPolicyPort>>) -> String {
        let mut rule = String::new();

        let Some(ports) = ports.as_ref() else {
            return rule;
        };
        if ports.is_empty() {
            return rule;
        }

        rule.push_str("meta l4proto . th dport {");
        for port in ports {
            let proto = port.protocol.as_deref().unwrap_or("TCP").to_lowercase();
            let port_range = match (port.port.as_ref(), port.end_port) {
                (None, _) => "0-0xffff",
                (Some(IntOrString::String(_)), _) => {
                    error!("named ports are not supported here");
                    continue;
                }
                (Some(IntOrString::Int(port)), None) => &format!("{port}"),
                (Some(IntOrString::Int(port)), Some(end)) => &format!("{port}-{end}"),
            };
            rule.push_str(&format!("{proto} . {port_range}, "));
        }
        rule.push_str("} ");

        rule
    }

    /// Registers named sets for `peers` and returns the match clauses
    /// referencing them (one clause per rule to emit).
    fn peers(&mut self, addr_type: &str, peers: &Option<Vec<NetworkPolicyPeer>>) -> Vec<String> {
        let Some(peers) = peers.as_ref() else {
            return vec![String::new()]; // unspecified = match all
        };
        if peers.is_empty() {
            return vec![String::new()]; // empty = match all
        }

        let mut clauses = Vec::new();
        let mut ipsv4: Set<Ipv4Addr> = Set::new();
        let mut ipsv6: Set<Ipv6Addr> = Set::new();
        let mut block_n = 0u32;

        for peer in peers {
            if let Some(ref ip_block) = peer.ip_block {
                let Ok(cidr) = (ip_block.cidr.parse::<IpCidr>())
                    .inspect_err(|e| error!("invalid ip block (ignored): {}: {e}", ip_block.cidr))
                else {
                    continue;
                };
                let except = ip_block.except.as_deref().unwrap_or(&[]);
                block_n += 1;

                match cidr {
                    IpCidr::V4(cidr) => {
                        let Some(ib) = IpBlock::new(cidr, except) else {
                            continue;
                        };
                        let name = format!("{np}_{n}_b{block_n}_v4", np = self.prefix, n = self.idx);
                        let mut clause = format!("ip {addr_type} @{name} ");
                        let range = ib.cidr.first_address()..=ib.cidr.last_address();
                        if !ib.except.is_empty() {
                            let exc_name = format!("{name}_exc");
                            let ranges = ib
                                .except
                                .iter()
                                .map(|c| c.first_address()..=c.last_address())
                                .collect();
                            self.sets.push_interval_v4(exc_name.clone(), ranges);
                            clause.push_str(&format!("ip {addr_type} != @{exc_name} "));
                        }
                        self.sets.push_interval_v4(name, vec![range]);
                        clauses.push(clause);
                    }
                    IpCidr::V6(cidr) => {
                        let Some(ib) = IpBlock::new(cidr, except) else {
                            continue;
                        };
                        let name = format!("{np}_{n}_b{block_n}_v6", np = self.prefix, n = self.idx);
                        let mut clause = format!("ip6 {addr_type} @{name} ");
                        let range = ib.cidr.first_address()..=ib.cidr.last_address();
                        if !ib.except.is_empty() {
                            let exc_name = format!("{name}_exc");
                            let ranges = ib
                                .except
                                .iter()
                                .map(|c| c.first_address()..=c.last_address())
                                .collect();
                            self.sets.push_interval_v6(exc_name.clone(), ranges);
                            clause.push_str(&format!("ip6 {addr_type} != @{exc_name} "));
                        }
                        self.sets.push_interval_v6(name, vec![range]);
                        clauses.push(clause);
                    }
                }
                continue;
            }

            let ns_filter: Option<Vec<_>> = peer.namespace_selector.as_ref().map(|ns_sel| {
                (self.state.nses.iter())
                    .filter(|(_, ns)| ns_sel.matches_labels(&ns.labels))
                    .map(|(ns, _)| ns)
                    .collect()
            });

            for (key, pod) in self.state.pods.iter() {
                if let Some(ref ns_filter) = ns_filter
                    && ns_filter.iter().all(|v| *v != &key.namespace)
                {
                    continue;
                }

                if let Some(ref filter) = peer.pod_selector
                    && !filter.matches_pod(key, pod)
                {
                    continue;
                }

                ipsv4.extend(&pod.ipsv4);
                ipsv6.extend(&pod.ipsv6);
            }
        }

        if !ipsv4.is_empty() {
            let name = format!("{}_{}_pods_v4", self.prefix, self.idx);
            self.sets
                .push_simple_v4(name.clone(), ipsv4.iter().copied().collect());
            clauses.push(format!("ip {addr_type} @{name} "));
        }
        if !ipsv6.is_empty() {
            let name = format!("{}_{}_pods_v6", self.prefix, self.idx);
            self.sets
                .push_simple_v6(name.clone(), ipsv6.iter().copied().collect());
            clauses.push(format!("ip6 {addr_type} @{name} "));
        }

        clauses
    }
}

struct IpBlock<T> {
    cidr: T,
    except: Vec<T>,
}

impl<T> IpBlock<T>
where
    T: std::str::FromStr,
    <T as std::str::FromStr>::Err: std::fmt::Display,
{
    fn new(cidr: T, except_str: &[String]) -> Option<Self> {
        let mut except = Vec::with_capacity(except_str.len());
        for s in except_str {
            let v = (s.parse())
                .inspect_err(|e| error!("invalid ip block except (block ignored): {s}: {e}"))
                .ok()?;
            except.push(v);
        }
        Some(IpBlock { cidr, except })
    }
}

trait PodSelector {
    fn matches_pod(&self, key: &keys::Object, pod: &Pod) -> bool;
}

impl PodSelector for Policy {
    fn matches_pod(&self, key: &keys::Object, pod: &Pod) -> bool {
        if key.namespace != self.namespace {
            return false;
        }
        self.pod_selector.matches_pod(key, pod)
    }
}

impl PodSelector for LabelSelector {
    fn matches_pod(&self, _: &keys::Object, pod: &Pod) -> bool {
        self.matches_labels(&pod.labels)
    }
}

trait LabelSel {
    fn matches_labels(&self, labels: &Map<String, String>) -> bool;
}

impl LabelSel for LabelSelector {
    fn matches_labels(&self, labels: &Map<String, String>) -> bool {
        let matches_labels = 'b: {
            let Some(ref filter) = self.match_labels else {
                break 'b true; // empty => true
            };
            if filter.is_empty() {
                break 'b true; // empty => true
            }
            for (k, v) in filter {
                if labels.get(k) != Some(v) {
                    break 'b false;
                }
            }
            true
        };

        let matches_expressions = 'b: {
            let Some(ref filter) = self.match_expressions else {
                break 'b true; // empty => true
            };
            if filter.is_empty() {
                break 'b true; // empty => true
            }
            for expr in filter {
                let value = labels.get(&expr.key);

                let eval = match expr.operator.as_str() {
                    "Exists" => value.is_some(),
                    "DoesNotExist" => value.is_none(),
                    "In" => value.is_some_and(|value| {
                        expr.values.as_ref().is_some_and(|v| v.contains(value))
                    }),
                    "NotIn" => value.is_none_or(|value| {
                        expr.values.as_ref().is_some_and(|v| !v.contains(value))
                    }),
                    op => {
                        error!("unknown operator {op}");
                        false
                    }
                };

                if !eval {
                    return false;
                }
            }
            true
        };

        matches_labels && matches_expressions
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netlink_packet_core::NetlinkPayload;
    use netlink_packet_netfilter::{
        nftables::{NfTablesMessage, SetElementAttribute, SetElementList},
        NetfilterMessage, NetfilterMessageInner,
    };

    fn v4(s: &str) -> Ipv4Addr {
        s.parse().expect("ipv4")
    }

    #[test]
    fn peer_set_messages_create_then_fill() {
        let mut sets = NamedSets::new("t");
        sets.push_interval_v4("np_a_i_1_b1_v4".into(), vec![v4("10.0.0.0")..=v4("10.0.0.255")]);
        sets.push_interval_v4("np_a_i_1_b1_v4_exc".into(), vec![v4("10.0.0.1")..=v4("10.0.0.2")]);
        sets.push_simple_v4("np_a_i_1_pods_v4".into(), vec![v4("10.1.0.1")]);

        let msgs = sets.peer_messages();
        // create + fill for each of the three sets
        assert_eq!(msgs.len(), 6);

        let creates = msgs
            .iter()
            .filter(|m| is_new_set(m))
            .count();
        let fills = msgs
            .iter()
            .filter(|m| is_new_elem(m))
            .count();
        assert_eq!(creates, 3);
        assert_eq!(fills, 3);
    }

    #[test]
    fn vmap_create_empty_and_fill_verdicts() {
        let mut sets = NamedSets::new("t");
        sets.pods_ingress.items.push((v4("10.0.0.1"), "ch".into()));

        let create = sets.vmap_create_messages();
        assert_eq!(create.len(), 1);
        assert!(is_new_set(&create[0]));
        // a create carries no elements
        assert_eq!(new_set_elems(&create[0]).len(), 0);

        let fill = sets.vmap_fill_messages();
        assert_eq!(fill.len(), 1);
        assert!(is_new_elem(&fill[0]));
        assert_eq!(new_set_elems(&fill[0]).len(), 1);
    }

    #[test]
    fn no_pod_maps_when_empty() {
        let sets = NamedSets::new("t");
        assert!(sets.vmap_create_messages().is_empty());
        assert!(sets.vmap_fill_messages().is_empty());
        assert!(sets.peer_messages().is_empty());
    }

    #[test]
    fn rendered_hash_tracks_elements() {
        let a = Rendered {
            script: "x".into(),
            peers: Vec::new(),
            vmap_create: Vec::new(),
            vmap_fill: Vec::new(),
        };
        let b = Rendered {
            script: "x".into(),
            peers: Vec::new(),
            vmap_create: Vec::new(),
            vmap_fill: Vec::new(),
        };
        assert_eq!(a.hash(), b.hash(), "hash must be deterministic");

        let mut sets = NamedSets::new("t");
        sets.push_simple_v4("s".into(), vec![v4("10.0.0.1")]);
        let c = Rendered {
            script: "x".into(),
            peers: sets.peer_messages(),
            vmap_create: Vec::new(),
            vmap_fill: Vec::new(),
        };
        assert_ne!(a.hash(), c.hash(), "element change must change the hash");
    }

    fn is_new_set(m: &Message) -> bool {
        matches!(
            m.payload,
            NetlinkPayload::InnerMessage(NetfilterMessage {
                inner: NetfilterMessageInner::NfTables(NfTablesMessage::NewSet(_)),
                ..
            })
        )
    }

    fn is_new_elem(m: &Message) -> bool {
        matches!(
            m.payload,
            NetlinkPayload::InnerMessage(NetfilterMessage {
                inner: NetfilterMessageInner::NfTables(NfTablesMessage::NewSetElement(_)),
                ..
            })
        )
    }

    fn new_set_elems(m: &Message) -> Vec<Vec<SetElementAttribute>> {
        let NetlinkPayload::InnerMessage(NetfilterMessage {
            inner: NetfilterMessageInner::NfTables(NfTablesMessage::NewSetElement(m)),
            ..
        }) = &m.payload
        else {
            return Vec::new();
        };
        m.attributes
            .iter()
            .find_map(|a| match a {
                SetElementList::Elements(e) => Some(e),
                _ => None,
            })
            .into_iter()
            .flatten()
            .filter_map(|item| match item {
                ListAttribute::Element(attrs) => Some(attrs.clone()),
                _ => None,
            })
            .collect()
    }

    use netlink_packet_netfilter::nftables::ListAttribute;

    #[test]
    fn render_references_named_sets_and_fills_maps() {
        use crate::kube_watch::Event;
        use kube::runtime::watcher::Event as W;
        use std::sync::Arc;

        let pod: core::Pod = serde_json::from_value(serde_json::json!({
            "metadata": {
                "name": "a",
                "namespace": "default",
                "labels": { "app": "a" },
            },
            "spec": { "nodeName": "n1" },
            "status": { "podIPs": [ { "ip": "10.0.0.1" } ] },
        }))
        .expect("pod");

        // ingress rule: from ipBlock 192.168.42.0/24 except 192.168.42.5
        let np: networking::NetworkPolicy = serde_json::from_value(serde_json::json!({
            "metadata": { "name": "np", "namespace": "default" },
            "spec": {
                "podSelector": { "matchLabels": { "app": "a" } },
                "policyTypes": ["Ingress"],
                "ingress": [ {
                    "from": [ { "ipBlock": {
                        "cidr": "192.168.42.0/24",
                        "except": ["192.168.42.5/32"],
                    } } ],
                } ],
            },
        }))
        .expect("netpol");

        let mut state = State::new();
        state.ingest(&Event::Pod(Arc::new(W::InitApply(pod))));
        state.ingest(&Event::Pod(Arc::new(W::InitDone)));
        state.ingest(&Event::NetworkPolicy(Arc::new(W::InitApply(np))));
        state.ingest(&Event::NetworkPolicy(Arc::new(W::InitDone)));
        state.ingest(&Event::Namespace(Arc::new(W::InitDone)));

        let rendered = render(
            &state,
            &Config {
                table: "t".into(),
                ..Default::default()
            },
            "n1",
        );

        // script references the named peer sets and the pod vmap
        assert!(
            rendered.script.contains("ip saddr @np_default_np_i_1_b1_v4"),
            "block set not referenced:\n{}",
            rendered.script
        );
        assert!(
            rendered
                .script
                .contains("ip saddr != @np_default_np_i_1_b1_v4_exc"),
            "except set not referenced:\n{}",
            rendered.script
        );
        assert!(
            rendered.script.contains("ip daddr vmap @pods_ingress"),
            "pod vmap not referenced:\n{}",
            rendered.script
        );
        // inline elements are gone
        assert!(!rendered.script.contains("192.168.42.0/24"));

        // netlink carries the set/map contents
        assert!(!rendered.peers.is_empty());
        assert_eq!(rendered.vmap_create.len(), 1);
        assert_eq!(rendered.vmap_fill.len(), 1);
    }

    /// Applies a rendered table to the real kernel and dumps it.
    ///
    /// Requires `CAP_NET_ADMIN`; run with `sudo -E cargo test -- --ignored`.
    #[ignore = "requires CAP_NET_ADMIN and a real kernel"]
    #[tokio::test]
    async fn render_applies_to_kernel() {
        use crate::kube_watch::Event;
        use kube::runtime::watcher::Event as W;
        use std::process::Command;
        use std::sync::Arc;

        let table = "knls-test-netpol";
        let _ = Command::new("nft")
            .args(["delete", "table", "inet", table])
            .status();

        let pod: core::Pod = serde_json::from_value(serde_json::json!({
            "metadata": { "name": "a", "namespace": "default", "labels": { "app": "a" } },
            "spec": { "nodeName": "n1" },
            "status": { "podIPs": [ { "ip": "10.0.0.1" }, { "ip": "fd00::1" } ] },
        }))
        .expect("pod");
        let peer: core::Pod = serde_json::from_value(serde_json::json!({
            "metadata": { "name": "b", "namespace": "other", "labels": { "app": "b" } },
            "spec": { "nodeName": "n2" },
            "status": { "podIPs": [ { "ip": "10.0.0.2" } ] },
        }))
        .expect("peer");
        let np: networking::NetworkPolicy = serde_json::from_value(serde_json::json!({
            "metadata": { "name": "np", "namespace": "default" },
            "spec": {
                "podSelector": { "matchLabels": { "app": "a" } },
                "policyTypes": ["Ingress", "Egress"],
                "ingress": [ {
                    "from": [ { "ipBlock": { "cidr": "192.168.42.0/24", "except": ["192.168.42.5/32"] } } ],
                    "ports": [ { "protocol": "TCP", "port": 80 } ],
                } ],
                "egress": [ { "to": [ { "podSelector": {} } ] } ],
            },
        }))
        .expect("netpol");

        let mut state = State::new();
        state.ingest(&Event::Pod(Arc::new(W::InitApply(pod))));
        state.ingest(&Event::Pod(Arc::new(W::InitApply(peer))));
        state.ingest(&Event::Pod(Arc::new(W::InitDone)));
        state.ingest(&Event::NetworkPolicy(Arc::new(W::InitApply(np))));
        state.ingest(&Event::NetworkPolicy(Arc::new(W::InitDone)));
        state.ingest(&Event::Namespace(Arc::new(W::InitDone)));

        let rendered = render(
            &state,
            &Config {
                table: table.into(),
                ..Default::default()
            },
            "n1",
        );

        let nl = netfilter::new_link().expect("netlink");
        apply(&nl, table, rendered).await.expect("apply");

        let out = Command::new("nft")
            .args(["list", "table", "inet", table])
            .output()
            .expect("nft");
        let dump = String::from_utf8_lossy(&out.stdout);
        assert!(out.status.success(), "nft list failed: {dump}");
        assert!(dump.contains("192.168.42.0/24"), "block set missing:\n{dump}");
        assert!(dump.contains("goto ingress_pod_default_a"), "vmap missing:\n{dump}");
        assert!(dump.contains("goto egress_pod_default_a"), "vmap missing:\n{dump}");

        let _ = Command::new("nft")
            .args(["delete", "table", "inet", table])
            .status();
    }
}

