use super::{EgressRule, IngressRule, Policy};
use crate::{
    kube_watch::EventReceiver,
    state::{keys, Namespace, Pod},
};
use cidr::{IpCidr, Ipv4Cidr, Ipv6Cidr};
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
use std::sync::Arc;
use xxhash_rust::xxh3;

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct Config {
    /// nftables table's name
    #[serde(default = "default_table")]
    table: String,
}
fn default_table() -> String {
    "kube-netpol".into()
}

crate::multimap!(
    State {
        netpols: NetworkPolicy(networking::NetworkPolicy) => Policy,
        pods: Pod(core::Pod) => Pod,
        nses: Namespace(core::Namespace) => Namespace,
    }
);

pub async fn watch(ctx: Arc<crate::Context>, cfg: Config, mut events: EventReceiver) -> Result<()> {
    let mut prev = 0;

    let node_name = ctx.node_name.as_str();

    let mut state = State::new();

    loop {
        let Some(updated) = state.ingest_events(&mut events).await else {
            return Ok(());
        };
        if !updated || !state.is_ready() {
            continue;
        }

        let mut rules = String::new();
        macro_rules! w {
            ($($tt:tt)*) => {
                rules.write_fmt(format_args!($($tt)*)).unwrap();
                rules.push('\n');
            };
        }

        let mut pod_ingress = String::new();
        let mut pod_egress = String::new();
        let mut pod_ingress6 = String::new();
        let mut pod_egress6 = String::new();

        let helper = NetpolHelper { state: &state };

        w!("table inet {} {{}}", cfg.table);
        w!("delete table inet {};", cfg.table);
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
                        pod_ingress.push_str(&format!("\n    {ip} : goto {chain},"));
                    }
                    for ip in &pod.ipsv6 {
                        pod_ingress6.push_str(&format!("\n    {ip} : goto {chain},"));
                    }
                    w!("  chain {chain} {{");
                }
                w!("    jump ingress_netpol_{np_ns}_{np_name};");
            }
            if recorded {
                w!("    reject;");
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
                        pod_egress.push_str(&format!("\n    {ip} : goto {chain},"));
                    }
                    for ip in &pod.ipsv6 {
                        pod_egress6.push_str(&format!("\n    {ip} : goto {chain},"));
                    }
                    w!("  chain {chain} {{");
                }
                w!("    jump egress_netpol_{np_ns}_{np_name};");
            }
            if recorded {
                w!("    reject;");
                w!("  }}");
            }
        }

        for (np_key, np) in state.netpols.iter() {
            let (ns, name) = np_key.as_str();
            if !used_netpols.contains(&(ns, name)) {
                continue;
            }

            if np.is_ingress {
                w!("  chain ingress_netpol_{ns}_{name} {{");
                for rule in &np.ingress {
                    w!("{}", helper.ingress_rules(rule));
                }
                w!("  }}");
            }

            if np.is_egress {
                w!("  chain egress_netpol_{ns}_{name} {{");
                for rule in &np.egress {
                    w!("{}", helper.egress_rules(rule));
                }
                w!("  }}");
            }
        }

        if !pod_ingress.is_empty() {
            w!("  map pods_ingress {{");
            w!("    type ipv4_addr : verdict;");
            w!("    elements = {{{pod_ingress}}}");
            w!("  }}");
        }
        if !pod_ingress6.is_empty() {
            w!("  map pods_ingress6 {{");
            w!("    type ipv6_addr : verdict;");
            w!("    elements = {{{pod_ingress6}}}");
            w!("  }}");
        }
        if !pod_egress.is_empty() {
            w!("  map pods_egress {{");
            w!("    type ipv4_addr : verdict;");
            w!("    elements = {{{pod_egress}}}");
            w!("  }}");
        }
        if !pod_egress6.is_empty() {
            w!("  map pods_egress6 {{");
            w!("    type ipv6_addr : verdict;");
            w!("    elements = {{{pod_egress6}}}");
            w!("  }}");
        }
        w!("  chain pods_filter {{");
        w!("    type filter hook forward priority 0; policy accept;");
        if !pod_ingress.is_empty() {
            w!("    ip daddr vmap @pods_ingress;");
        }
        if !pod_egress.is_empty() {
            w!("    ip saddr vmap @pods_egress;");
        }
        if !pod_ingress6.is_empty() {
            w!("    ip6 daddr vmap @pods_ingress6;");
        }
        if !pod_egress6.is_empty() {
            w!("    ip6 saddr vmap @pods_egress6;");
        }
        w!("  }}");

        w!("}}");

        let h = xxh3::xxh3_128(rules.as_bytes());

        if prev == h {
            continue;
        }

        log::debug!("applying nft rules:\n{rules}");

        let mut nft = tokio::process::Command::new("nft")
            .args(["-f", "-"])
            .stdin(std::process::Stdio::piped())
            .spawn()?;

        let mut rules_rd = std::io::Cursor::new(rules.as_bytes());
        let stdin = nft.stdin.as_mut().expect("stdin must exist");
        tokio::io::copy(&mut rules_rd, stdin).await?;

        let status = nft.wait().await?;
        if !status.success() {
            error!("nft failed");
            for (i, line) in rules.lines().enumerate() {
                eprintln!("  {:3}: {line}", i + 1);
            }
            continue;
        }

        prev = h;
    }
}

struct NetpolHelper<'t> {
    state: &'t State,
}

impl<'t> NetpolHelper<'t> {
    fn ingress_rules(&self, rule: &IngressRule) -> String {
        let ports = self.ports(&rule.ports);
        self.rules(ports, self.peers("saddr", &rule.from))
    }
    fn egress_rules(&self, rule: &EgressRule) -> String {
        let ports = self.ports(&rule.ports);
        self.rules(ports, self.peers("daddr", &rule.to))
    }

    fn rules(&self, ports: String, peers: Vec<String>) -> String {
        let mut rules = String::new();
        for (i, peer_match) in peers.iter().enumerate() {
            if i != 0 {
                rules.push('\n');
            }
            rules.push_str(&format!("    {ports}{peer_match}accept;"));
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

    fn peers(&self, addr_type: &str, peers: &Option<Vec<NetworkPolicyPeer>>) -> Vec<String> {
        let Some(peers) = peers.as_ref() else {
            return vec!["".into()]; // unspecified = match all
        };
        if peers.is_empty() {
            return vec!["".into()]; // empty = match all
        }

        let mut results = Peers::default();

        for peer in peers {
            if let Some(ref ip_block) = peer.ip_block {
                let Ok(cidr) = (ip_block.cidr.parse::<IpCidr>())
                    .inspect_err(|e| error!("invalid ip block (ignored): {}: {e}", ip_block.cidr))
                else {
                    continue;
                };
                let except = ip_block.except.as_deref().unwrap_or(&[]);
                match cidr {
                    IpCidr::V4(cidr) => {
                        if let Some(ib) = IpBlock::new(cidr, except) {
                            results.ip_blocks4.push(ib);
                        }
                    }
                    IpCidr::V6(cidr) => {
                        if let Some(ib) = IpBlock::new(cidr, except) {
                            results.ip_blocks6.push(ib);
                        }
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
                if let Some(ref ns_filter) = ns_filter && ns_filter.iter().all(|v| *v != &key.namespace) {
                    continue;
                }

                if let Some(ref filter) = peer.pod_selector && !filter.matches_pod(key, pod) {
                    continue;
                }

                results.ipsv4.extend(&pod.ipsv4);
                results.ipsv6.extend(&pod.ipsv6);
            }
        }

        results.rules(addr_type)
    }
}

#[derive(Default)]
struct Peers {
    ip_blocks4: Vec<IpBlock<Ipv4Cidr>>,
    ip_blocks6: Vec<IpBlock<Ipv6Cidr>>,
    ipsv4: Set<Ipv4Addr>,
    ipsv6: Set<Ipv6Addr>,
}

impl Peers {
    fn rules(&self, addr_type: &str) -> Vec<String> {
        let mut rules = Vec::with_capacity(self.ip_blocks4.len() + self.ip_blocks6.len() + 2);
        for i in &self.ip_blocks4 {
            rules.push(i.to_ip_rule(addr_type))
        }
        for i in &self.ip_blocks6 {
            rules.push(i.to_ip_rule(addr_type))
        }
        if !self.ipsv4.is_empty() {
            rules.push(self.ipsv4.to_ip_rule(addr_type));
        }
        if !self.ipsv6.is_empty() {
            rules.push(self.ipsv6.to_ip_rule(addr_type));
        }
        rules
    }
}

fn join<I: std::fmt::Display>(s: &mut String, iter: impl Iterator<Item = I>) {
    let mut first = true;
    for i in iter {
        if first {
            first = false
        } else {
            s.push_str(", ");
        }
        s.push_str(&i.to_string());
    }
}

trait ToIpRule {
    fn to_ip_rule(&self, addr_type: &str) -> String;
}

impl ToIpRule for Set<Ipv4Addr> {
    fn to_ip_rule(&self, addr_type: &str) -> String {
        let mut rule = format!("ip {addr_type} {{");
        join(&mut rule, self.iter());
        rule.push_str("} ");
        rule
    }
}

impl ToIpRule for Set<Ipv6Addr> {
    fn to_ip_rule(&self, addr_type: &str) -> String {
        let mut rule = format!("ip6 {addr_type} {{");
        join(&mut rule, self.iter());
        rule.push_str("} ");
        rule
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

impl ToIpRule for IpBlock<Ipv4Cidr> {
    fn to_ip_rule(&self, addr_type: &str) -> String {
        let mut rule = format!("ip {addr_type} {}", self.cidr);
        if !self.except.is_empty() {
            rule.push_str(&format!(" ip {addr_type} != {{"));
            join(&mut rule, self.except.iter());
            rule.push('}');
        }
        rule.push(' ');
        rule
    }
}

impl ToIpRule for IpBlock<Ipv6Cidr> {
    fn to_ip_rule(&self, addr_type: &str) -> String {
        let mut rule = format!("ip6 {addr_type} {}", self.cidr);
        if !self.except.is_empty() {
            rule.push_str(&format!(" ip6 {addr_type} != {{"));
            join(&mut rule, self.except.iter());
            rule.push('}');
        }
        rule.push(' ');
        rule
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
