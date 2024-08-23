use eyre::{format_err, Result};
use log::{debug, error, info};
use std::collections::BTreeMap as Map;
use std::io::{self, Write};
use std::net::IpAddr;
use std::process::Stdio;

use crate::change;
use crate::state::{
    keys, proxy, LocalEndpoint, LocalEndpointSlice, Node, ProtoPort, Protocol, SessionAffinity,
};
use crate::watcher::Watcher;

const SERVICE_IPS: &'static str = "service_ips";
const SERVICE_NODEPORTS: &'static str = "service_nodeports";
const NEED_MASQ_V4: &'static str = "need_masquerade";
const NEED_MASQ_V6: &'static str = "need_masquerade6";

pub async fn watch(
    table_name: String,
    disable_nodeports: bool,
    mut watcher: Watcher,
) -> Result<()> {
    let mut n = 0;
    let mut table = TableTracker::new(format!("inet {table_name}"));

    loop {
        let Some((my_node, cfg)) = watcher
            .next(|state| {
                Some((
                    state.my_node.get().cloned()?,
                    (proxy::from_state(state, disable_nodeports)?),
                ))
            })
            .await?
        else {
            continue;
        };

        if log::log_enabled!(log::Level::Debug) {
            nft_dump_table_to(&table_name, &format!("nftables.{:03}.initial", n)).await?;
        }

        if let Err(e) = update_table(&mut table, &my_node, &cfg).await {
            if log::log_enabled!(log::Level::Debug) {
                let err_file = format!("nftables.{:03}.conf", n);
                error!("partial update of table failed ({e}, see {err_file}); doing a full update");
                tokio::fs::write(&err_file, &table.nft).await?;
                n += 1;
            } else {
                error!("partial update of table failed ({e}); doing a full update");
            }

            table.clear();
            if let Err(e) = update_table(&mut table, &my_node, &cfg).await {
                error!("full update failed ({e}), will retry on next update");
                table.clear();
                continue;
            }
        } else if log::log_enabled!(log::Level::Debug) && !table.nft.is_empty() {
            let out_file = format!("nftables.{:03}.conf", n);
            tokio::fs::write(&out_file, &table.nft).await?;
            debug!("nft input saved to {out_file}");
            n += 1;
        }

        table.update_done();
    }
}

async fn nft_dump_table_to(table_name: &str, out_file: &str) -> eyre::Result<()> {
    let mut out = tokio::fs::File::create(&out_file).await?;

    let child = tokio::process::Command::new("nft")
        .args(["list", "table", "inet", table_name])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;

    let mut stdout = child.stdout.unwrap();
    tokio::io::copy(&mut stdout, &mut out).await?;

    debug!("nft state saved to {out_file}");
    Ok(())
}

async fn update_table(table: &mut TableTracker, my_node: &Node, cfg: &proxy::State) -> Result<()> {
    table.prepare()?;

    // ----------------------------------------
    for (key, svc) in cfg.iter() {
        write_service_slices_elements(table, &my_node, key, &svc, false, &svc.internal_slices)?;

        if let Some(external_slices) = svc.external_slices.as_ref() {
            write_service_slices_elements(table, &my_node, key, &svc, true, &external_slices)?;
        };
    }

    // ----------------------------------------
    table.ctr(CtrKind::Map, "service_ips", |buf| {
        writeln!(
            buf,
            concat!(
                "  comment \"ClusterIP, ExternalIP and LoadBalancer IP traffic\"\n",
                "  type ipv4_addr . inet_proto . inet_service : verdict"
            )
        )
    })?;

    for (key, svc) in cfg.iter().filter(|(_, svc)| !svc.cluster_ips.is_empty()) {
        let svc_chain = svc_chain(key);
        let svc_chain_ext = svc_chain_ext(key, svc);

        for port in &svc.ports {
            let (proto, port) = port.0.protocol_port();
            let proto = nft_proto(proto);

            for ip in &svc.cluster_ips {
                table.map_element(
                    SERVICE_IPS,
                    format!("{ip} . {proto} . {port}"),
                    format!("goto {svc_chain}"),
                )?;
            }
            for ip in &svc.external_ips {
                table.map_element(
                    SERVICE_IPS,
                    format!("{ip} . {proto} . {port}"),
                    format!("goto {svc_chain_ext}"),
                )?;
            }
        }
    }

    // ----------------------------------------
    table.ctr(CtrKind::Map, SERVICE_NODEPORTS, |buf| {
        writeln!(buf, "  comment \"NodePort traffic\"")?;
        writeln!(buf, "  type inet_proto . inet_service : verdict")
    })?;

    for (key, svc) in cfg.iter().filter(|(_, svc)| !svc.cluster_ips.is_empty()) {
        let svc_chain_ext = svc_chain_ext(key, svc);

        for port in &svc.node_ports {
            let (proto, port) = port.0.protocol_port();
            let proto = nft_proto(proto);

            table.map_element(
                SERVICE_NODEPORTS,
                format!("{proto} . {port}"),
                format!("goto {}", svc_chain_ext),
            )?;
        }
    }

    // ----------------------------------------
    table.ctr(CtrKind::Chain, "dispatch", |buf| {
        writeln!(
            buf,
            concat!(
                "  ip daddr . ip protocol . th dport vmap @service_ips;\n",
                "  fib daddr type local ip protocol . th dport vmap @service_nodeports;"
            )
        )
    })?;

    // ----------------------------------------
    table.ctr(CtrKind::Chain, "a_hook_dnat_prerouting", |buf| {
        writeln!(buf, "  type nat hook prerouting priority 0;")?;
        writeln!(buf, "  jump dispatch;")
    })?;
    table.ctr(CtrKind::Chain, "a_hook_dnat_output", |buf| {
        writeln!(buf, "  type nat hook output priority 0;")?;
        writeln!(buf, "  jump dispatch;")
    })?;

    // ----------------------------------------
    table.ctr(CtrKind::Set, "need_masquerade", |buf| {
        writeln!(buf, "  type ipv4_addr . ipv4_addr . ipv4_addr")
    })?;
    table.ctr(CtrKind::Set, "need_masquerade6", |buf| {
        writeln!(buf, "  type ipv6_addr . ipv6_addr . ipv6_addr")
    })?;

    for (_, svc) in cfg.iter().filter(|(_, svc)| !svc.cluster_ips.is_empty()) {
        for ep in svc.internal_endpoints().filter(|ep| ep.node_local) {
            set_need_masquerade_for(table, ep, svc.cluster_ips.iter(), &my_node.ips)?;
        }
        for ep in svc.external_endpoints().filter(|ep| ep.node_local) {
            set_need_masquerade_for(table, ep, svc.external_ips.iter(), &my_node.ips)?;
        }
    }

    table.ctr(CtrKind::Chain, "a_hook_dnat_postrouting", |buf| {
        writeln!(buf, "  type nat hook postrouting priority 0;")?;
        writeln!(
            buf,
            "  ip saddr . ip daddr . ct original ip daddr @need_masquerade masquerade;"
        )
    })?;

    // ----------------------------------------
    for (kind, ctr_name) in table.ctrs.current_keys() {
        let deleted: Box<dyn Iterator<Item = &String>> = match kind {
            CtrKind::Set => Box::new(table.sets.get(ctr_name).unwrap().deleted()),
            CtrKind::Map => Box::new(table.maps.get(ctr_name).unwrap().deleted()),
            _ => {
                continue;
            }
        };

        for key in deleted {
            writeln!(
                &mut table.nft,
                "delete element {} {ctr_name} {{ {key} }}",
                table.table
            )?;
        }
    }

    for (kind, name) in table.ctrs.deleted() {
        writeln!(&mut table.nft, "delete {kind} {} {name};", table.table)?;
    }

    // ----------------------------------------
    if table.nft.is_empty() {
        return Ok(());
    }

    let mut child = tokio::process::Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .spawn()?;

    use tokio::io::AsyncWriteExt;
    let stdin = child.stdin.as_mut().unwrap();
    if let Err(e) = stdin.write_all(&table.nft).await {
        error!("nft's stdin write failed: {e}");
    }

    let status = child.wait().await?;
    if status.success() {
        Ok(())
    } else {
        Err(format_err!("nft command failed ({status})"))
    }
}

fn obj_chain(prefix: &str, key: &keys::Object) -> String {
    format!("{prefix}_{}_{}", key.namespace, key.name)
}

fn svc_chain(key: &keys::Object) -> String {
    obj_chain("svc", key)
}

fn svc_chain_ext(key: &keys::Object, svc: &proxy::Service) -> String {
    let mut base = svc_chain(key);
    if svc.external_slices.is_some() {
        base.push_str("_ext")
    }
    base
}

fn affinity_set(key: &keys::Object, ip_version: char) -> String {
    obj_chain(&format!("affinity{ip_version}"), key)
}

fn write_service_slices_elements(
    table: &mut TableTracker,
    my_node: &Node,
    key: &keys::Object,
    svc: &proxy::Service,
    ext: bool,
    slices: &Vec<LocalEndpointSlice>,
) -> eyre::Result<()> {
    let svc_chain = if ext {
        svc_chain_ext(key, svc)
    } else {
        svc_chain(key)
    };

    table.ctr(CtrKind::Map, svc_chain.clone(), |buf| {
        writeln!(buf, "  typeof numgen random mod 1 : verdict")
    })?;

    match svc.session_affinity {
        SessionAffinity::None => {}
        SessionAffinity::ClientIP { timeout } => {
            for ipv in ['4', '6'] {
                table.ctr(CtrKind::Set, affinity_set(key, ipv), |buf| {
                    writeln!(buf, "  type ipv{ipv}_addr . ipv{ipv}_addr")?;
                    writeln!(buf, "  flags timeout; timeout {timeout}s;")
                })?;
            }
        }
    }

    let mut pre_rules = Vec::new();

    let mut n_ipv4 = 0;
    let mut n_ipv6 = 0;

    for slice in slices {
        for ep in &slice.endpoints {
            for ip in ep.ips() {
                let (ip_hex, n) = match ip {
                    IpAddr::V4(ip) => (hex::encode(ip.octets()), &mut n_ipv4),
                    IpAddr::V6(ip) => (hex::encode(ip.octets()), &mut n_ipv6),
                };

                let ep_chain = format!("{svc_chain}_ep_{ip_hex}");

                table.ctr(CtrKind::Chain, &ep_chain, |buf| {
                    match svc.session_affinity {
                        SessionAffinity::None => {}
                        SessionAffinity::ClientIP { .. } => {
                            let affinity_set = affinity_set(
                                key,
                                match ip {
                                    IpAddr::V4(_) => '4',
                                    IpAddr::V6(_) => '6',
                                },
                            );
                            writeln!(
                                pre_rules,
                                "  ip saddr . {ip} @{affinity_set} goto {ep_chain}"
                            )?;
                            writeln!(buf, "  update @{affinity_set} {{ ip saddr . {ip} }}")?;
                        }
                    };

                    let mut dnat = DnatWriter {
                        content: buf,
                        my_ips: &my_node.ips,
                        slice,
                        ip,
                        node_port: false,
                    };

                    for (port, target_port) in &svc.ports {
                        dnat.write_port(port, target_port)?;
                    }

                    dnat.node_port = true;
                    for (port, target_port) in &svc.node_ports {
                        dnat.write_port(port, target_port)?;
                    }

                    Ok(())
                })?;

                table.map_element(&svc_chain, format!("{n}"), format!("goto {}", ep_chain))?;
                *n += 1;
            }
        }
    }

    table.ctr(CtrKind::Chain, svc_chain.clone(), |buf| {
        buf.extend(pre_rules);

        for (n, nfproto) in [(n_ipv4, "ipv4"), (n_ipv6, "ipv6")] {
            if n == 0 {
                writeln!(buf, "  meta nfproto {nfproto} reject")?;
            } else {
                writeln!(
                    buf,
                    "  meta nfproto ipv4 numgen random mod {n} vmap @{svc_chain}"
                )?;
            }
        }
        Ok(())
    })?;

    Ok(())
}

struct DnatWriter<'t> {
    content: &'t mut Vec<u8>,
    my_ips: &'t Vec<IpAddr>,
    slice: &'t LocalEndpointSlice,
    ip: &'t IpAddr,
    node_port: bool,
}

impl<'t> Write for DnatWriter<'t> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.content.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.content.flush()
    }
}

impl<'t> DnatWriter<'t> {
    fn write_port(&mut self, port: &ProtoPort, port_name: &str) -> io::Result<()> {
        let Some(target_port) = self.slice.target_ports.get(port_name) else {
            return Ok(());
        };

        let ipvx = match self.ip {
            IpAddr::V4(_) => "ipv4",
            IpAddr::V6(_) => "ipv6",
        };
        let (protocol, port) = port.protocol_port();
        let protocol = nft_proto(protocol);

        write!(self, "  ")?;
        if self.node_port {
            write!(self, "fib daddr type local ")?;
        }

        write!(self, "meta nfproto {ipvx} {protocol} dport {port} ")?;

        let ip = self.ip;
        return if self.my_ips.contains(ip) {
            writeln!(self, "redirect to {target_port}")
        } else {
            writeln!(self, "dnat to {ip}:{target_port}")
        };
    }
}

fn set_need_masquerade_for<'t>(
    table: &mut TableTracker,
    ep: &LocalEndpoint,
    ips: impl Iterator<Item = &'t IpAddr>,
    my_ips: &Vec<IpAddr>,
) -> Result<()> {
    for svc_ip in ips {
        let (set, ep_ip) = match svc_ip {
            IpAddr::V4(_) => (NEED_MASQ_V4, ep.ipv4),
            IpAddr::V6(_) => (NEED_MASQ_V6, ep.ipv6),
        };
        let Some(ep_ip) = ep_ip else {
            continue;
        };
        if my_ips.contains(&ep_ip) {
            continue;
        };
        table.set_element(set, format!("{ep_ip} . {ep_ip} . {svc_ip}"))?;
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum CtrKind {
    Chain,
    Set,
    Map,
}
impl std::fmt::Display for CtrKind {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        use CtrKind::*;
        f.write_str(match self {
            Chain => "chain",
            Set => "set",
            Map => "map",
        })
    }
}

struct TableTracker {
    table: String,
    has_table: bool,
    ctrs: change::Tracker<(CtrKind, String), u128>,
    sets: Map<String, change::Tracker<String, ()>>,
    maps: Map<String, change::Tracker<String, u128>>,
    maps_to_define: Map<String, Vec<u8>>,
    nft: Vec<u8>,
    buf: Vec<u8>,
}
impl TableTracker {
    fn new(name: String) -> Self {
        Self {
            table: name,
            has_table: false,
            ctrs: change::Tracker::new(),
            sets: Map::new(),
            maps: Map::new(),
            maps_to_define: Map::new(),
            nft: Vec::with_capacity(1024),
            buf: Vec::with_capacity(1024),
        }
    }

    fn clear(&mut self) {
        self.has_table = false;
        self.ctrs.clear();
        self.sets.clear();
        self.maps.clear();
        self.reset_bufs();
    }

    fn update_done(&mut self) {
        self.has_table = true;

        for (kind, key) in self.ctrs.deleted() {
            match kind {
                CtrKind::Set => {
                    self.sets.remove(key);
                }
                CtrKind::Map => {
                    self.maps.remove(key);
                }
                _ => {}
            }
        }

        self.ctrs.update_done();
        for map in self.maps.values_mut() {
            map.update_done();
        }
        for set in self.sets.values_mut() {
            set.update_done();
        }
        self.reset_bufs();
    }

    #[allow(unused)]
    fn update_failed(&mut self) {
        self.ctrs.update_failed();
        for map in self.maps.values_mut() {
            map.update_failed();
        }
        for set in self.sets.values_mut() {
            set.update_failed();
        }
        self.reset_bufs();
    }

    fn reset_bufs(&mut self) {
        self.maps_to_define.clear();
        Self::reset_buf(&mut self.nft);
        Self::reset_buf(&mut self.buf);
    }

    fn reset_buf(buf: &mut Vec<u8>) {
        if buf.capacity() > 1024 {
            *buf = Vec::with_capacity(1024);
        } else {
            buf.clear();
        }
    }

    fn prepare(&mut self) -> io::Result<()> {
        if self.has_table {
            return Ok(());
        }

        let table = &self.table;

        info!("assuming no table, will recreate table {table}");

        writeln!(self.nft, "table {table} {{}};")?;
        writeln!(self.nft, "delete table {table};")?;
        writeln!(self.nft, "table {table} {{}};")?;
        Ok(())
    }

    // set a contrainer, writing to its content. Returns false if unchanged, true otherwise.
    fn ctr<F>(&mut self, kind: CtrKind, name: impl ToString, write_value: F) -> io::Result<bool>
    where
        F: FnOnce(&mut Vec<u8>) -> io::Result<()>,
    {
        self.buf.clear();
        write_value(&mut self.buf)?;

        let h = hash(&self.buf);

        let name = name.to_string();

        let Some(change) = self.ctrs.check((kind.clone(), name.clone()), &h) else {
            // there's an nft bug when writing chains with map ref: the map must be defined in the
            // script otherwise it fails (even if the map was defined in a previous iteration).
            self.maps_to_define.insert(name.clone(), self.buf.clone());
            return Ok(false);
        };

        let nft = &mut self.nft;
        let table = &self.table;

        match change.kind {
            change::Kind::Created => match kind {
                CtrKind::Set => {
                    self.sets.insert(name.clone(), change::Tracker::new());
                }
                CtrKind::Map => {
                    self.maps.insert(name.clone(), change::Tracker::new());
                }
                _ => {}
            },
            change::Kind::Modified => {
                writeln!(nft, "flush {kind} {table} {name};")?;
            }
        }

        // redefine maps to workaround nft bug
        for token in self.buf.split(|b| b" ;\t\n".contains(b)) {
            if token.get(0) != Some(&b'@') {
                continue; // not a ref
            }
            let name = String::from_utf8_lossy(&token[1..]).to_string();
            let Some(def) = self.maps_to_define.get(&name) else {
                continue; // not a ref to a map
            };
            writeln!(nft, "map {table} {name} {{")?;
            nft.write(def)?;
            writeln!(nft, "}}")?;
            self.maps_to_define.remove(&name);
        }

        // write the container & its content
        writeln!(nft, "{kind} {table} {name} {{")?;
        nft.write(&self.buf)?;
        writeln!(nft, "}};")?;

        change.set(h);
        Ok(true)
    }

    fn map_element(&mut self, map_name: &str, key: String, value: String) -> io::Result<()> {
        let h = xxhash_rust::xxh3::xxh3_128(value.as_bytes());
        let Some(change) = self
            .maps
            .get_mut(map_name)
            .unwrap() // 'element' must be called before
            .check(key, &h)
        else {
            return Ok(());
        };

        let table = &self.table;
        let key = change.key();

        match change.kind {
            change::Kind::Created => {}
            change::Kind::Modified => {
                writeln!(self.nft, "delete element {table} {map_name} {{ {key} }}")?;
            }
        };
        writeln!(
            self.nft,
            "add element {table} {map_name} {{ {key} : {value} }}"
        )?;

        change.set(h);

        Ok(())
    }

    fn set_element(&mut self, set_name: &str, key: String) -> io::Result<()> {
        let Some(change) = self
            .sets
            .get_mut(set_name)
            .unwrap() // 'element' must be call before
            .check(key, &())
        else {
            return Ok(());
        };

        let table = &self.table;
        let key = change.key();

        match change.kind {
            change::Kind::Created => {
                writeln!(self.nft, "add element {table} {set_name} {{ {key} }}")?;
            }
            change::Kind::Modified => {
                unreachable!();
            }
        };

        change.set(());

        Ok(())
    }
}

#[cfg(test)]
mod tests;

fn nft_proto(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::TCP => "tcp",
        Protocol::UDP => "udp",
        Protocol::SCTP => "sctp",
    }
}

fn hash(content: &Vec<u8>) -> u128 {
    use xxhash_rust::xxh3;
    xxh3::xxh3_128(content.as_slice())
}
