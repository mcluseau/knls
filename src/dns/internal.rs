#![allow(clippy::unusual_byte_groupings)]

use eyre::format_err;
use log::debug;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::{
    net::UdpSocket,
    sync::{oneshot, watch},
};

use crate::dns::{self, data, packet};
use crate::{actions, kube_watch::EventReceiver, state::State, worker};

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct Config {
    cluster_domain: String,
    bind: String,
    on_listen: Vec<crate::actions::Action>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            cluster_domain: "cluster.local".into(),
            bind: "127.0.0.1:1053".into(),
            on_listen: vec![],
        }
    }
}

pub async fn watch(
    ctx: Arc<crate::Context>,
    cfg: Config,
    mut events: EventReceiver,
) -> eyre::Result<()> {
    // Bind with std so the socket can be adopted by the responder's own
    // runtime: a tokio socket is tied to the runtime that created it.
    let sock = std::net::UdpSocket::bind(cfg.bind.as_str())?;
    sock.set_nonblocking(true)?;
    actions::run_event(module_path!(), "on_listen", &cfg.on_listen).await?;

    let cluster_domain = data::DomainName::try_from(cfg.cluster_domain.as_str())
        .map_err(|_| format_err!("invalid cluster domain"))?;

    // The responder reads the latest zone from this watch channel; state
    // ingestion never blocks on answering queries.
    let (domain_tx, domain_rx) = watch::channel(Arc::new(data::Domain::new()));

    // Run the responder on its own thread and runtime. A busy main runtime
    // (zone rebuilds, nftables renders) then cannot delay the socket's I/O
    // driver and the queries queued on it.
    let (result_tx, mut result_rx) = oneshot::channel();
    worker::single_thread("dns-responder", move || async move {
        let _ = result_tx.send(run_responder(sock, domain_rx).await);
    })?;

    let mut state = State::new(ctx.node_name.clone());

    loop {
        use std::ops::ControlFlow::*;
        tokio::select! {
            updated = state.ingest_events(&mut events) => {
                match updated {
                    Some(Break(())) => return Ok(()),
                    Some(Continue(())) => continue,
                    None => {}
                }
            }
            result = &mut result_rx => {
                // The responder only finishes on a socket error or when the
                // watch closes; report a failure so the service restarts.
                return match result {
                    Ok(res) => res,
                    Err(e) => Err(e.into()),
                };
            }
        }

        if !state.is_ready() {
            continue;
        }

        let cluster_zone = dns::cluster_zone_from_state(&state, &cluster_domain);
        let mut root = data::Domain::new();
        root.set(&cluster_domain, cluster_zone);
        dns::add_reverse_records(&mut root, &state, &cluster_domain);
        domain_tx.send_replace(Arc::new(root));
    }
}

/// Adopts the pre-bound blocking socket on the worker's runtime.
async fn run_responder(
    sock: std::net::UdpSocket,
    root: watch::Receiver<Arc<data::Domain>>,
) -> eyre::Result<()> {
    let sock = UdpSocket::from_std(sock)?;
    respond(sock, root).await?;
    Ok(())
}

/// Answers DNS queries from the most recently published zone until the watch
/// closes (the service shutting down).
async fn respond(
    sock: UdpSocket,
    mut root_rx: watch::Receiver<Arc<data::Domain>>,
) -> std::io::Result<()> {
    let mut recv_buf = [0; 512];
    let mut root = root_rx.borrow_and_update().clone();
    loop {
        tokio::select! {
            result = sock.recv_from(&mut recv_buf) => {
                let (len, remote) = result?;
                let pkt = &recv_buf[..len];
                handle_req(&sock, pkt, remote, &root).await;
            }
            changed = root_rx.changed() => {
                if changed.is_err() {
                    // end of watch
                    return Ok(());
                }

                root = root_rx.borrow_and_update().clone();
            }
        }
    }
}

const RESPONSE_PACKET: [u8; 12] = [
    0,
    0,
    0b1_0000_0_0_0u8,
    0b0_000_0000u8,
    // no response data
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
];

async fn handle_req(sock: &UdpSocket, pkt: &[u8], remote: SocketAddr, root: &dns::Domain) {
    debug!("recv from {remote} ({} bytes)", pkt.len());

    let resp = match try_handle_req(pkt, root) {
        Ok(v) => v,
        Err(e) => {
            debug!("request handler failed: {e:?}");
            let mut r = Vec::from(RESPONSE_PACKET);
            if let Some(id) = pkt.get(..2) {
                r[0] = id[0];
                r[1] = id[1];
            }
            r[3] |= ((e as isize) as u8) & 0b0000_1111;
            r
        }
    };

    if let Err(e) = sock.send_to(&resp, remote).await {
        debug!("response to {remote} failed: {e}");
    }
}

fn try_handle_req(pkt: &[u8], data: &dns::Domain) -> packet::Result<Vec<u8>> {
    use packet::ResponseCode;

    let mut pkt = packet::Reader::with_header(pkt);

    let qd_count = pkt.qd_count()?;

    let mut resp = packet::Writer::new();
    resp.push_n(&RESPONSE_PACKET);
    resp.set_id(pkt.id()?);
    resp.set_rd(pkt.rd()?);

    if qd_count == 0 {
        // no question
        return Err(ResponseCode::FormatError);
    }
    if qd_count > 1 {
        // won't answer more than one question
        return Err(ResponseCode::Refused);
    }

    // read query
    let name = pkt.next_domain_name()?;
    let rtype = pkt.next_u16()?;
    let class = pkt.next_u16()?;

    // read RRs
    for _ in 0..pkt.an_count()? {
        pkt.next_rr()?;
    }
    for _ in 0..pkt.ns_count()? {
        pkt.next_rr()?;
    }

    let mut opt = None;
    for _ in 0..pkt.ar_count()? {
        let (_, record) = pkt.next_rr()?;
        if record.rtype() == &RecordType::OPT {
            opt = Some(record);
        }
    }

    // write question back
    let name_offset = resp.pos() as u16;
    resp.push_dn(&name);
    resp.push_u16(rtype);
    resp.push_u16(class);
    resp.set_qd_count(1);

    if class != 1 {
        return Ok(resp.into_vec());
    }

    debug!(
        "query rtype: {rtype} ({}) for name: {name}",
        RecordType::from(rtype)
    );

    use data::RecordType;
    let rtype = RecordType::from(rtype);
    if rtype == RecordType::Unknown {
        debug!("invalid rtype: {rtype}");
        return Err(ResponseCode::FormatError);
    };

    let mut resolve = Resolve::new(data, rtype);
    resolve.resolve(&mut resp, name, name_offset)?;

    resp.set_an_count(resolve.an_count);

    resp.set_ns_count(resolve.ns.len() as u16);
    for (dn, rr) in resolve.ns {
        resp.push_dn(&dn);
        resp.push_record(&rr);
    }

    if let Some(opt) = opt {
        resp.set_ar_count(1);
        resp.push(0); // ROOT label
        let udp_size = opt.class(); // TODO .min(something); + handling of larger packets
        let rcode_and_flags = 0; // we know nothing but udp_size for now
        resp.push_record(&data::Record::opt(udp_size, rcode_and_flags, &[]));
    }

    debug!("reply ok");

    Ok(resp.into_vec())
}

struct Resolve<'t> {
    root: &'t data::Domain,
    rtype: data::RecordType,
    an_count: u16,
    cname_depth: u8,
    ns: Vec<(data::DomainName, data::Record)>,
}
impl<'t> Resolve<'t> {
    fn new(root: &'t data::Domain, rtype: data::RecordType) -> Self {
        Resolve {
            root,
            rtype,
            an_count: 0,
            cname_depth: 0,
            ns: Vec::new(),
        }
    }

    fn resolve(
        &mut self,
        resp: &mut packet::Writer,
        name: data::DomainName,
        name_offset: u16,
    ) -> packet::Result<()> {
        use packet::ResponseCode;

        let jump = packet::Label::Jump {
            offset: name_offset,
        };

        let mut cname = None;

        let resolved = self.root.resolve(&name);

        let mut answered = false;

        for record in resolved.domain.iter().flat_map(|d| d.records().iter()) {
            debug!("evaluating {record:?}");
            if record.rtype() == &self.rtype {
                resp.push_label(&jump);
                record.push_to(resp);
                self.an_count += 1;
                answered = true;
            } else if record.rtype() == &data::RecordType::CNAME && cname.is_none() {
                cname = Some(record);
            }
        }

        let Some(cname) = cname else {
            if self.cname_depth == 0
                && let Some(soa) = resolved.soa
            {
                resp.set_aa(true);

                if !answered {
                    self.ns.push((soa.0, soa.1.clone()));
                }

                if resolved.domain.is_none() {
                    resp.set_rcode(ResponseCode::NameError);
                }
            }

            return Ok(()); // finished
        };

        resp.push_label(&jump);

        let name_offset = resp.pos() as u16;
        resp.push_record(cname);
        self.an_count += 1;

        if self.cname_depth == 16 {
            return Ok(());
        }
        self.cname_depth += 1;

        // cname rdata is a domain name
        let name = packet::Reader::new(cname.rdata()).next_domain_name()?;

        self.resolve(resp, name, name_offset)
    }
}
