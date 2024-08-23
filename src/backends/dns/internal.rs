use log::{debug, error};
use tokio::net::{ToSocketAddrs, UdpSocket};
use tokio::sync::watch;

use crate::dns;
use crate::dns::{data, packet};

pub async fn watch<A: ToSocketAddrs>(
    mut watcher: crate::watcher::Watcher,
    cluster_domain: String,
    binding: A,
) -> eyre::Result<()> {
    let (tx, rx) = watch::channel(dns::Domain::new());

    let listener = UdpSocket::bind(binding).await?;
    tokio::spawn(async move {
        if let Err(e) = serve_dns(listener, rx).await {
            error!("dns server finished on error {e}");
        } else {
            error!("dns server finished with no error");
        }
        std::process::exit(1);
    });

    let cluster_domain = data::DomainName::try_from(cluster_domain.as_str()).unwrap();

    loop {
        let cluster_zone = watcher.next(dns::cluster_zone_from_state).await?;

        let mut root = data::Domain::new();

        if let Some(zone) = cluster_zone {
            root.set(&cluster_domain, zone);
        }
        tx.send_replace(root);
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

async fn serve_dns(listener: UdpSocket, rx: watch::Receiver<dns::Domain>) -> eyre::Result<()> {
    let mut n = 0;

    let buf = &mut [0; 512];
    loop {
        let (len, remote) = match listener.recv_from(buf).await {
            Ok(v) => v,
            Err(e) => {
                debug!("recv error, ignoring request: {e}");
                continue;
            }
        };

        debug!("recv from {remote} ({len} bytes)");

        let pkt = &buf[0..len];
        let resp = match handle_req(pkt, &rx) {
            Ok(v) => v,
            Err(e) => {
                debug!("request handler failed: {e:?}");
                let mut r = Vec::from(RESPONSE_PACKET);
                r[0] = buf[0];
                r[1] = buf[1];
                r[3] |= ((e as isize) as u8) & 0b0000_1111;
                r
            }
        };

        const COMPARE_TO_OTHER: bool = false;
        if COMPARE_TO_OTHER {
            let sock = UdpSocket::bind("127.0.0.1:0").await?;
            sock.send_to(pkt, "127.0.0.1:1054").await?;

            let buf = &mut [0; 4096];
            let len = sock.recv(buf).await?;
            let expected = &buf[..len];

            if resp != expected {
                let mut b = Vec::new();
                hxdmp::hexdump(pkt, &mut b)?;
                b.extend(b"\n--\n");
                let pos = b.len();
                hxdmp::hexdump(expected, &mut b)?;
                std::fs::write(format!("tmp/{n}.exp.raw"), &b)?;
                b.truncate(pos);
                hxdmp::hexdump(&resp, &mut b)?;
                std::fs::write(format!("tmp/{n}.got.raw"), &b)?;
                n += 1;
            }
        }

        listener.send_to(&resp, remote).await?;
    }
}

#[allow(unused)]
fn hexdump(data: &[u8]) -> String {
    let mut v = Vec::new();
    hxdmp::hexdump(data, &mut v).unwrap();
    String::from_utf8_lossy(&v).to_string()
}

fn handle_req(pkt: &[u8], data: &watch::Receiver<dns::Domain>) -> packet::Result<Vec<u8>> {
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

    let mut resolve = Resolve::new(data.borrow(), rtype);
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

    return Ok(resp.into_vec());
}

struct Resolve<'t> {
    root: watch::Ref<'t, data::Domain>,
    rtype: data::RecordType,
    an_count: u16,
    cname_depth: u8,
    ns: Vec<(data::DomainName, data::Record)>,
}
impl<'t> Resolve<'t> {
    fn new(root: watch::Ref<'t, data::Domain>, rtype: data::RecordType) -> Self {
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

        for record in resolved.domain.iter().map(|d| d.records().iter()).flatten() {
            debug!("evaluating {record:?}");
            if record.rtype() == &self.rtype {
                resp.push_label(&jump);
                record.push_to(resp);
                self.an_count += 1;
                answered = true;
            } else if record.rtype() == &data::RecordType::CNAME {
                if cname.is_none() {
                    cname = Some(record);
                }
            }
        }

        let Some(cname) = cname else {
            if self.cname_depth == 0 {
                if let Some(soa) = resolved.soa {
                    resp.set_aa(true);

                    if !answered {
                        self.ns.push((soa.0, soa.1.clone()));
                    }

                    if resolved.domain.is_none() {
                        resp.set_rcode(ResponseCode::NameError);
                    }
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
