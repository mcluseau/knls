use log::error;
use std::collections::{BTreeMap as Map, BTreeSet};
use std::net::IpAddr;

use crate::state::{Protocol, ServiceTarget, State};

pub mod internal;

pub mod data;
pub mod packet;

pub use data::{Domain, DomainName, Label, Record};

pub type Config = Map<String, Vec<Entry>>;

#[derive(Debug, serde::Serialize)]
pub enum Entry {
    IP(IpAddr),
    Name(String),
}
impl std::fmt::Display for Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            Self::IP(ip) => match ip {
                IpAddr::V4(ip) => write!(f, "A {ip}"),
                IpAddr::V6(ip) => write!(f, "AAAA {ip}"),
            },
            Self::Name(alias) => write!(f, "CNAME {alias}"),
        }
    }
}

/// The `<name>.<namespace>.svc.<cluster-domain>` name of a Service.
fn service_fqdn(key: &crate::state::keys::Object, cluster_domain: &DomainName) -> DomainName {
    let mut dn = DomainName::unchecked_new(&format!("{}.{}.svc", key.name, key.namespace));
    dn.extend(cluster_domain.clone());
    dn
}

/// The `in-addr.arpa`/`ip6.arpa` name a PTR query for `ip` would use.
fn reverse_name(ip: IpAddr) -> DomainName {
    // The name is the address least-significant first, so the octets are
    // iterated in reverse; IPv4 has one label per octet, IPv6 per nibble.
    match ip {
        IpAddr::V4(ip) => (ip.octets().into_iter().rev())
            .map(|o| Label::unchecked_new(o.to_string()))
            .chain(["in-addr", "arpa"].map(Label::unchecked_new))
            .collect(),
        IpAddr::V6(ip) => (ip.octets().into_iter().rev())
            .flat_map(|b| {
                [
                    Label::unchecked_new(format!("{:x}", b & 0xf)),
                    Label::unchecked_new(format!("{:x}", b >> 4)),
                ]
            })
            .chain(["ip6", "arpa"].map(Label::unchecked_new))
            .collect(),
    }
}

/// Builds the `<cluster-domain>` zone from the cluster state, with the
/// `svc.<ns>.<name>` A/AAAA/CNAME records and the `_<port>._<proto>` SRV records.
pub fn cluster_zone_from_state(state: &State, cluster_domain: &DomainName) -> Domain {
    let ttl = 5;

    let ns_dn = DomainName::unchecked_new("localhost.localdomain");

    let mut domain = Domain::new();

    // add a default SOA
    domain.push_record(
        // @ 5 SOA ns.dns clusteradmin {zone_serial} 7200 1800 86400 {ttl}
        data::Soa {
            mname: ns_dn.clone(),
            rname: DomainName::unchecked_new("cluster-admin"),
            serial: 1,
            refresh: 60,
            retry: ttl,
            expire: 86400,
            minimum: ttl,
        }
        .into_record(5),
    );
    domain.push_record(Record::ns(5, &ns_dn));

    let svc_zone = domain.sub_or_create(Label::new("svc"));

    for (key, svc) in state.maps.services.iter() {
        let zone = svc_zone.sub_or_create(Label::new(&key.namespace));
        let zone = zone.sub_or_create(Label::new(&key.name));

        match &svc.target {
            ServiceTarget::None => { /* noop */ }
            ServiceTarget::Name(name) => match DomainName::try_from(name.as_str()) {
                Ok(dn) => {
                    zone.push_record(Record::cname(ttl, &dn));
                }
                Err(e) => {
                    error!("invalid name {name:?}: {e:?}");
                }
            },
            ServiceTarget::ClusterIPs(ips) => {
                for ip in ips {
                    zone.push_record(Record::alias(ttl, *ip));
                }
            }
            ServiceTarget::Headless => {
                for slice in state.slices(key, svc.internal_traffic.is_local()) {
                    for ep in slice.endpoints.into_iter() {
                        for ip in ep.ips() {
                            zone.push_record(Record::alias(ttl, ip));
                        }
                    }
                }
            }
        };

        // `_<port-name>._<proto>.<svc>.<ns>.svc.<domain>` SRV records, one per
        // named Service port (kube-dns generates them for ClusterIP and
        // headless Services alike). A headless Service may be selectorless,
        // with its ports defined only by the EndpointSlices; include those too.
        let target = service_fqdn(key, cluster_domain);
        let mut srv_ports = BTreeSet::new();
        for (port, port_name) in &svc.ports {
            // kube-dns only publishes SRV records for named ports.
            if port_name.is_empty() {
                continue;
            }
            let (proto, port) = port.protocol_port();
            srv_ports.insert((port_name.clone(), proto, port));
        }
        if matches!(&svc.target, ServiceTarget::Headless) {
            for slice in state.slices(key, svc.internal_traffic.is_local()) {
                for (name, proto, port) in slice.ports {
                    srv_ports.insert((name, proto, port));
                }
            }
        }
        for (port_name, proto, port) in srv_ports {
            let proto = match proto {
                Protocol::TCP => "_tcp",
                Protocol::UDP => "_udp",
                Protocol::SCTP => "_sctp",
            };
            zone.sub_or_create(Label::new(proto))
                .sub_or_create(Label::new(&format!("_{port_name}")))
                .push_record(Record::srv(ttl, 0, 100, port, &target));
        }
    }

    // add entries for slice endpoints with hostname
    for (key, slice) in state.maps.ep_slices.iter() {
        for ep in slice.endpoints.iter() {
            let Some(ref hostname) = ep.hostname else {
                continue;
            };

            let zone = svc_zone.sub_or_create(Label::new(&key.namespace));
            let zone = zone.sub_or_create(Label::new(&key.service_name));
            let zone = zone.sub_or_create(Label::new(hostname));

            for ip in ep.ips() {
                zone.push_record(Record::alias(ttl, ip));
            }
        }
    }

    domain
}

/// Adds the reverse (`in-addr.arpa`/`ip6.arpa`) PTR records for every Service
/// ClusterIP, mapping it back to the Service's `<name>.<ns>.svc.<domain>` name.
pub fn add_reverse_records(root: &mut Domain, state: &State, cluster_domain: &DomainName) {
    let ttl = 5;

    for (key, svc) in state.maps.services.iter() {
        let ServiceTarget::ClusterIPs(ips) = &svc.target else {
            continue;
        };

        let target = service_fqdn(key, cluster_domain);
        for ip in ips {
            root.resolve_or_create(&reverse_name(*ip))
                .push_record(Record::ptr(ttl, &target));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kube_watch::{Change, Event};
    use std::sync::Arc;

    fn ready_state() -> State {
        let svc = serde_json::from_value(serde_json::json!({
            "metadata": { "name": "web", "namespace": "default" },
            "spec": {
                "type": "ClusterIP",
                "clusterIPs": ["10.96.0.10"],
                "ports": [{ "name": "http", "protocol": "TCP", "port": 80 }],
            },
        }))
        .expect("service");

        let mut state = State::new("n1".into());
        state.ingest(&Event::Service(Change::InitApply(Arc::new(svc))));
        state.ingest(&Event::Service(Change::InitDone));
        state
    }

    fn has(domain: &Domain, name: &str, rtype: data::RecordType) -> bool {
        let dn = DomainName::try_from(name).expect("name");
        domain
            .resolve(&dn)
            .domain
            .into_iter()
            .flat_map(|d| d.records())
            .any(|r| r.rtype() == &rtype)
    }

    #[test]
    fn reverse_name_encodes_v4_and_v6() {
        assert_eq!(
            reverse_name("10.96.0.10".parse().expect("ip")).to_string(),
            "10.0.96.10.in-addr.arpa."
        );

        // RFC 3596 §2.5 example.
        assert_eq!(
            reverse_name("4321:0:1:2:3:4:567:89ab".parse().expect("ip")).to_string(),
            "b.a.9.8.7.6.5.0.4.0.0.0.3.0.0.0.2.0.0.0.1.0.0.0.0.0.0.0.1.2.3.4.ip6.arpa."
        );
    }

    #[test]
    fn headless_srv_includes_endpoint_slice_ports() {
        let svc = serde_json::from_value(serde_json::json!({
            "metadata": { "name": "dns-test-service", "namespace": "default" },
            "spec": {
                "type": "ClusterIP",
                "clusterIP": "None",
                "clusterIPs": ["None"],
                "internalTrafficPolicy": "Local",
                "ports": [{ "name": "http", "protocol": "TCP", "port": 80 }],
            },
        }))
        .expect("service");

        let slice = serde_json::from_value(serde_json::json!({
            "apiVersion": "discovery.k8s.io/v1",
            "kind": "EndpointSlice",
            "metadata": {
                "name": "dns-test-service-abc",
                "namespace": "default",
                "labels": { "kubernetes.io/service-name": "dns-test-service" },
            },
            "addressType": "IPv4",
            "endpoints": [{
                "addresses": ["1.2.3.4"],
                "conditions": { "ready": true },
                "nodeName": "n1",
            }],
            "ports": [{ "name": "https", "port": 443, "protocol": "TCP" }],
        }))
        .expect("endpoint slice");

        let mut state = State::new("n1".into());
        state.ingest(&Event::Service(Change::InitApply(Arc::new(svc))));
        state.ingest(&Event::Service(Change::InitDone));
        state.ingest(&Event::EndpointSlice(Change::InitApply(Arc::new(slice))));
        state.ingest(&Event::EndpointSlice(Change::InitDone));

        let cluster_domain = DomainName::try_from("cluster.local").expect("domain");
        let zone = cluster_zone_from_state(&state, &cluster_domain);

        assert!(has(
            &zone,
            "_http._tcp.dns-test-service.default.svc",
            data::RecordType::SRV
        ));
        assert!(has(
            &zone,
            "_https._tcp.dns-test-service.default.svc",
            data::RecordType::SRV
        ));
    }

    #[test]
    fn zone_has_service_srv_and_clusterip_ptr() {
        let state = ready_state();
        let cluster_domain = DomainName::try_from("test.nv").expect("domain");

        let zone = cluster_zone_from_state(&state, &cluster_domain);
        assert!(has(
            &zone,
            "_http._tcp.web.default.svc",
            data::RecordType::SRV
        ));
        assert!(has(&zone, "web.default.svc", data::RecordType::A));

        let mut root = Domain::new();
        root.set(&cluster_domain, zone);
        add_reverse_records(&mut root, &state, &cluster_domain);
        let rev = reverse_name("10.96.0.10".parse().expect("ip"));
        assert!(
            root.resolve(&rev)
                .domain
                .into_iter()
                .flat_map(|d| d.records())
                .any(|r| r.rtype() == &data::RecordType::PTR)
        );
    }
}
