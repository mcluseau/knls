use log::error;
use std::collections::BTreeMap as Map;
use std::net::IpAddr;

use crate::state::{ServiceTarget, State};

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

pub fn cluster_zone_from_state(state: &State) -> Option<Domain> {
    let ttl = 5;

    if !(state.services.is_ready() && state.ep_slices.is_ready()) {
        return None;
    }

    let ns_dn = DomainName::try_from("localhost.localdomain").unwrap();

    let mut domain = Domain::new();

    // add a default SOA
    domain.push_record(
        // @ 5 SOA ns.dns clusteradmin {zone_serial} 7200 1800 86400 {ttl}
        data::Soa {
            mname: ns_dn.clone(),
            rname: "cluster-admin".try_into().unwrap(),
            serial: 1,
            refresh: 60,
            retry: ttl,
            expire: 86400,
            minimum: ttl,
        }
        .into_record(5),
    );
    domain.push_record(Record::ns(5, &ns_dn));

    let svc_zone = domain.sub_or_create(Label::from_str("svc"));

    for (key, svc) in state.services.iter() {
        let zone = svc_zone.sub_or_create(Label::from_str(&key.namespace));
        let zone = zone.sub_or_create(Label::from_str(&key.name));

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
                        for ip in ep.into_ips() {
                            zone.push_record(Record::alias(ttl, ip));
                        }
                    }
                }
            }
        };
    }

    // add entries for slice endpoints with hostname
    for (key, slice) in state.ep_slices.iter() {
        for ep in slice.endpoints.iter() {
            let Some(ref hostname) = ep.hostname else {
                continue;
            };

            let zone = svc_zone.sub_or_create(Label::from_str(&key.namespace));
            let zone = zone.sub_or_create(Label::from_str(&key.name));
            let zone = zone.sub_or_create(Label::from_str(hostname));

            for ip in (&ep).ips() {
                zone.push_record(Record::alias(ttl, ip));
            }
        }
    }

    Some(domain)
}
