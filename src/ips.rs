use k8s_openapi::api::{core::v1 as core, discovery::v1 as discovery};
use std::collections::{HashSet, hash_set};
use std::net::IpAddr;

pub fn parse_iter<'t>(ips: impl Iterator<Item = &'t String>) -> impl Iterator<Item = IpAddr> {
    ips.filter_map(|s| s.parse::<IpAddr>().ok())
}

pub fn parse_opt(ips: Option<&Vec<String>>) -> Vec<IpAddr> {
    let mut parsed = Vec::new();
    let Some(ips) = ips.as_ref() else {
        return parsed;
    };
    parsed.reserve(ips.len());
    parsed.extend(parse_iter(ips.iter()));
    parsed
}

pub fn parse_opt_with<I>(items: Option<&Vec<I>>, f: fn(&I) -> Option<&String>) -> Vec<IpAddr> {
    let mut parsed = Vec::new();
    let Some(items) = items.as_ref() else {
        return parsed;
    };
    parsed.reserve(items.len());
    parsed.extend(parse_iter(items.iter().filter_map(|i| f(i))));
    parsed
}

pub struct Service {
    cluster: Vec<IpAddr>,
    external: Vec<IpAddr>,
    load_balancer: Vec<IpAddr>,
}

impl Service {
    pub fn all(&self) -> impl Iterator<Item = IpAddr> {
        [&self.cluster, &self.external, &self.load_balancer]
            .into_iter()
            .flatten()
            .cloned()
    }
}

impl From<&core::Service> for Service {
    fn from(svc: &core::Service) -> Self {
        let spec = svc.spec.as_ref();

        let lb = (svc.status.as_ref())
            .and_then(|s| s.load_balancer.as_ref())
            .and_then(|lb| lb.ingress.as_ref());

        Self {
            cluster: parse_opt(spec.and_then(|s| s.cluster_ips.as_ref())),
            external: parse_opt(spec.and_then(|s| s.external_ips.as_ref())),
            load_balancer: parse_opt_with(lb, |ing| ing.ip.as_ref()),
        }
    }
}

pub struct Endpoint {
    ips: HashSet<IpAddr>,
}

impl Endpoint {
    pub fn contains(&self, ip: &IpAddr) -> bool {
        self.ips.contains(ip)
    }
}

impl From<&discovery::EndpointSlice> for Endpoint {
    fn from(eps: &discovery::EndpointSlice) -> Endpoint {
        Self {
            ips: HashSet::from_iter(parse_iter(
                eps.endpoints.iter().flat_map(|ep| &ep.addresses),
            )),
        }
    }
}

impl<'t> IntoIterator for &'t Endpoint {
    type Item = &'t IpAddr;
    type IntoIter = hash_set::Iter<'t, IpAddr>;
    fn into_iter(self) -> hash_set::Iter<'t, IpAddr> {
        self.ips.iter()
    }
}
