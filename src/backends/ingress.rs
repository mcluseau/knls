use k8s_openapi::api::networking::v1 as networking;

use crate::state::State;

pub fn from_state(state: &State) -> Option<ProxyConfig> {
    // TODO check everything is ready
    if todo!() {
        return None;
    }

    // assemble proxy config
    let mut cfg = ProxyConfig::new();

    for (key, ing) in &self.state.ingresses {
        for rule in &ing.rules {
            let host_config = proxy.entry(rule.host.clone()).or_default();

            if let Some(tls_secret) = rule.tls_secret.as_ref() {
                host_config.tls_secret = Some(ObjectKey {
                    namespace: key.namespace.clone(),
                    name: tls_secret.clone(),
                });
            }

            for m in &rule.matches {
                let mut endpoints =
                    m.endpoints(&key.namespace, &self.state.services, &self.state.ep_slices);

                use PathMatch::*;
                match &m.path_match {
                    Exact(path) => host_config.exact_matches.entry(path.clone()).or_default(),
                    Prefix(path) => host_config.prefix_matches.entry(path.clone()).or_default(),
                    Any => &mut host_config.any_match,
                }
                .append(&mut endpoints);
            }
        }
    }

    Some(cfg)
}

pub async fn watch_config(mut cfg_rx: config::Receiver) -> eyre::Result {
    loop {
        cfg_rx.changed().await?;
        let cfg = cfg_rx.borrow_and_update().clone();

        if log_enabled!(log::Level::Debug) {
            let mut buf = Vec::new();

            {
                writeln!(buf, "proxy:")?;
                for (host, cfg) in cfg.proxy.as_ref() {
                    writeln!(buf, "- {host}")?;
                    if let Some(key) = &cfg.tls_secret {
                        writeln!(buf, "  - tls from {key}")?;
                    }
                    for (path, m) in &cfg.exact_matches {
                        writeln!(buf, "  - {path} => {}", m.iter().join(", "))?;
                    }
                    for (path, m) in &cfg.prefix_matches {
                        writeln!(buf, "  - {path}* => {}", m.iter().join(", "))?;
                    }
                    writeln!(buf, "  - * => {}", cfg.any_match.iter().join(", "))?;
                }
                writeln!(buf, "")?;
            }

            debug!("new config received:\n{}", String::from_utf8_lossy(&buf));
        }
    }
}

struct Endpoint {
    ipv4: IpAddr,
    ipv6: IpAddr,
    port: u16,
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{}:{}", self.addr, self.port)
    }
}

#[derive(Debug, serde::Serialize)]
struct Ingress {
    rules: Vec<IngressRule>,
}
impl KeyValueFrom<networking::Ingress> for Ingress {
    type Key = ObjectKey;
    type Error = &'static str;

    fn key_from(ing: &networking::Ingress) -> Result<Self::Key, Self::Error> {
        ObjectKey::try_from(&ing.metadata)
    }

    fn value_from(ing: &networking::Ingress) -> Result<Self, Self::Error> {
        let spec = ing.spec.as_ref().ok_or("no spec")?;

        let rules = spec.rules.as_ref().map_or_else(
            || Vec::new(),
            |v| {
                v.iter()
                    .filter_map(|m| IngressRule::from_rule(m, &spec))
                    .collect()
            },
        );

        Ok(Self { rules })
    }
}

#[derive(Debug, serde::Serialize)]
struct IngressRule {
    host: String,
    tls_secret: Option<String>,
    matches: Vec<IngressMatch>,
}
impl IngressRule {
    fn from_rule(rule: &networking::IngressRule, spec: &networking::IngressSpec) -> Option<Self> {
        let Some(host) = rule.host.as_ref() else {
            return None;
        };
        Some(Self {
            host: host.clone(),
            tls_secret: spec.tls.as_ref().and_then(|tls| {
                tls.iter()
                    .find(|tls| tls.hosts.as_ref().is_some_and(|hosts| hosts.contains(host)))
                    .and_then(|tls| tls.secret_name.clone())
            }),
            matches: rule
                .http
                .as_ref()
                .map(|http| {
                    http.paths
                        .iter()
                        .filter_map(|path| IngressMatch::from_http_path(&path, spec))
                        .collect()
                })
                .unwrap_or_default(),
        })
    }
}

#[derive(Debug, serde::Serialize)]
struct IngressMatch {
    path_match: PathMatch,
    backend: Option<IngressBackend>,
}
impl IngressMatch {
    fn from_http_path(
        path_spec: &networking::HTTPIngressPath,
        spec: &networking::IngressSpec,
    ) -> Option<Self> {
        let path_match = match path_spec.path_type.as_str() {
            "Exact" => PathMatch::Exact(path_spec.path.as_ref().unwrap().clone()),
            "Prefix" | "ImplementationSpecific" => match path_spec.path.as_ref() {
                None => PathMatch::Any,
                Some(path) => match path.as_str() {
                    "" | "/" => PathMatch::Any,
                    _ => PathMatch::Prefix(path.clone()),
                },
            },
            _ => {
                return None;
            }
        };
        Some(Self {
            path_match,
            backend: IngressBackend::from_backend(&path_spec.backend).or_else(|| {
                spec.default_backend
                    .as_ref()
                    .and_then(|b| IngressBackend::from_backend(b))
            }),
        })
    }

    fn endpoints(
        &self,
        namespace: &String,
        services: &Map<ObjectKey, Service>,
        ep_slices: &Map<EndpointSliceKey, EndpointSlice>,
    ) -> Set<Endpoint> {
        let mut endpoints = Set::new();

        let Some(backend) = self.backend.as_ref() else {
            return endpoints;
        };

        let service_key = ObjectKey {
            namespace: namespace.clone(),
            name: backend.service.clone(),
        };

        let Some(service) = services.get(&service_key) else {
            return endpoints;
        };

        let port_name = match &backend.port {
            PortRef::Name(n) => Some(n),
            PortRef::Number(n) => service.ports.get(&n),
        };
        let Some(port_name) = port_name else {
            return endpoints;
        };

        for (_, slice) in EndpointSlice::for_service(&service_key, &ep_slices) {
            let Some(port) = slice.target_ports.get(port_name) else {
                continue;
            };

            for (_, addr) in &slice.endpoints {
                endpoints.insert(Endpoint {
                    ip: addr.clone(),
                    port: port.clone(),
                });
            }
        }

        endpoints
    }
}

#[derive(Debug, serde::Serialize)]
struct IngressBackend {
    service: String,
    port: PortRef,
}
impl IngressBackend {
    fn from_backend(backend: &networking::IngressBackend) -> Option<Self> {
        let Some(service) = backend.service.as_ref() else {
            return None;
        };
        let Some(port) = service.port.as_ref() else {
            return None;
        };
        let port = if let Some(number) = port.number {
            PortRef::Number(number as u16)
        } else if let Some(name) = port.name.as_ref() {
            PortRef::Name(name.clone())
        } else {
            return None;
        };
        Some(Self {
            service: service.name.clone(),
            port,
        })
    }
}

#[derive(Debug, serde::Serialize)]
enum PortRef {
    Number(u16),
    Name(String),
}

#[derive(Debug, serde::Serialize)]
enum PathMatch {
    Exact(String),
    Prefix(String),
    Any,
}
