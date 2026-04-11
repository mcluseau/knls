use conntrack::{model::IpProto, Conntrack};
use eyre::{format_err, Result};
use k8s_openapi::api::{core::v1 as core, discovery::v1 as discovery};
use log::{debug, error, warn};
use std::collections::{BTreeSet, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::task::spawn_blocking;

use crate::{
    ips, keys,
    kube_watch::{ingest_events, Event, EventReceiver},
    store::{HashIndex, Store},
};

pub async fn watch(mut events: EventReceiver) -> Result<()> {
    let mut state = State::new().await?;

    loop {
        use std::ops::ControlFlow::*;
        match ingest_events(&mut events, |e| state.ingest(&e)).await {
            Some(Break(_)) => break,
            Some(Continue(_)) => continue,
            None => {}
        };

        if !state.is_ready() {
            continue;
        }

        if let Err(e) = cleanup(&state).await {
            error!("conntrack cleanup failed: {e}");
        }
    }

    Ok(())
}

pub async fn cleanup(state: &State) -> Result<()> {
    let ct = state.ct.clone();
    let flows = spawn_blocking(move || ct.dump())
        .await?
        .map_err(|e| format_err!("dump failed: {e}"))?;

    for flow in flows {
        let Some(orig) = flow.origin.as_ref() else {
            continue;
        };
        let Some(orig_proto) = orig.proto.as_ref() else {
            continue;
        };
        if orig_proto.number != Some(IpProto::Udp) {
            continue; // UDP only
        }
        let Some(id) = flow.id else {
            continue;
        };
        let Some(orig_dst) = orig.dst else {
            continue;
        };
        let Some(orig_port) = orig_proto.dst_port else {
            continue;
        };
        let Some(reply) = flow.reply else {
            continue;
        };
        let Some(reply_proto) = reply.proto.as_ref() else {
            continue;
        };
        let Some(ep_ip) = reply.src else {
            continue;
        };
        let Some(ep_port) = reply_proto.src_port else {
            continue;
        };

        let mut any_ip = false;
        let mut any_ep = false;

        for svc_key in [
            Target::IpPort(orig_port, orig_dst),
            Target::NodePort(orig_port),
        ]
        .iter()
        .filter_map(|target| state.svc_targets.get_rev(target))
        .flatten()
        {
            any_ip = true; // matches a service

            for (_, eps) in (state.svc_eps).range(svc_key.to_parent()..svc_key.to_parent().end()) {
                any_ep |= eps.contains(&ep_ip);
            }

            if any_ep {
                break; // flow is valid
            }
        }

        if !any_ip || any_ep {
            continue;
        }

        debug!("removing flow {id} mapped from {orig_dst}:{orig_port} to {ep_ip}:{ep_port}");
        // TODO remove flows by id (but it's not available with the conntrack tool, and conntrack
        // lib only has dump)

        let mut cmd = tokio::process::Command::new("conntrack");

        cmd.arg("-D")
            .arg("--proto=udp")
            .arg(format!("--orig-dst={orig_dst}"))
            .arg(format!("--orig-port-dst={orig_port}"))
            .arg(format!("--reply-src={ep_ip}"))
            .arg(format!("--reply-port-src={ep_port}"));

        // filter on every other field so basically selector == id
        if let Some(v) = orig.src {
            cmd.arg(format!("--orig-src={v}"));
        }
        if let Some(v) = orig_proto.src_port {
            cmd.arg(format!("--orig-port-src={v}"));
        }
        if let Some(v) = reply.dst {
            cmd.arg(format!("--reply-dst={v}"));
        }
        if let Some(v) = reply_proto.dst_port {
            cmd.arg(format!("--reply-port-dst={v}"));
        }

        match cmd.output().await {
            Err(e) => error!("conntrack command failed: {e}"),
            Ok(out) => {
                if !out.status.success() {
                    warn!(
                        "conntrack -D failed, {}: {}",
                        out.status,
                        String::from_utf8_lossy(&out.stderr)
                    )
                }
            }
        }
    }
    Ok(())
}

pub struct State {
    ct: Arc<Conntrack>,
    svc_targets: HashIndex<core::Service, keys::Obj, Target>,
    svc_eps: Store<keys::ByParent, EndpointIps>,
}

impl State {
    pub async fn new() -> Result<Self> {
        Ok(Self {
            ct: spawn_blocking(Conntrack::connect).await??.into(),
            svc_targets: HashIndex::new(svc_targets),
            svc_eps: Store::new(),
        })
    }

    pub fn is_ready(&self) -> bool {
        self.svc_targets.is_ready() && self.svc_eps.is_ready()
    }

    pub fn ingest(&mut self, e: &Event) -> bool {
        use Event::{EndpointSlice, Service};
        match e {
            Service(e) => {
                self.svc_targets.ingest(e);
                true
            }
            EndpointSlice(e) => {
                self.svc_eps.ingest(e);
                true
            }
            _ => false,
        }
    }
}

#[derive(Default)]
struct ServiceIps {
    cluster: Vec<IpAddr>,
    external: Vec<IpAddr>,
    load_balancer: Vec<IpAddr>,
}

impl ServiceIps {
    fn all(&self) -> impl Iterator<Item = IpAddr> {
        [&self.cluster, &self.external, &self.load_balancer]
            .into_iter()
            .flatten()
            .cloned()
    }
}

impl From<&core::Service> for ServiceIps {
    fn from(svc: &core::Service) -> Self {
        let Some(spec) = svc.spec.as_ref() else {
            return Self::default();
        };

        if !(spec.ports.iter().flatten()).any(|p| p.protocol.as_deref() == Some("UDP")) {
            return Self::default(); // no UDP -> no IP to check
        }

        let lb = (svc.status.as_ref())
            .and_then(|s| s.load_balancer.as_ref())
            .and_then(|lb| lb.ingress.as_ref());
        Self {
            cluster: ips::parse_opt(spec.cluster_ips.as_ref()),
            external: ips::parse_opt(spec.external_ips.as_ref()),
            load_balancer: ips::parse_opt_with(lb, |ing| ing.ip.as_ref()),
        }
    }
}

fn svc_targets(svc: &core::Service) -> BTreeSet<Target> {
    let mut set = BTreeSet::new();

    let Some(spec) = svc.spec.as_ref() else {
        return set;
    };

    let ports: Vec<_> = (spec.ports.iter().flatten())
        .filter(|p| p.protocol.as_deref() == Some("UDP")) // UDP only
        .map(|p| (p.port as u16, p.node_port.map(|p| p as u16)))
        .collect();

    for ip in ServiceIps::from(svc).all() {
        for (port, _) in &ports {
            set.insert(Target::IpPort(*port, ip));
        }
    }

    for (_, node_port) in &ports {
        let Some(node_port) = node_port else {
            continue;
        };
        set.insert(Target::NodePort(*node_port));
    }

    set
}

struct EndpointIps {
    ips: HashSet<IpAddr>,
}

impl EndpointIps {
    fn contains(&self, ip: &IpAddr) -> bool {
        self.ips.contains(ip)
    }
}

impl From<&discovery::EndpointSlice> for EndpointIps {
    fn from(eps: &discovery::EndpointSlice) -> EndpointIps {
        Self {
            ips: HashSet::from_iter(ips::parse_iter(
                eps.endpoints.iter().flat_map(|ep| &ep.addresses),
            )),
        }
    }
}

#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
enum Target {
    IpPort(u16, IpAddr),
    NodePort(u16),
}
