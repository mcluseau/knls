use conntrack::{model::IpProto, Conntrack};
use eyre::{format_err, Result};
use k8s_openapi::api::core::v1 as core;
use log::{debug, error, warn};
use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::task::spawn_blocking;

use crate::{
    ips, keys,
    kube_watch::Event,
    store::{HashIndex, Store},
};

pub async fn cleanup(state: &State) -> Result<()> {
    let ct = state.ct.clone();
    let flows = spawn_blocking(move || ct.dump())
        .await?
        .map_err(|e| format_err!("dump failed: {e}"))?;

    for flow in flows {
        let Some(flow) = Flow::from_ct(flow) else {
            continue;
        };

        let svc = flow.origin.dst;
        let ep = flow.reply.src;

        let mut any_ip = false;
        let mut any_ep = false;

        for svc_key in [Target::IpPort(svc), Target::NodePort(svc.port())]
            .iter()
            .filter_map(|target| state.svc_targets.get_rev(target))
            .flatten()
        {
            any_ip = true; // matches a service

            for (_, eps) in (state.svc_eps).range(svc_key.to_parent()..svc_key.to_parent().end()) {
                any_ep |= eps.contains(&ep.ip());
            }

            if any_ep {
                break; // flow is valid
            }
        }

        if !any_ip || any_ep {
            continue;
        }

        debug!("removing flow {id} mapped from {svc} to {ep}", id = flow.id);
        // TODO remove flows by id (but it's not available with the conntrack tool, and conntrack
        // lib only has dump)

        let mut cmd = tokio::process::Command::new("conntrack");
        cmd.arg("-D").args(flow.match_args());

        match cmd.output().await {
            Err(e) => error!("conntrack command failed: {e}"),
            Ok(out) => {
                if !out.status.success() {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    if !stderr.contains(" 0 flow entries have been deleted") {
                        warn!("conntrack -D failed, {}: {}", out.status, stderr)
                    }
                }
            }
        }
    }
    Ok(())
}

/// resolved conntrack Flow entry for our use
struct Flow {
    id: u32,
    origin: IpTuple,
    reply: IpTuple,
}

impl Flow {
    fn from_ct(ct: conntrack::model::Flow) -> Option<Self> {
        Some(Self {
            id: ct.id?,
            origin: IpTuple::from_ct(ct.origin?)?,
            reply: IpTuple::from_ct(ct.reply?)?,
        })
    }

    fn match_args(&self) -> impl Iterator<Item = String> {
        ["--proto=udp".to_string()]
            .into_iter()
            .chain(self.origin.match_args("orig"))
            .chain(self.reply.match_args("reply"))
    }
}

struct IpTuple {
    src: SocketAddr,
    dst: SocketAddr,
}

impl IpTuple {
    fn from_ct(ct: conntrack::model::IpTuple) -> Option<Self> {
        let proto = ct.proto?;
        if proto.number? != IpProto::Udp {
            return None; // UDP only
        }
        Some(Self {
            src: SocketAddr::new(ct.src?, proto.src_port?),
            dst: SocketAddr::new(ct.dst?, proto.dst_port?),
        })
    }

    fn match_args(&self, name: &str) -> impl Iterator<Item = String> {
        [
            format!("--{name}-src={}", self.src.ip()),
            format!("--{name}-port-src={}", self.src.port()),
            format!("--{name}-dst={}", self.dst.ip()),
            format!("--{name}-port-dst={}", self.dst.port()),
        ]
        .into_iter()
    }
}

pub struct State {
    ct: Arc<Conntrack>,
    svc_targets: HashIndex<core::Service, keys::Obj, Target>,
    svc_eps: Store<keys::ByParent, ips::Endpoint>,
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

fn svc_targets(svc: &core::Service) -> BTreeSet<Target> {
    let mut set = BTreeSet::new();

    let Some(spec) = svc.spec.as_ref() else {
        return set;
    };

    let ports: Vec<_> = (spec.ports.iter().flatten())
        .filter(|p| p.protocol.as_deref() == Some("UDP")) // UDP only
        .map(|p| (p.port as u16, p.node_port.map(|p| p as u16)))
        .collect();

    if ports.is_empty() {
        return set;
    }

    for ip in ips::Service::from(svc).all() {
        for (port, _) in &ports {
            set.insert(Target::ip(ip, *port));
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

#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
enum Target {
    IpPort(SocketAddr),
    NodePort(u16),
}

impl Target {
    fn ip(ip: IpAddr, port: u16) -> Self {
        Self::IpPort(SocketAddr::new(ip, port))
    }
}
