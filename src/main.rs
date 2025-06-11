use clap::{Parser, ValueEnum};
use eyre::format_err;
use kube::{runtime::watcher, Client};
use log::{error, info};
use std::process::exit;
use std::sync::Arc;
use tokio::{
    select,
    signal::unix::{signal, SignalKind},
};

use knls::kube_watch;

pub mod config;

/// Kubernetes Node-Local Services
#[derive(Parser)]
#[command(version, about, long_about = ABOUT)]
struct Cli {
    /// log filters (see https://docs.rs/env_logger/latest/env_logger/index.html#enabling-logging)
    #[arg(long, default_value = "info", env = "KNLS_LOG")]
    log: String,
    /// log style (see https://docs.rs/env_logger/latest/env_logger/index.html#disabling-colors)
    #[arg(long, default_value = "auto", env = "KNLS_LOG_STYLE")]
    log_style: String,

    /// my node name (hint: {valueFrom: {fieldRef: { fieldPath: spec.nodeName }}})
    #[arg(
        long,
        env = "NODE_NAME",
        default_value_t = default_nodename()
    )]
    node_name: String,

    /// Config file path.
    #[arg(long, short = 'c', default_value = "config.yaml")]
    config: String,

    /// Test the config and exit.
    #[arg(long)]
    test_config: bool,
}

#[derive(Clone, ValueEnum)]
enum Dns {
    Internal,
}

const ABOUT: &'static str = r#"
Kubernetes Node-Local Services

Watch the Kubernetes API server to provide node-level services:
- kube-proxy service using nftables
- authoritative DNS
- pod connectivity through wireguard
"#;

fn default_nodename() -> String {
    gethostname::gethostname()
        .into_string()
        .map_err(|s| format_err!("invalid hostname: {s:?}"))
        .unwrap()
}

type Tasks = tokio::task::JoinSet<(String, eyre::Result<()>)>;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let cli = Cli::parse();

    env_logger::builder()
        .parse_filters(cli.log.as_str())
        .parse_write_style(cli.log_style.as_str())
        .format_timestamp_millis()
        .init();

    use config::*;
    let config = tokio::fs::read(&cli.config)
        .await
        .map_err(|e| format_err!("read config failed: {}: {e}", cli.config))?;
    let config: Config =
        serde_yaml::from_slice(&config).map_err(|e| format_err!("parse config failed: {e}"))?;

    let cluster_url = config
        .cluster_url()
        .map_err(|e| format_err!("invalid cluster_url: {e}"))?;

    if cli.test_config {
        return Ok(());
    }

    tokio::spawn(async move {
        let mut sigterm = signal(SignalKind::terminate()).unwrap();
        let mut sigint = signal(SignalKind::interrupt()).unwrap();
        select! {
            _ = sigterm.recv() => println!("Received SIGTERM"),
            _ = sigint.recv() => println!("Received SIGINT"),
        };
        exit(0);
    });

    info!("starting as node {}", cli.node_name);

    let mut kube_cfg = kube::Config::infer().await?;
    if let Some(cluster_url) = cluster_url {
        kube_cfg.cluster_url = cluster_url;
    }

    info!("kubernetes cluster at {}", kube_cfg.cluster_url);

    let kube: Client = kube_cfg.try_into()?;
    let watcher_config = watcher::Config::default();

    match &config.namespace {
        None => info!("watching all namespaces"),
        Some(ns) => info!("watching namespace {ns}"),
    };

    let ctx = Arc::new(knls::Context {
        node_name: cli.node_name,
        namespace: config.namespace,
        kube,
    });

    let watch_config = kube_watch::Config {
        client: ctx.kube.clone(),
        watcher_config,
        namespace: ctx.namespace.clone(),
        node_name: ctx.node_name.clone(),
        with_nodes: config.connectivity.is_some(),
    };

    let source = knls::watcher::Source::new(ctx.node_name.clone());

    let mut tasks = Tasks::new();

    let mut services = Services {
        tasks: &mut tasks,
        ctx: &ctx,
        source: &source,
    };

    services.spawn("proxy", config.proxy);
    services.spawn("connectivity", config.connectivity);
    services.spawn("dns", config.dns);

    #[cfg(feature = "ingress")]
    {
        tasks.spawn(knls::backends::ingress::watch(cfg_rx.clone()));
    }

    tokio::spawn(knls::process_kube_events(
        source,
        watch_config,
        config.event_buffer,
    ));

    while let Some(res) = tasks.join_next().await {
        match res {
            Err(e) => {
                error!("task wait failed: {e}");
            }
            Ok((name, Ok(_))) => {
                info!("task {name} finished");
                continue;
            }
            Ok((name, Err(e))) => {
                error!("task {name} finished with error: {e}");
            }
        }
        exit(1);
    }

    error!("all tasks finished");
    exit(1); // this is actually unexpected
}

struct Services<'t> {
    tasks: &'t mut Tasks,
    ctx: &'t Arc<knls::Context>,
    source: &'t knls::watcher::Source,
}

impl<'t> Services<'t> {
    fn spawn<S>(&mut self, service_name: &'static str, service: Option<S>)
    where
        S: knls::Service + Send + 'static,
    {
        match service {
            None => {
                info!("{service_name}: no configuration, service not enabled.");
            }
            Some(service) => {
                let flavor = service.impl_name();
                info!("{service_name}: starting {flavor} implementation");

                self.spawn_task(
                    format!("{service_name}:{flavor}"),
                    service.watch(self.ctx.clone(), self.source.new_watcher()),
                );
            }
        }
    }

    fn spawn_task<F>(&mut self, task_name: String, task: F)
    where
        F: Future<Output = eyre::Result<()>>,
        F: Send + 'static,
    {
        self.tasks.spawn(async move { (task_name, task.await) });
    }
}
