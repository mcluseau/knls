use clap::{Parser, ValueEnum};
use eyre::format_err;
use kube::{runtime::watcher, Client};
use log::{error, info};
use std::process::exit;
use tokio::{
    select,
    signal::unix::{signal, SignalKind},
};

use knls::kube_watch;

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

    /// namespace to watch instead of the whole cluster
    #[arg(short = 'n', long)]
    namespace: Option<String>,

    /// Kubernetes API server URL
    #[arg(long)]
    cluster_url: Option<http::uri::Uri>,

    /// Kubernetes cluster domain
    #[arg(long, default_value = "cluster.local")]
    cluster_domain: String,

    /// Kubernetes watch events buffer size
    #[arg(long, default_value = "100")]
    event_buffer: usize,

    /// Proxy implementation to use
    #[arg(long)]
    proxy: Option<Proxy>,

    /// Disable node ports (since they are forced for load balancers at API level for non-technical reasons)
    #[arg(long)]
    disable_nodeports: bool,

    /// nftables table's name
    #[arg(long, default_value = "kube-proxy")]
    nftables_table: String,

    /// Node connectivity implementation to use
    #[arg(long)]
    connectivity: Option<Connectivity>,

    /// Activate node connectivity through wireguard using this interface
    #[arg(long, default_value = "kwg")]
    wireguard_ifname: String,

    /// Wireguard private key file (will be created as needed).
    #[arg(long, default_value = "/var/lib/knls/wireguard.key")]
    wireguard_key: String,

    /// CNI config path
    #[arg(long, default_value = "/etc/cni/net.d/10-knls.conf")]
    cni_config: String,

    /// DNS implementation to use (no DNS if not set).
    #[arg(long)]
    dns: Option<Dns>,

    /// DNS implementation to use (no DNS if not set).
    #[arg(long, default_value = "127.0.0.1:1053")]
    internal_dns_binding: String,
}

#[derive(Clone, ValueEnum)]
enum Proxy {
    Nftables,
}

#[derive(Clone, ValueEnum)]
enum Connectivity {
    Wireguard,
}

#[derive(Clone, ValueEnum)]
enum Dns {
    Internal,
}

const ABOUT: &'static str = r#"
Kubernetes Node-Local Services

Watch the Kubernetes API server to provide node-specific services:
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

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let cli = Cli::parse();

    env_logger::builder()
        .parse_filters(cli.log.as_str())
        .parse_write_style(cli.log_style.as_str())
        .format_timestamp_millis()
        .init();

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

    let mut cfg = kube::Config::infer().await?;
    if let Some(cluster_url) = cli.cluster_url {
        cfg.cluster_url = cluster_url;
    }

    info!("kubernetes cluster at {}", cfg.cluster_url);

    let client: Client = cfg.try_into()?;
    let watcher_config = watcher::Config::default();

    match &cli.namespace {
        None => info!("watching all namespaces"),
        Some(ns) => info!("watching namespace {ns}"),
    };

    let source = knls::watcher::Source::new(cli.node_name.clone());

    let mut tasks = tokio::task::JoinSet::new();

    match cli.proxy {
        None => {}
        Some(Proxy::Nftables) => {
            let table_name = cli.nftables_table.clone();
            tasks.spawn(named_task(
                "nftables",
                knls::backends::nftables::watch(
                    table_name,
                    cli.disable_nodeports,
                    source.new_watcher(),
                ),
            ));
        }
    }

    match cli.connectivity {
        None => {}
        Some(Connectivity::Wireguard) => {
            let client = client.clone();
            tasks.spawn(named_task(
                "wireguard",
                knls::backends::wireguard::watch(
                    source.new_watcher(),
                    cli.node_name.clone(),
                    cli.wireguard_ifname.clone(),
                    cli.wireguard_key.clone(),
                    cli.cni_config,
                    client,
                ),
            ));
        }
    }

    match cli.dns {
        None => {}
        Some(Dns::Internal) => {
            tasks.spawn(named_task(
                "internal-dns",
                knls::backends::dns::internal::watch(
                    source.new_watcher(),
                    cli.cluster_domain,
                    cli.internal_dns_binding,
                ),
            ));
        }
    }

    #[cfg(feature = "ingress")]
    {
        tasks.spawn(knls::backends::ingress::watch(cfg_rx.clone()));
    }

    let watch_config = kube_watch::Config {
        client,
        watcher_config,
        namespace: cli.namespace,
        node_name: cli.node_name,
        with_nodes: cli.connectivity.is_some(),
    };
    tokio::spawn(knls::process_kube_events(
        source,
        watch_config,
        cli.event_buffer,
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

async fn named_task<F>(name: &str, task: F) -> (&str, eyre::Result<()>)
where
    F: futures::Future<Output = eyre::Result<()>>,
{
    info!("starting task {name}");
    (name, task.await)
}
