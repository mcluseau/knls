use futures::{StreamExt, TryStreamExt};
use k8s_openapi::api::{
    core::v1 as core, discovery::v1 as discovery, networking::v1 as networking,
};
use kube::{api::Api, runtime::watcher, Client};
use log::{error, info};
use std::ops::ControlFlow;
use std::sync::Arc;
use tokio::{
    sync::mpsc,
    time::{sleep, timeout, Duration, Instant},
};

/// How long a burst of events is coalesced into a single update.
const COALESCE_WINDOW: Duration = Duration::from_millis(10);
/// How long to wait for the next event before re-checking the coalescing window.
const COALESCE_WAIT: Duration = Duration::from_millis(1);

pub type EventReceiver = mpsc::Receiver<Event>;

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(tag = "stream", content = "event")]
pub enum Event {
    MyNode(Change<core::Node>),
    Service(Change<core::Service>),
    EndpointSlice(Change<discovery::EndpointSlice>),
    Node(Change<core::Node>),
    NetworkPolicy(Change<networking::NetworkPolicy>),
    Namespace(Change<core::Namespace>),
    Pod(Change<core::Pod>),
}

/// kube's watcher::Event are not serde. Since we need that, also use Arc here, as we need that.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Change<K> {
    Init,
    InitApply(Arc<K>),
    InitDone,
    Apply(Arc<K>),
    Delete(Arc<K>),
}

impl<K> From<watcher::Event<K>> for Change<K> {
    fn from(event: watcher::Event<K>) -> Self {
        use watcher::Event as E;
        use Change as C;
        match event {
            E::Init => C::Init,
            E::InitApply(v) => C::InitApply(Arc::new(v)),
            E::InitDone => C::InitDone,
            E::Apply(v) => C::Apply(Arc::new(v)),
            E::Delete(v) => C::Delete(Arc::new(v)),
        }
    }
}

pub struct Config {
    pub node_name: String,
    pub namespace: Option<String>,
    pub client: Client,
    pub watcher_config: watcher::Config,
    pub with_nodes: bool,
    pub with_netpols: bool,
}

impl Config {
    fn namespaced_api<K>(&self) -> Api<K>
    where
        K: kube::api::Resource<Scope = k8s_openapi::NamespaceResourceScope>,
        <K as kube::Resource>::DynamicType: Default,
    {
        match &self.namespace {
            None => Api::all(self.client.clone()),
            Some(ns) => Api::namespaced(self.client.clone(), ns.as_str()),
        }
    }

    pub fn watch_to(&self, tx: mpsc::Sender<Event>) {
        tokio::spawn(watch_to_events(
            Api::all(self.client.clone()),
            self.watcher_config
                .clone()
                .fields(format!("metadata.name={}", self.node_name).as_str()),
            tx.clone(),
            Event::MyNode,
        ));

        tokio::spawn(watch_to_events(
            self.namespaced_api(),
            self.watcher_config.clone(),
            tx.clone(),
            Event::Service,
        ));

        tokio::spawn(watch_to_events(
            self.namespaced_api(),
            self.watcher_config.clone(),
            tx.clone(),
            Event::EndpointSlice,
        ));

        if self.with_nodes {
            tokio::spawn(watch_to_events(
                Api::all(self.client.clone()),
                self.watcher_config.clone(),
                tx.clone(),
                Event::Node,
            ));
        }

        if self.with_netpols {
            tokio::spawn(watch_to_events(
                self.namespaced_api(),
                self.watcher_config.clone(),
                tx.clone(),
                Event::NetworkPolicy,
            ));
            tokio::spawn(watch_to_events(
                Api::all(self.client.clone()),
                self.watcher_config.clone(),
                tx.clone(),
                Event::Namespace,
            ));
            tokio::spawn(watch_to_events(
                Api::all(self.client.clone()),
                self.watcher_config.clone(),
                tx.clone(),
                Event::Pod,
            ));
        } else {
            // no netpols, watch only my node's pods
            let wc = watcher::Config {
                field_selector: Some(format!("spec.nodeName={}", self.node_name)),
                ..self.watcher_config.clone()
            };
            tokio::spawn(watch_to_events(
                Api::all(self.client.clone()),
                wc,
                tx.clone(),
                Event::Pod,
            ));
        }
    }
}

pub async fn ingest_events(
    events: &mut EventReceiver,
    mut ingest: impl FnMut(Event) -> bool,
) -> Option<ControlFlow<()>> {
    let Some(event) = events.recv().await else {
        return Some(ControlFlow::Break(()));
    };
    let mut updated = ingest(event);

    // Coalesce a burst (e.g. a watch (re)list re-emitting thousands of
    // `InitApply`s) into one update instead of one per buffered batch: keep
    // consuming for up to `COALESCE_WINDOW`, waiting at most `COALESCE_WAIT`
    // for the next event. `try_recv` drains whatever is already queued.
    let deadline = Instant::now() + COALESCE_WINDOW;
    loop {
        while let Ok(event) = events.try_recv() {
            updated |= ingest(event);
        }
        if Instant::now() >= deadline {
            break;
        }
        match timeout(COALESCE_WAIT, events.recv()).await {
            Ok(Some(event)) => updated |= ingest(event),
            // the stream closed; the next call reports it
            Ok(None) => break,
            // nothing in flight right now, keep the window open for the rest
            Err(_) => {}
        }
    }

    (!updated).then_some(ControlFlow::Continue(()))
}

async fn watch_to_events<K>(
    api: Api<K>,
    watcher_config: watcher::Config,
    tx: mpsc::Sender<Event>,
    map: fn(Change<K>) -> Event,
) where
    K: kube::api::Resource + Clone + serde::de::DeserializeOwned + std::fmt::Debug + Send + 'static,
{
    let resource = api.resource_url().to_string();
    info!("starting watch on {resource}");

    let mut watcher = watcher(api, watcher_config).boxed();

    loop {
        let event = match watcher.try_next().await {
            Ok(v) => v,
            Err(e) => {
                error!("watch error: {resource}: {e}");
                sleep(Duration::from_secs(1)).await;
                continue;
            }
        };

        let Some(event) = event else {
            info!("watch on {resource} stopped");
            return;
        };

        if tx.send(map(event.into())).await.is_err() {
            info!("receiver of {resource} stopped");
            return;
        }
    }
}
