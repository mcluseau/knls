use futures::{StreamExt, TryStreamExt};
#[cfg(feature = "ingress")]
use k8s_openapi::api::networking::v1 as networking;
use k8s_openapi::api::{core::v1 as core, discovery::v1 as discovery};
use kube::{Client, api::Api, runtime::watcher};
use log::{error, info};
use tokio::sync::mpsc;

#[derive(Debug)]
pub enum Event {
    MyNode(watcher::Event<core::Node>),
    Service(watcher::Event<core::Service>),
    EndpointSlice(watcher::Event<discovery::EndpointSlice>),
    Node(watcher::Event<core::Node>),
    #[cfg(feature = "ingress")]
    Ingress(watcher::Event<networking::Ingress>),
}

pub struct Config {
    pub node_name: String,
    pub namespace: Option<String>,
    pub client: Client,
    pub watcher_config: watcher::Config,
    pub with_nodes: bool,
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

        #[cfg(feature = "ingress")]
        tokio::spawn(watch_to_events(
            self.namespaced_api(),
            self.watcher_config.clone(),
            tx.clone(),
            Event::Ingress,
        ));
    }
}

async fn watch_to_events<K>(
    api: Api<K>,
    watcher_config: watcher::Config,
    tx: mpsc::Sender<Event>,
    map: fn(watcher::Event<K>) -> Event,
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
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                continue;
            }
        };

        let Some(event) = event else {
            info!("watch on {resource} stopped");
            return;
        };

        if tx.send(map(event)).await.is_err() {
            info!("receiver of {resource} stopped");
            return;
        }
    }
}
