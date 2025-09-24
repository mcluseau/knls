pub mod actions;
pub mod change;
pub mod connectivity;
pub mod dns;
pub mod hw_labels;
pub mod kube_watch;
pub mod memstore;
pub mod proxy;
pub mod state;
pub mod watcher;

use kube::api::PatchParams;
use std::sync::Arc;
use tokio::sync::mpsc::{self, error::TryRecvError};

pub struct Context {
    pub node_name: String,
    pub namespace: Option<String>,
    pub kube: kube::Client,
}

/// Service trait common to all services implemented by KNLS.
pub trait Service {
    /// prefix (aka kind, category) of the service provided. e.g.: "proxy", "connectivity", "dns"...
    fn prefix(&self) -> &'static str;
    /// start the service's watch, returning the implementation name and a future to spawn.
    fn impl_name(&self) -> &'static str;
    /// run the service's watch
    fn watch(
        self,
        ctx: Arc<Context>,
        watcher: watcher::Watcher,
    ) -> impl Future<Output = eyre::Result<()>> + Send;
}

pub async fn process_kube_events(
    mut source: watcher::Source,
    watch_config: kube_watch::Config,
    event_buffer_size: usize,
) {
    let (tx, mut rx) = mpsc::channel(event_buffer_size);

    watch_config.watch_to(tx);

    while let Some(event) = rx.recv().await {
        let mut state = source.write().await;

        // consume this new event
        state.ingest(event);

        // also consume the current event queue.
        // Don't process more than the requested buffer size as an heuristic on how many events we
        // want to consume before forcing a state update.
        for _ in 0..event_buffer_size {
            match rx.try_recv() {
                Ok(event) => {
                    state.ingest(event);
                }
                Err(e) => {
                    use TryRecvError::*;
                    match e {
                        Empty => {
                            break;
                        }
                        Disconnected => {
                            return;
                        }
                    };
                }
            }
        }

        drop(state);
        source.notify();
    }
}

pub fn patch_params() -> PatchParams {
    PatchParams::apply("knls")
}

/// Helper to define standard services. A standard service is defined as:
/// - a config and
/// - a watch fn(ctx: knls::Context, cfg: the given config, watcher: knls::watcher::Watcher) -> eyre::Result<()>
#[macro_export]
macro_rules! service {
    ($name:literal $type:ident { $( $flavor:literal $var:ident: $cfg:ty => $impl:expr , )+ }) => {
        #[derive(Debug, serde::Deserialize, serde::Serialize)]
        pub enum $type {
            $(
            #[serde(rename = $flavor)]
            $var($cfg),
            )+
        }
        impl knls::Service for $type {
            fn prefix(&self) -> &'static str {
                $name
            }

            fn impl_name(&self) -> &'static str {
                match self {
                    $(
                    Self::$var(_) => $flavor,
                    )+
                }
            }

            fn watch(
                self,
                ctx: Arc<knls::Context>,
                watcher: knls::watcher::Watcher,
            ) -> impl Future<Output = Result<()>> + Send {
                match self {
                    $(
                    Self::$var(cfg) => $impl(ctx, cfg, watcher),
                    )+
                }
            }
        }
    };
}
