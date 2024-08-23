pub mod backends;
pub mod change;
pub mod dns;
pub mod kube_watch;
pub mod memstore;
pub mod state;
pub mod watcher;

use tokio::sync::mpsc::{self, error::TryRecvError};

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
