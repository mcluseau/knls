use std::sync::Arc;
use tokio::sync::{
    watch::{self, error::RecvError, Receiver, Sender},
    RwLock,
};

use crate::state::State;

#[derive(Clone)]
pub struct Watcher {
    shared_state: Arc<RwLock<State>>,
    watch: Receiver<()>,
}

impl Watcher {
    pub async fn next<F, R>(&mut self, read_state: F) -> Result<R, RecvError>
    where
        F: FnOnce(&State) -> R,
    {
        self.watch.changed().await?;

        let state = self.shared_state.read().await;
        self.watch.borrow_and_update();

        Ok(read_state(&state))
    }
}

pub struct Source {
    tx: Sender<()>,
    rx: Receiver<()>,
    shared_state: Arc<RwLock<State>>,
}

impl Source {
    pub fn new(node_name: String) -> Self {
        let (tx, rx) = watch::channel(());
        Self {
            rx,
            tx,
            shared_state: Arc::new(RwLock::new(State::new(node_name))),
        }
    }

    pub fn new_watcher(&self) -> Watcher {
        Watcher {
            shared_state: self.shared_state.clone(),
            watch: self.rx.clone(),
        }
    }

    pub async fn write(&self) -> WriteGuard<'_> {
        self.shared_state.write().await
    }

    pub fn notify(&mut self) {
        self.tx.send_replace(())
    }
}

type WriteGuard<'t> = tokio::sync::RwLockWriteGuard<'t, State>;
