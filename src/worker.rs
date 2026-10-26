//! Spawning isolated tokio workers.
//!
//! Tokio I/O resources are serviced by the runtime that created them (one I/O
//! driver per worker thread). Long synchronous work on the main runtime — e.g.
//! rendering nftables tables or rebuilding a DNS zone — can therefore delay
//! socket readiness. Running a latency-sensitive component on its own thread
//! and runtime keeps its I/O driver independent.
//!
//! Threads are named `knls: <name>`.

use std::future::Future;
use std::io;
use std::thread::JoinHandle;

/// Spawns `f` on its own thread, driving it with a current-thread runtime.
///
/// Use this for I/O-bound tasks that must stay responsive while the main
/// runtime is busy with synchronous work.
pub fn single_thread<F, Fut>(name: &str, f: F) -> io::Result<JoinHandle<()>>
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = ()> + 'static,
{
    let name = format!("knls: {name}");

    std::thread::Builder::new()
        .name(name.clone())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("build tokio worker runtime");

            rt.block_on(f());
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use tokio::runtime::{Handle, RuntimeFlavor};

    #[test]
    fn single_thread_is_named_and_current() {
        let (tx, rx) = mpsc::channel();
        let handle = single_thread("unit", move || async move {
            tx.send((
                std::thread::current()
                    .name()
                    .unwrap_or_default()
                    .to_string(),
                Handle::current().runtime_flavor(),
            ))
            .expect("send worker result");
        })
        .expect("spawn worker");
        handle.join().expect("join worker");

        assert_eq!(
            rx.recv().expect("worker result"),
            ("knls: unit".into(), RuntimeFlavor::CurrentThread)
        );
    }
}
