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
    run(name, false, f)
}

/// Spawns `f` on its own thread, driving it with a multi-thread runtime.
pub fn multi_thread<F, Fut>(name: &str, f: F) -> io::Result<JoinHandle<()>>
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = ()> + 'static,
{
    run(name, true, f)
}

fn run<F, Fut>(name: &str, multi: bool, f: F) -> io::Result<JoinHandle<()>>
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = ()> + 'static,
{
    let name = format!("knls: {name}");

    std::thread::Builder::new()
        .name(name.clone())
        .spawn(move || {
            let rt = match multi {
                true => tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .thread_name(name)
                    .build(),
                false => tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build(),
            }
            .expect("build tokio worker runtime");

            rt.block_on(f());
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use tokio::runtime::{Handle, RuntimeFlavor};

    fn probe(name: &str, multi: bool) -> (String, RuntimeFlavor) {
        let (tx, rx) = mpsc::channel();
        let f = move || async move {
            tx.send((
                std::thread::current()
                    .name()
                    .unwrap_or_default()
                    .to_string(),
                Handle::current().runtime_flavor(),
            ))
            .expect("send worker result");
        };

        let handle = if multi {
            multi_thread(name, f)
        } else {
            single_thread(name, f)
        }
        .expect("spawn worker");
        handle.join().expect("join worker");

        rx.recv().expect("worker result")
    }

    #[test]
    fn single_thread_is_named_and_current() {
        assert_eq!(
            probe("unit-single", false),
            ("knls: unit-single".into(), RuntimeFlavor::CurrentThread)
        );
    }

    #[test]
    fn multi_thread_is_named_and_multi() {
        assert_eq!(
            probe("unit-multi", true),
            ("knls: unit-multi".into(), RuntimeFlavor::MultiThread)
        );
    }
}
