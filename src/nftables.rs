pub mod chain;
pub mod rules;
pub mod set;
pub mod table;

use eyre::Result;
use log::debug;
use netlink_packet_core::NetlinkMessage;
use netlink_packet_netfilter::{NetfilterHeader, NetfilterMessage, NetfilterProtoFamily};
use std::{io::Cursor, process::Stdio};
use tokio::{io, io::AsyncRead, process::Command};

pub type Message = NetlinkMessage<NetfilterMessage>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("io error: {0}")]
    Io(std::io::Error),
    #[error("exit code {0}")]
    Exit(i32),
}

pub async fn apply_script(script: impl Into<String>) -> Result<(), Error> {
    let script = script.into();
    debug!("nft script:\n{script}");

    apply_from_reader(Cursor::new(script)).await
}

pub async fn apply_from_reader<R>(mut script: R) -> Result<(), Error>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    let mut cmd = Command::new("nft");
    cmd.args(["-f", "-"]);
    cmd.stdin(Stdio::piped());

    let mut child = cmd.spawn().map_err(Error::Io)?;

    let mut nft_in = child.stdin.take().expect("stdin should exist");
    tokio::spawn(async move { io::copy(&mut script, &mut nft_in).await });

    let s = child.wait().await.map_err(Error::Io)?;
    if !s.success() {
        return Err(Error::Exit(s.code().unwrap_or(0)));
    }

    Ok(())
}

fn nft_header() -> NetfilterHeader {
    NetfilterHeader::new(NetfilterProtoFamily::Inet, 0, 0)
}

/// Test helpers shared by the nftables subsystems.
///
/// A golden scenario is a list of [`Op`]s run against a [`System`]: at every
/// `Verify`, the rendered table is applied to the real kernel and its
/// `nft list` output (minus the `table <name> { … }` wrapper) is compared.
#[cfg(test)]
pub mod test_harness {
    use super::Message;
    use crate::{
        kube_watch,
        netlink::netfilter::{self, NetlinkExt as _},
    };
    use std::process::{Command, Stdio};

    /// One step of a golden scenario.
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum Op {
        /// Feed each event into the system.
        Ingest(Vec<kube_watch::Event>),
        /// Apply the current table and compare against this `nft list` body.
        Verify(String),
    }

    /// A subsystem under test, driven by a golden scenario.
    pub trait System: Sized {
        /// Builds the subsystem, rendering into `table`.
        fn new(table: String) -> Self;
        /// Ingests one watch event.
        fn ingest(&mut self, event: kube_watch::Event);
        /// The netlink messages rendering the current state.
        fn render(&self) -> Vec<Message>;
    }

    /// Collapse all whitespace, so line wrapping and indentation don't matter.
    pub fn normalize(s: &str) -> String {
        s.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// Applies `messages` to `table` and returns the table body (without the
    /// `table <table> { … }` wrapper) as dumped by `nft list`.
    async fn dump(table: &str, messages: Vec<Message>) -> String {
        // best-effort cleanup: the table usually does not exist yet
        let _ = Command::new("nft")
            .args(["delete", "table", "inet", table])
            .stderr(Stdio::null())
            .status();

        let nl = netfilter::new_link().expect("netlink");
        nl.send_as_transactions(messages.into_iter())
            .await
            .expect("apply");

        let out = Command::new("nft")
            .args(["list", "table", "inet", table])
            .output()
            .expect("nft");
        let dump = String::from_utf8_lossy(&out.stdout).into_owned();
        assert!(out.status.success(), "nft list failed: {dump}");

        let _ = Command::new("nft")
            .args(["delete", "table", "inet", table])
            .status();

        // drop the `table <table> {` opener and the final `}`
        let (_, body) = dump.split_once('{').expect("table opener");
        let (body, _) = body.rsplit_once('}').expect("table closer");

        body.trim().to_string()
    }

    /// Runs a golden scenario (a YAML list of [`Op`]s) against a fresh
    /// `S::new(table)` system: `Ingest` events are fed to it, and every
    /// `Verify` re-applies `render()` and compares the resulting table body
    /// with the expected `nft list` output.
    ///
    /// Requires `CAP_NET_ADMIN`; run with `sudo -E cargo test -- --ignored`.
    pub async fn golden<S: System>(table: impl Into<String>, yaml: &str) {
        let table = table.into();
        let mut system = S::new(table.clone());

        let ops: Vec<Op> = serde_yaml::from_str(yaml).expect("bad scenario yaml");

        for (i, op) in ops.into_iter().enumerate() {
            match op {
                Op::Ingest(events) => {
                    for event in events {
                        system.ingest(event);
                    }
                }
                Op::Verify(expected) => {
                    let actual = dump(&table, system.render()).await;
                    assert_eq!(
                        normalize(&actual),
                        normalize(&expected),
                        "step {i}: table mismatch, actual dump:\n{actual}"
                    );
                }
            }
        }
    }

    /// Runs every `*.yaml` golden scenario in `dir`, each against a table named
    /// `{table_prefix}{file_stem}`.
    ///
    /// Requires `CAP_NET_ADMIN`; run with `sudo -E cargo test -- --ignored`.
    pub async fn golden_dir<S: System>(dir: &str, table_prefix: &str) {
        let mut paths: Vec<_> = std::fs::read_dir(dir)
            .expect("golden dir")
            .map(|e| e.expect("golden dir entry").path())
            .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("yaml"))
            .collect();
        paths.sort();

        for path in paths {
            let stem = path
                .file_stem()
                .and_then(|s| s.to_str())
                .expect("golden file stem");
            let yaml = std::fs::read_to_string(&path).expect("golden file read");
            let table = format!("{table_prefix}{stem}");

            golden::<S>(table, &yaml).await;
        }
    }
}
