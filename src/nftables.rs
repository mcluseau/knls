pub mod chain;
pub mod rules;
pub mod set;
pub mod table;
pub mod table_sync;

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
        /// Select a scenario-provided state, e.g. a [`TableSync`] to render.
        ///
        /// [`TableSync`]: crate::nftables::table_sync::TableSync
        Custom(usize),
        /// Run an `nft` script against the kernel, out of band: it changes the
        /// table behind the system's back, so the next `apply` must detect the
        /// divergence and rebuild. `{table}` is replaced by the scenario table.
        Nft(String),
        /// Apply the current table and compare against this `nft list` body.
        Verify(String),
    }

    /// A subsystem under test, driven by a golden scenario.
    ///
    /// `render` is applied to the persistent table at every `Verify` (the table
    /// is emptied once, at the start of the scenario). A full-render system
    /// re-creates the table itself; an incremental one
    /// ([`TableState`](crate::nftables::table_sync::TableState)) emits only the
    /// diff against its previously rendered state, and so must be `&mut self`.
    #[allow(async_fn_in_trait)]
    pub trait System: Sized {
        /// Builds the subsystem, rendering into `table`.
        fn new(table: String) -> Self;
        /// Ingests one watch event.
        fn ingest(&mut self, _event: kube_watch::Event) {}
        /// Selects one of the scenario's states.
        fn custom(&mut self, _id: usize) {}
        /// The netlink messages applying the current state to the table.
        ///
        /// Only needed by the default [`apply`](System::apply); a system that
        /// overrides `apply` need not implement it.
        fn render(&mut self) -> Vec<Message> {
            unimplemented!("implement either `render` or `apply`")
        }
        /// Renders the current state and sends the resulting messages to
        /// `table`. Overridable, e.g. to apply through a
        /// [`TableState`](crate::nftables::table_sync::TableState).
        async fn apply(&mut self, table: &str) {
            let messages = self.render();
            let nl = netfilter::new_link().expect("netlink");
            nl.send_as_transactions(messages.into_iter())
                .await
                .unwrap_or_else(|e| panic!("apply to {table} failed: {e}"));
        }
    }

    /// Collapse all whitespace, so line wrapping and indentation don't matter.
    pub fn normalize(s: &str) -> String {
        s.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// The table body (without the `table <table> { … }` wrapper), with nft's
    /// one level of table indentation stripped — the layout `nft list` would use
    /// for the table's contents alone. The comparison normalizes whitespace, so
    /// this is for the golden's readability only.
    fn table_body(dump: &str) -> String {
        let (_, body) = dump.split_once('{').expect("table opener");
        let (body, _) = body.rsplit_once('}').expect("table closer");

        body.lines()
            .map(|line| line.strip_prefix('\t').unwrap_or(line))
            .collect::<Vec<_>>()
            .join("\n")
            .trim()
            .to_string()
    }

    /// Applies `messages` to a clean `table` and returns the resulting body, as
    /// [`dump`] would. Exposed for scenario drivers that render themselves.
    ///
    /// Requires `CAP_NET_ADMIN`; run with `sudo -E cargo test -- --ignored`.
    pub async fn capture(table: &str, messages: Vec<Message>) -> String {
        dump(table, messages).await
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

        table_body(&dump)
    }

    /// The table body (without the `table <table> { … }` wrapper) as dumped by
    /// `nft list`, without deleting the table first.
    async fn dump_existing(table: &str) -> String {
        let out = Command::new("nft")
            .args(["list", "table", "inet", table])
            .output()
            .expect("nft");
        let dump = String::from_utf8_lossy(&out.stdout).into_owned();
        assert!(out.status.success(), "nft list failed: {dump}");

        table_body(&dump)
    }

    /// Runs a golden scenario (a YAML list of [`Op`]s) against a fresh
    /// `S::new(table)` system: `Ingest`/`Custom`/`Nft` drive it, and every
    /// `Verify` applies the current state to the (once-emptied, then persistent)
    /// table and compares the resulting body with the expected `nft list` output.
    ///
    /// A full-render system re-creates the table itself; an incremental one only
    /// emits the diff against its previous render.
    ///
    /// Requires `CAP_NET_ADMIN`; run with `sudo -E cargo test -- --ignored`.
    pub async fn golden<S: System>(table: impl Into<String>, yaml: &str) {
        let table = table.into();

        // empty the table once: the first `render` builds it.
        let _ = Command::new("nft")
            .args(["delete", "table", "inet", &table])
            .stderr(Stdio::null())
            .status();

        let mut system = S::new(table.clone());

        let ops: Vec<Op> = serde_yaml::from_str(yaml).expect("bad scenario yaml");

        for (i, op) in ops.into_iter().enumerate() {
            match op {
                Op::Ingest(events) => {
                    for event in events {
                        system.ingest(event);
                    }
                }
                Op::Custom(id) => system.custom(id),
                Op::Nft(script) => {
                    let script = script.replace("{table}", &table);
                    super::apply_script(script).await.expect("nft script");
                }
                Op::Verify(expected) => {
                    system.apply(&table).await;
                    let actual = dump_existing(&table).await;
                    assert_eq!(
                        normalize(&actual),
                        normalize(&expected),
                        "step {i}: table mismatch, actual dump:\n{actual}"
                    );
                }
            }
        }

        let _ = Command::new("nft")
            .args(["delete", "table", "inet", &table])
            .status();
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
