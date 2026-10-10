use super::Message;
use crate::{
    kube_watch,
    netlink::netfilter::{self, NetlinkExt as _},
};
use std::collections::BTreeMap;
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

/// Splits a dedented table body into its top-level objects, keyed by
/// `"<kind> <name>"` (e.g. `"map my-map"`) with the object's raw text as
/// value.
///
/// `nft list` prints sets/maps then chains, each in creation (handle) order,
/// not sorted; keying by name makes the comparison order-independent and
/// lets a mismatch name the offending object.
fn objects(body: &str) -> BTreeMap<String, String> {
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    let mut name = String::new();
    let mut block = String::new();

    for line in body.lines() {
        // a top-level object starts with its kind keyword at column 0; its
        // body lines (and closing brace) are indented.
        let header =
            line.starts_with("set ") || line.starts_with("map ") || line.starts_with("chain ");
        if header {
            if !name.is_empty() {
                out.insert(std::mem::take(&mut name), block.trim().to_string());
                block.clear();
            }
            name = line.split('{').next().unwrap_or(line).trim().to_string();
        }
        block.push_str(line);
        block.push('\n');
    }
    if !name.is_empty() {
        out.insert(name, block.trim().to_string());
    }
    out
}

/// Compares two table bodies object by object, returning a message that
/// names the first mismatching object.
fn compare_bodies(expected: &str, actual: &str) -> Result<(), String> {
    let expected = objects(expected);
    let actual = objects(actual);

    for (name, want) in &expected {
        match actual.get(name) {
            None => {
                return Err(format!(
                    "{name} is missing from the table. Expected:\n{want}"
                ));
            }
            Some(got) if normalize(got) != normalize(want) => {
                return Err(format!(
                    "{name} does not match. Expected:\n{want}\nGot:\n{got}"
                ));
            }
            _ => {}
        }
    }
    if let Some(name) = actual.keys().find(|name| !expected.contains_key(*name)) {
        return Err(format!(
            "unexpected {name} in the table. Got:\n{}",
            actual[name]
        ));
    }
    Ok(())
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
/// `nft list`, without deleting the table first. Exposed for scenario
/// drivers that apply their own way (e.g. a legacy `nft` script).
pub async fn dump_current(table: &str) -> String {
    dump_existing(table).await
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
                if let Err(message) = compare_bodies(&expected, &actual) {
                    panic!("step {i}: {message}\n\nfull actual dump:\n{actual}");
                }
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

mod tests {
    use super::*;

    const A: &str = "set a {\n\ttype ipv4_addr\n\telements = { 1.2.3.4 }\n}\n\n\
                     chain c {\n\taccept\n}";

    #[test]
    fn objects_splits_top_level_objects_by_name() {
        let objects = objects(A);
        assert_eq!(objects.len(), 2);
        assert!(objects.contains_key("set a"));
        assert!(objects.contains_key("chain c"));
    }

    #[test]
    fn compare_ignores_object_order() {
        let reordered = "chain c {\n\taccept\n}\n\n\
                         set a {\n\ttype ipv4_addr\n\telements = { 1.2.3.4 }\n}";
        assert_eq!(compare_bodies(A, reordered), Ok(()));
    }

    #[test]
    fn compare_names_the_mismatching_object() {
        let changed = "chain c {\n\taccept\n}\n\n\
                       set a {\n\ttype ipv4_addr\n\telements = { 5.6.7.8 }\n}";
        let err = compare_bodies(A, changed).expect_err("a mismatch");
        assert!(err.starts_with("set a does not match"), "{err}");
    }

    #[test]
    fn compare_reports_missing_and_unexpected_objects() {
        let missing = compare_bodies(A, "chain c {\n\taccept\n}").expect_err("missing");
        assert!(missing.starts_with("set a is missing"), "{missing}");

        let extra = compare_bodies("chain c {\n\taccept\n}", A).expect_err("unexpected");
        assert!(extra.starts_with("unexpected set a"), "{extra}");
    }
}
