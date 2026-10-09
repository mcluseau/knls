use super::*;

use crate::{kube_watch::Event, nftables::test_harness};
use test_harness::System as _;

#[test]
fn test_table_tracker() -> eyre::Result<()> {
    let mut table = TableTracker::new("inet kube-proxy".into());
    let mut nft = Vec::new();

    // initial table
    let mut update = table.update(&mut nft);
    update.prepare()?;
    update.ctr(CtrKind::Chain, "dispatch", |buf| {
        writeln!(buf, "  test rule")
    })?;
    update.finalize()?;

    assert_eq!(
        &nft,
        b"table inet kube-proxy {};
delete table inet kube-proxy;
table inet kube-proxy {};
chain inet kube-proxy dispatch {
  test rule
};
"
    );

    table.update_done();

    // update with the same table
    nft.clear();
    let mut update = table.update(&mut nft);
    update.prepare()?;
    assert_eq!(String::from_utf8_lossy(update.nft), "");
    update.ctr(CtrKind::Chain, "dispatch", |buf| {
        writeln!(buf, "  test rule")
    })?;
    update.finalize()?;

    assert_eq!(nft, b"");
    table.update_done();

    // update with a different chain
    nft.clear();
    let mut update = table.update(&mut nft);
    update.prepare()?;
    update.ctr(CtrKind::Chain, "dispatch", |buf| {
        writeln!(buf, "  test rule2")
    })?;
    update.finalize()?;

    assert_eq!(
        nft,
        b"flush chain inet kube-proxy dispatch;
chain inet kube-proxy dispatch {
  test rule2
};
"
    );

    table.update_done();

    Ok(())
}

/// A [`test_harness::System`] driving the *current* (script-based) proxy
/// renderer: `apply` renders the nft script and pipes it through the `nft`
/// binary, exactly as `update_table` does.
///
/// It exists to capture the pre-migration table as goldens under
/// `test_assets/golden-nftables/proxy/`, which the `TableSync` migration must
/// reproduce. The comparison is at the `nft list` level, so the same scenarios
/// can later be pointed at a netlink `TableState` without changing the goldens.
struct TestSystem {
    cfg: Config,
    state: crate::state::State,
    table: TableTracker,
}

impl test_harness::System for TestSystem {
    fn new(table: String) -> Self {
        Self {
            cfg: Config {
                table: table.clone(),
                disable_nodeports: false,
            },
            state: crate::state::State::new("n1".into()),
            table: TableTracker::new(format!("inet {table}")),
        }
    }

    fn ingest(&mut self, event: Event) {
        self.state.ingest(&event);
    }

    async fn apply(&mut self, _table: &str) {
        let my_node = self.state.my_node.get().cloned().expect("my node");
        let cfg =
            proxy::from_state(&self.state, self.cfg.disable_nodeports).expect("state not ready");

        let mut script = Vec::new();
        update_table_to(&mut script, &mut self.table, &my_node, &cfg).expect("render");

        crate::nftables::apply_script(String::from_utf8(script).expect("utf8 script"))
            .await
            .expect("apply script");

        self.table.update_done();
    }
}

/// Golden tests: each `test_assets/golden-nftables/proxy/*.yaml` scenario,
/// driven through the current script renderer and compared to `nft list` at
/// each step.
///
/// Requires `CAP_NET_ADMIN`; run with `sudo -E cargo test -- --ignored`.
#[ignore = "requires CAP_NET_ADMIN and a real kernel"]
#[tokio::test]
async fn golden() {
    test_harness::golden_dir::<TestSystem>("test_assets/golden-nftables/proxy", "knls-test-proxy-")
        .await;
}

/// Prints, for each `test_assets/golden-nftables/proxy/*.yaml` scenario, the
/// kernel body after every `!verify` step. Used to (re)generate the goldens.
///
/// Requires `CAP_NET_ADMIN`; run with `sudo -E cargo test -- --ignored --nocapture`.
#[ignore = "requires CAP_NET_ADMIN and a real kernel"]
#[tokio::test]
async fn print_goldens() {
    let dir = "test_assets/golden-nftables/proxy";
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
        let table = format!("knls-test-proxy-regen-{stem}");

        let _ = std::process::Command::new("nft")
            .args(["delete", "table", "inet", &table])
            .stderr(std::process::Stdio::null())
            .status();

        let yaml = std::fs::read_to_string(&path).expect("golden file read");
        let ops: Vec<test_harness::Op> = serde_yaml::from_str(&yaml).expect("bad scenario yaml");

        let mut system = TestSystem::new(table.clone());
        let mut step = 0;
        for op in ops {
            match op {
                test_harness::Op::Ingest(events) => {
                    for event in events {
                        system.ingest(event);
                    }
                }
                test_harness::Op::Custom(id) => system.custom(id),
                test_harness::Op::Nft(script) => {
                    let script = script.replace("{table}", &table);
                    crate::nftables::apply_script(script)
                        .await
                        .expect("nft script");
                }
                test_harness::Op::Verify(_) => {
                    system.apply(&table).await;
                    let body = test_harness::dump_current(&table).await;
                    println!("=== {stem} step {step} ===\n{body}\n");
                    step += 1;
                }
            }
        }

        let _ = std::process::Command::new("nft")
            .args(["delete", "table", "inet", &table])
            .status();
    }
}
