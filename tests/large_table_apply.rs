//! Kernel regression test for applying a large nftables table.
//!
//! Every nft message is acknowledged individually, and netlink-proto only
//! closes the request stream once all of them are acked. A transaction with too
//! many messages therefore used to overflow the socket receive buffer
//! (`ENOBUFS`), drop the batch-end ack and hang the apply.
//!
//! This lives in its own test binary so it does not run concurrently with the
//! other kernel tests: concurrent nftables writers make the `nft`-based golden
//! dumps flaky (a `nft list` racing another commit can transiently repeat a
//! chain).
//!
//! Requires `CAP_NET_ADMIN`; run with `sudo -E cargo test -- --ignored`.

use knls::nftables::{
    rules,
    table_sync::{ChainSync, TableState, TableSync},
};
use std::process::{Command, Stdio};

/// A full create of a big table must not hang. Before the per-transaction
/// message cap, the ~10k messages here landed in one transaction, whose acks
/// overflowed the receive buffer.
#[ignore = "requires CAP_NET_ADMIN and a real kernel"]
#[tokio::test]
async fn large_full_create_does_not_hang() {
    let table = "knls-test-table-sync-large";
    let _ = Command::new("nft")
        .args(["delete", "table", "inet", table])
        .stderr(Stdio::null())
        .status();

    // 5000 chains x 2 messages each exceeds both the 2 MiB transaction bound
    // and the 1024-message cap
    let mut next = TableSync::default();
    for i in 0..5000 {
        next.chains.insert(
            format!("c{i}"),
            ChainSync {
                base: None,
                rules: vec![vec![rules::accept()]],
                anon_sets: Vec::new(),
            },
        );
    }

    let mut state = TableState::new(table.to_string());
    tokio::time::timeout(std::time::Duration::from_secs(120), state.update(next))
        .await
        .expect("apply must not hang")
        .expect("apply");

    let _ = Command::new("nft")
        .args(["delete", "table", "inet", table])
        .status();
}
