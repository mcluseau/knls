use super::*;

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
    assert_eq!(String::from_utf8_lossy(&update.nft), "");
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
