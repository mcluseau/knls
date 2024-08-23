use super::*;

#[test]
fn test_table_tracker() -> io::Result<()> {
    let mut table = TableTracker::new("inet kube-proxy".into());

    // initial table
    table.prepare()?;
    table.ctr(CtrKind::Chain, "dispatch", |buf| {
        writeln!(buf, "  test rule")
    })?;

    assert_eq!(
        String::from_utf8_lossy(&table.nft),
        "table inet kube-proxy {};
delete table inet kube-proxy;
table inet kube-proxy {};
chain inet kube-proxy dispatch {
  test rule
};
"
    );

    table.update_done();
    assert_eq!(String::from_utf8_lossy(&table.nft), "");

    // update to the same table
    table.prepare()?;
    assert_eq!(String::from_utf8_lossy(&table.nft), "");
    table.ctr(CtrKind::Chain, "dispatch", |buf| {
        writeln!(buf, "  test rule")
    })?;
    assert_eq!(String::from_utf8_lossy(&table.nft), "");
    table.update_done();
    assert_eq!(String::from_utf8_lossy(&table.nft), "");

    // update with a different chain
    table.prepare()?;
    table.ctr(CtrKind::Chain, "dispatch", |buf| {
        writeln!(buf, "  test rule2")
    })?;

    assert_eq!(
        String::from_utf8_lossy(&table.nft),
        "flush chain inet kube-proxy dispatch;
chain inet kube-proxy dispatch {
  test rule2
};
"
    );

    table.update_done();
    assert_eq!(String::from_utf8_lossy(&table.nft), "");

    Ok(())
}
