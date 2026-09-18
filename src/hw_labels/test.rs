use super::*;

#[test]
fn test_hw_label() {
    // normal id
    assert_eq!(
        "disk-wwid.hw.knls.eu/eui.002538a851407b93",
        hw_label("disk-wwid", "eui.002538a851407b93")
    );

    // long id
    let long_id = hw_label(
        "disk-wwid",
        "eui.002538a851407b93.002538a851407b93.002538a851407b93.002538a851407b93",
    );
    assert_eq!(Some(63), long_id.split_once('/').map(|(_, l)| l.len()));
    assert_eq!(
        "disk-wwid.hw.knls.eu/eui.002538a851407b93.002538a851407b93.002538a851407b93.-7doe38t",
        long_id
    );
}
