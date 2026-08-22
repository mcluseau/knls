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
    assert!(long_id.split_once('/').unwrap().1.len() == 63);
    assert_eq!(
        "disk-wwid.hw.knls.eu/eui.002538a851407b93.002538a851407b93.002538a851407b93.-7doe38t",
        long_id
    );
}
