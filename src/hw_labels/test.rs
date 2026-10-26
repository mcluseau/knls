use super::*;

fn valid_name_part(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        && name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric())
        && name
            .chars()
            .last()
            .is_some_and(|c| c.is_ascii_alphanumeric())
}

fn name_part(label: &str) -> &str {
    label.split_once('/').expect("qualified label name").1
}

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

#[test]
fn invalid_ids_are_sanitized() {
    let id = "t10.ATA     EMTEC X150 120GB                        511";
    let label = hw_label("disk-wwid", id);
    let name = name_part(&label);
    assert!(valid_name_part(name), "{label}");
    assert!(name.starts_with("t10.ATA-EMTEC-X150-120GB-511-"), "{label}");

    // distinct raw ids must not collapse onto one label
    assert_ne!(hw_label("part-uuid", "a b"), hw_label("part-uuid", "a-b"));

    for id in ["- abc.- ", "   ", "", &"x ".repeat(100)] {
        let label = hw_label("part-uuid", id);
        assert!(valid_name_part(name_part(&label)), "{id:?} -> {label}");
    }
}
