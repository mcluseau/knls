use log::{error, warn};
use std::collections::BTreeMap as Map;
use std::sync::Arc;
use tokio::{fs, time};
use xxhash_rust::xxh3::xxh3_64;

use crate::patch_params;

#[cfg(test)]
mod test;

const LABEL_VALUE: &str = "present";

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct HwLabels {
    #[serde(default)]
    disk_wwid: bool,
    #[serde(default)]
    part_uuid: bool,
}

pub async fn watch(ctx: Arc<crate::Context>, cfg: HwLabels) -> eyre::Result<()> {
    let mut ticker = time::interval(time::Duration::from_secs(60));

    let mut prev_labels = None;

    loop {
        ticker.tick().await;

        let labels = match my_hw_labels(&cfg).await {
            Ok(v) => v,
            Err(e) => {
                error!("failed to get my labels: {e}");
                continue;
            }
        };

        if prev_labels.as_ref() == Some(&labels) {
            continue;
        }

        if let Err(e) = update_node(&ctx, &labels).await {
            error!("failed to update node: {e}");
            continue;
        }

        prev_labels = Some(labels);
    }
}

fn hw_label(kind: &str, id: &str) -> String {
    let id = if id.len() <= 63 {
        id.to_string()
    } else {
        // id too long for a kube name segment
        let h = xxh3_64(id.as_bytes()).to_le_bytes();
        let suffix = base32::encode(base32::Alphabet::Z, &h);
        format!("{}-{}", &id[..63 - 1 - 7], &suffix[..7])
    };
    format!("{kind}.hw.knls.eu/{id}")
}

fn is_hw_label(label: &str) -> bool {
    label.contains(".hw.knls.eu/")
}

async fn update_node(
    ctx: &Arc<crate::Context>,
    labels: &Map<String, BlockInfo>,
) -> eyre::Result<()> {
    use k8s_openapi::api::core::v1::Node;
    use kube::api::Patch;
    use kube::core::PartialObjectMetaExt;

    let nodes = kube::Api::<Node>::all(ctx.kube.clone());
    let name = ctx.node_name.as_str();

    let mut node = nodes.get_metadata(name).await?.metadata;

    let node_labels = node.labels.get_or_insert_default();
    let node_annotations = node.annotations.get_or_insert_default();

    node_labels.retain(|k, _| !is_hw_label(k));
    node_annotations.retain(|k, _| !is_hw_label(k));

    for (label, info) in labels {
        node_labels.insert(label.clone(), LABEL_VALUE.into());
        node_annotations.insert(label.clone(), format!("{} {}", info.size, info.id));
    }

    node.managed_fields = None;
    let patch = Patch::Apply(node.into_request_partial::<Node>());

    nodes.patch_metadata(name, &patch_params(), &patch).await?;

    Ok(())
}

#[derive(PartialEq, Eq)]
struct BlockInfo {
    id: String,
    size: String,
}

async fn my_hw_labels(cfg: &HwLabels) -> std::io::Result<Map<String, BlockInfo>> {
    let mut labels = Map::new();
    let mut add = |kind, id: &str, size: u64| {
        let info = BlockInfo {
            id: id.into(),
            size: human_size(size),
        };
        labels.insert(hw_label(kind, id), info);
    };

    let mut dir = fs::read_dir("/sys/class/block").await?;
    while let Some(sys_dir) = dir.next_entry().await? {
        let size = (read_sub(&sys_dir, "size").await.ok().and_then(|s| s))
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);

        if cfg.disk_wwid {
            if let Some(wwid) = read_sub(&sys_dir, "wwid").await? {
                add("disk-wwid", wwid.trim_ascii(), size);
            } else if let Some(wwid) = read_sub(&sys_dir, "device/wwid").await? {
                add("disk-wwid", wwid.trim_ascii(), size);
            }
        }

        if cfg.part_uuid {
            let mut dir = fs::read_dir(sys_dir.path()).await?;
            while let Some(sub_dir) = dir.next_entry().await? {
                let Some(uevent) = read_sub(&sub_dir, "uevent").await? else {
                    continue;
                };

                let Some(partuuid) = (uevent.lines())
                    .filter_map(|l| l.strip_prefix("PARTUUID="))
                    .next()
                else {
                    continue;
                };

                add("part-uuid", partuuid, size);
            }
        }
    }

    Ok(labels)
}

async fn read_sub(dir: &fs::DirEntry, file: &str) -> std::io::Result<Option<String>> {
    use nix::errno::Errno;
    use std::io::ErrorKind;

    let file = dir.path().join(file);

    match fs::read_to_string(&file).await {
        // fs::read_to_string(&file).await {
        Ok(s) => Ok(Some(s)),
        Err(e) => match e.kind() {
            ErrorKind::NotFound => Ok(None),
            ErrorKind::NotADirectory => Ok(None),
            _ => match e.raw_os_error().map(Errno::from_raw) {
                Some(Errno::ENXIO | Errno::EINVAL) => Ok(None),
                _ => {
                    warn!(
                        "ignoring read error: {}: {e}",
                        file.as_path().to_string_lossy()
                    );
                    Ok(None)
                }
            },
        },
    }
}

fn human_size(s: u64) -> String {
    for (unit, div) in [
        ("Ti", 1 << 40),
        ("Gi", 1 << 30),
        ("Mi", 1 << 20),
        ("Ki", 1 << 10),
    ] {
        let s = s / div;
        if s >= 100 {
            return format!("{s}{unit}");
        }
    }
    s.to_string()
}
