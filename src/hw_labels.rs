use log::error;
use std::collections::BTreeSet as Set;
use std::sync::Arc;
use tokio::{fs, time};

use crate::patch_params;

const LABEL_VALUE: &str = "present";

#[derive(Debug, serde::Deserialize, serde::Serialize)]
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
    format!("{kind}.hw.knls.eu/{id}")
}

fn is_hw_label(label: &str) -> bool {
    label.contains(".hw.knls.eu/")
}

async fn update_node(ctx: &Arc<crate::Context>, labels: &Set<String>) -> eyre::Result<()> {
    use k8s_openapi::api::core::v1::Node;
    use kube::api::Patch;
    use kube::core::PartialObjectMetaExt;

    let nodes = kube::Api::<Node>::all(ctx.kube.clone());
    let name = ctx.node_name.as_str();

    let mut node = nodes.get_metadata(name).await?.metadata;

    let mut node_labels = node.labels.unwrap_or_default();

    node_labels.retain(|k, _| !is_hw_label(k));

    for label in labels {
        node_labels.insert(label.clone(), LABEL_VALUE.into());
    }

    node.labels = Some(node_labels);

    node.managed_fields = None;
    let patch = Patch::Apply(node.into_request_partial::<Node>());

    nodes.patch_metadata(name, &patch_params(), &patch).await?;

    Ok(())
}

async fn my_hw_labels(cfg: &HwLabels) -> std::io::Result<Set<String>> {
    let mut labels = Set::new();
    let mut add = |kind, id: &str| labels.insert(hw_label(kind, id));

    let mut dir = fs::read_dir("/sys/class/block").await?;
    while let Some(sys_dir) = dir.next_entry().await? {
        if cfg.disk_wwid
            && let Some(wwid) = read_sub(&sys_dir, "wwid").await?
        {
            add("disk-wwid", wwid.trim_ascii());
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

                add("part-uuid", partuuid);
            }
        }
    }

    Ok(labels)
}

async fn read_sub(dir: &fs::DirEntry, file: &str) -> std::io::Result<Option<String>> {
    use std::io::ErrorKind;

    let file = dir.path().join(file);

    match fs::read_to_string(&file).await {
        Ok(s) => Ok(Some(s)),
        Err(e) => match e.kind() {
            ErrorKind::NotFound => Ok(None),
            ErrorKind::NotADirectory => Ok(None),
            _ => Err(e),
        },
    }
}
