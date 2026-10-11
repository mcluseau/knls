use super::*;

use crate::{
    kube_watch::{Change, Event},
    nftables::test_harness,
};
use k8s_openapi::api::{core::v1 as core, discovery::v1 as discovery};
use std::sync::Arc;
use test_harness::System as _;

fn node() -> core::Node {
    serde_json::from_value(serde_json::json!({
        "metadata": { "name": "n1" },
        "spec": { "podCIDRs": ["10.244.0.0/24"] },
        "status": { "addresses": [{ "type": "InternalIP", "address": "192.168.1.10" }] },
    }))
    .expect("node")
}

fn service() -> core::Service {
    serde_json::from_value(serde_json::json!({
        "metadata": { "name": "web", "namespace": "default" },
        "spec": {
            "type": "ClusterIP",
            "clusterIPs": ["10.96.0.10"],
            "ports": [{ "name": "http", "protocol": "TCP", "port": 80, "targetPort": 8080 }],
        },
    }))
    .expect("service")
}

fn slice() -> discovery::EndpointSlice {
    serde_json::from_value(serde_json::json!({
        "metadata": {
            "name": "web-abc",
            "namespace": "default",
            "labels": { "kubernetes.io/service-name": "web" },
        },
        "addressType": "IPv4",
        "endpoints": [{ "addresses": ["10.244.0.5"], "conditions": { "ready": true }, "nodeName": "n1" }],
        "ports": [{ "name": "http", "port": 8080, "protocol": "TCP" }],
    }))
    .expect("slice")
}

/// A ready state with one ClusterIP service and one local endpoint.
fn ready_state() -> crate::state::State {
    let mut state = crate::state::State::new("n1".into());
    state.ingest(&Event::MyNode(Change::InitApply(Arc::new(node()))));
    state.ingest(&Event::MyNode(Change::InitDone));
    state.ingest(&Event::Service(Change::InitApply(Arc::new(service()))));
    state.ingest(&Event::EndpointSlice(Change::InitApply(Arc::new(slice()))));
    state.ingest(&Event::Service(Change::InitDone));
    state.ingest(&Event::EndpointSlice(Change::InitDone));
    state
}

/// A ready state with one ClusterIP service and the given local endpoint IPs.
fn state_with_eps(ips: &[&str]) -> crate::state::State {
    let mut state = crate::state::State::new("n1".into());
    state.ingest(&Event::MyNode(Change::InitApply(Arc::new(node()))));
    state.ingest(&Event::MyNode(Change::InitDone));
    state.ingest(&Event::Service(Change::InitApply(Arc::new(service()))));

    let endpoints: Vec<serde_json::Value> = ips
        .iter()
        .map(|ip| {
            serde_json::json!({
                "addresses": [ip],
                "conditions": { "ready": true },
                "nodeName": "n1",
            })
        })
        .collect();
    let slice: discovery::EndpointSlice = serde_json::from_value(serde_json::json!({
        "metadata": {
            "name": "web-abc",
            "namespace": "default",
            "labels": { "kubernetes.io/service-name": "web" },
        },
        "addressType": "IPv4",
        "endpoints": endpoints,
        "ports": [{ "name": "http", "port": 8080, "protocol": "TCP" }],
    }))
    .expect("slice");

    state.ingest(&Event::EndpointSlice(Change::InitApply(Arc::new(slice))));
    state.ingest(&Event::Service(Change::InitDone));
    state.ingest(&Event::EndpointSlice(Change::InitDone));
    state
}

/// The dispatch map's `n -> endpoint chain`, for assertions.
fn dispatch_map(table: &TableSync) -> std::collections::BTreeMap<u32, String> {
    let SetSync::VerdictMap(vm) = &table.sets["svc_default_web"] else {
        panic!("not a verdict map");
    };
    vm.entries
        .iter()
        .map(|(key, verdict)| {
            let n = u32::from_ne_bytes(key.as_slice().try_into().expect("4-byte key"));
            let Verdict::Goto(chain) = verdict else {
                panic!("not a goto");
            };
            (n, chain.clone())
        })
        .collect()
}

/// Adding an endpoint appends a slot and removing one is swap-removed, so
/// existing endpoints keep their `numgen` index across renders.
#[test]
fn dispatch_indices_are_stable_across_renders() {
    let mut dispatch = DispatchIndices::default();
    let render_eps = |eps: &[&str], dispatch: &mut DispatchIndices| {
        let state = state_with_eps(eps);
        let cfg = proxy::from_state(&state, false).expect("ready");
        let node = state.my_node.get().expect("node");
        render(node, &cfg, dispatch)
    };

    let a = render_eps(&["10.244.0.5", "10.244.0.6"], &mut dispatch);
    let m = dispatch_map(&a);
    assert_eq!(
        m.get(&0).map(String::as_str),
        Some("svc_default_web_ep_0af40005")
    );
    assert_eq!(
        m.get(&1).map(String::as_str),
        Some("svc_default_web_ep_0af40006")
    );

    // adding an endpoint keeps the existing indices and appends the new one
    let b = render_eps(&["10.244.0.5", "10.244.0.6", "10.244.0.7"], &mut dispatch);
    let m = dispatch_map(&b);
    assert_eq!(
        m.get(&0).map(String::as_str),
        Some("svc_default_web_ep_0af40005")
    );
    assert_eq!(
        m.get(&1).map(String::as_str),
        Some("svc_default_web_ep_0af40006")
    );
    assert_eq!(
        m.get(&2).map(String::as_str),
        Some("svc_default_web_ep_0af40007")
    );

    // removing the slot-0 endpoint moves the last endpoint into it
    let c = render_eps(&["10.244.0.6", "10.244.0.7"], &mut dispatch);
    let m = dispatch_map(&c);
    assert_eq!(
        m.get(&0).map(String::as_str),
        Some("svc_default_web_ep_0af40007")
    );
    assert_eq!(
        m.get(&1).map(String::as_str),
        Some("svc_default_web_ep_0af40006")
    );
}

/// Updating an EndpointSlice to carry the `service.kubernetes.io/headless`
/// label drops its endpoints (the Service is headless), so the service chain
/// rejects and its dispatch map is no longer emitted at all.
#[test]
fn headless_slice_label_drops_endpoints() {
    let state = ready_state();
    let cfg = proxy::from_state(&state, false).expect("ready");
    let before = render(
        state.my_node.get().expect("node"),
        &cfg,
        &mut DispatchIndices::default(),
    );
    assert!(!dispatch_map(&before).is_empty(), "endpoint dispatched");

    let mut state2 = ready_state();
    let mut updated = slice();
    updated
        .metadata
        .labels
        .as_mut()
        .expect("labels")
        .insert("service.kubernetes.io/headless".into(), "".into());
    state2.ingest(&Event::EndpointSlice(Change::Apply(Arc::new(updated))));

    let cfg2 = proxy::from_state(&state2, false).expect("ready");
    let after = render(
        state2.my_node.get().expect("node"),
        &cfg2,
        &mut DispatchIndices::default(),
    );
    // the Service has no endpoints now: no dispatch map (the chain rejects)
    assert!(!after.sets.contains_key("svc_default_web"));
}

/// Only Ready node-local endpoints count towards a Service's health-check
/// NodePort; terminating (serving but not Ready) and remote endpoints do not.
#[test]
fn local_ready_endpoint_count_ignores_terminating_and_remote() {
    let mut state = crate::state::State::new("n1".into());
    state.ingest(&Event::MyNode(Change::InitApply(Arc::new(node()))));
    state.ingest(&Event::MyNode(Change::InitDone));
    state.ingest(&Event::Service(Change::InitApply(Arc::new(service()))));

    let slice: discovery::EndpointSlice = serde_json::from_value(serde_json::json!({
        "metadata": {
            "name": "web-abc",
            "namespace": "default",
            "labels": { "kubernetes.io/service-name": "web" },
        },
        "addressType": "IPv4",
        "endpoints": [
            { "addresses": ["10.244.0.5"], "conditions": { "ready": true }, "nodeName": "n1" },
            {
                "addresses": ["10.244.0.6"],
                "conditions": { "ready": false, "serving": true, "terminating": true },
                "nodeName": "n1",
            },
            { "addresses": ["10.244.0.7"], "conditions": { "ready": true }, "nodeName": "n2" },
        ],
        "ports": [{ "name": "http", "port": 8080, "protocol": "TCP" }],
    }))
    .expect("slice");

    state.ingest(&Event::EndpointSlice(Change::InitApply(Arc::new(slice))));
    state.ingest(&Event::Service(Change::InitDone));
    state.ingest(&Event::EndpointSlice(Change::InitDone));

    let key = crate::state::keys::Object {
        namespace: "default".into(),
        name: "web".into(),
    };
    assert_eq!(state.local_ready_endpoint_count(&key), 1);
}

/// Renders the same state twice: the two `TableSync`s are structurally equal,
/// and diffing one against the other emits nothing.
#[test]
fn render_is_deterministic_and_a_noop_syncs_nothing() {
    let state = ready_state();
    let cfg = proxy::from_state(&state, false).expect("ready");
    let node = state.my_node.get().expect("node");

    let a = render(node, &cfg, &mut DispatchIndices::default());
    let b = render(node, &cfg, &mut DispatchIndices::default());

    let prev = a.reference("t");
    assert_eq!(prev, b.reference("t"));
    assert!(crate::nftables::table_sync::sync("t", Some(&prev), &b).is_empty());
}

/// A first-apply full create and the incremental diff to the same target both
/// produce the table (a pure-logic sanity check of the renderer's shape).
#[test]
fn render_has_base_chains_and_dispatch() {
    let state = ready_state();
    let cfg = proxy::from_state(&state, false).expect("ready");
    let table = render(
        state.my_node.get().expect("node"),
        &cfg,
        &mut DispatchIndices::default(),
    );

    for name in [
        "dispatch",
        "a_hook_dnat_prerouting",
        "a_hook_dnat_output",
        "a_hook_dnat_postrouting",
    ] {
        assert!(table.chains.contains_key(name), "missing chain {name}");
    }
    for name in ["service_ips", "service_nodeports", "need_masquerade"] {
        assert!(table.sets.contains_key(name), "missing set {name}");
    }
    // the per-service map and chain share a name
    assert!(table.chains.contains_key("svc_default_web"));
    assert!(table.sets.contains_key("svc_default_web"));
}

/// A [`test_harness::System`] rendering the proxy as a [`TableSync`] and
/// applying it over netlink through a [`TableState`], exactly as `watch` does.
struct NetlinkSystem {
    state: crate::state::State,
    table: TableState,
    dispatch: DispatchIndices,
}

impl test_harness::System for NetlinkSystem {
    fn new(table: String) -> Self {
        Self {
            state: crate::state::State::new("n1".into()),
            table: TableState::new(table),
            dispatch: DispatchIndices::default(),
        }
    }

    fn ingest(&mut self, event: Event) {
        self.state.ingest(&event);
    }

    async fn apply(&mut self, _table: &str) {
        let my_node = self.state.my_node.get().cloned().expect("my node");
        let cfg = proxy::from_state(&self.state, false).expect("state not ready");
        self.table
            .update(render(&my_node, &cfg, &mut self.dispatch))
            .await
            .expect("apply");
    }
}

/// Golden tests: each `test_assets/golden-nftables/proxy/*.yaml` scenario,
/// rendered as a `TableSync` and applied over netlink (incrementally), compared
/// to `nft list` at each step.
///
/// Requires `CAP_NET_ADMIN`; run with `sudo -E cargo test -- --ignored`.
#[ignore = "requires CAP_NET_ADMIN and a real kernel"]
#[tokio::test]
async fn golden() {
    test_harness::golden_dir::<NetlinkSystem>(
        "test_assets/golden-nftables/proxy",
        "knls-test-proxy-",
    )
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

        let mut system = NetlinkSystem::new(table.clone());
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
