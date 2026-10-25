use super::*;
use crate::nftables::{
    Message,
    chain::{self, Rule},
    rules,
    rules::{Dir, Family},
    set, test_harness,
};
use netlink_packet_core::NetlinkPayload;
use netlink_packet_netfilter::{
    NetfilterMessage, NetfilterMessageInner,
    nftables::{
        ChainAttribute, DataAttribute, NfTablesMessage, RuleAttribute, SetAttribute,
        SetElementAttribute, SetElementList,
    },
};
use std::net::{Ipv4Addr, Ipv6Addr};

/// `sync`'s groups flattened, for asserting on the message stream.
fn sync_all(table: &str, prev: Option<&TableSyncRef>, next: &TableSync) -> Vec<Message> {
    sync(table, prev, next).into_iter().flatten().collect()
}

/// A coarse classification of the messages `sync` emits, for asserting the
/// diff structure without a kernel.
#[derive(Debug, PartialEq, Eq)]
enum Step {
    /// A `table::recreate` message (create/delete/new).
    Recreate,
    NewSet(String),
    DeleteSet(String),
    NewChain(String),
    DeleteChain(String),
    /// A `flush chain` (DeleteRule carrying only table + chain).
    Flush(String),
    NewRule(String),
    /// A set element add (`true` = delete, not add).
    Elem(String, bool),
}

fn classify(msg: &Message) -> Step {
    let NetlinkPayload::InnerMessage(NetfilterMessage { inner, .. }) = &msg.payload else {
        panic!("not an inner message");
    };
    match inner {
        NetfilterMessageInner::NfTables(NfTablesMessage::NewTable(_))
        | NetfilterMessageInner::NfTables(NfTablesMessage::DeleteTable(_)) => Step::Recreate,
        NetfilterMessageInner::NfTables(NfTablesMessage::NewSet(m)) => Step::NewSet(set_name(m)),
        NetfilterMessageInner::NfTables(NfTablesMessage::DeleteSet(m)) => {
            Step::DeleteSet(set_name(m))
        }
        NetfilterMessageInner::NfTables(NfTablesMessage::NewChain(m)) => {
            Step::NewChain(chain_name(m))
        }
        NetfilterMessageInner::NfTables(NfTablesMessage::DeleteChain(m)) => {
            Step::DeleteChain(chain_name(m))
        }
        NetfilterMessageInner::NfTables(NfTablesMessage::DeleteRule(m)) => {
            let chain = m
                .attributes
                .iter()
                .find_map(|a| match a {
                    RuleAttribute::Chain(c) => Some(c.clone()),
                    _ => None,
                })
                .expect("chain");
            Step::Flush(chain)
        }
        NetfilterMessageInner::NfTables(NfTablesMessage::NewRule(m)) => {
            let chain = m
                .attributes
                .iter()
                .find_map(|a| match a {
                    RuleAttribute::Chain(c) => Some(c.clone()),
                    _ => None,
                })
                .expect("chain");
            Step::NewRule(chain)
        }
        NetfilterMessageInner::NfTables(NfTablesMessage::NewSetElement(m)) => {
            Step::Elem(first_elem_set(m), false)
        }
        NetfilterMessageInner::NfTables(NfTablesMessage::DeleteSetElement(m)) => {
            Step::Elem(first_elem_set(m), true)
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

fn steps(msgs: &[Message]) -> Vec<Step> {
    msgs.iter().map(classify).collect()
}

fn set_name(m: &netlink_packet_netfilter::nftables::SetMessage) -> String {
    m.attributes
        .iter()
        .find_map(|a| match a {
            SetAttribute::Name(n) => Some(n.clone()),
            _ => None,
        })
        .expect("set name")
}

fn chain_name(m: &netlink_packet_netfilter::nftables::ChainMessage) -> String {
    m.attributes
        .iter()
        .find_map(|a| match a {
            ChainAttribute::Name(n) => Some(n.clone()),
            _ => None,
        })
        .expect("chain name")
}

fn first_elem_set(m: &netlink_packet_netfilter::nftables::SetElementMessage) -> String {
    m.attributes
        .iter()
        .find_map(|a| match a {
            SetElementList::Set(s) => Some(s.clone()),
            _ => None,
        })
        .expect("set name")
}

/// The raw keys of every element in a set-element message.
fn elem_keys(msg: &Message) -> Vec<Vec<u8>> {
    let NetlinkPayload::InnerMessage(NetfilterMessage {
        inner:
            NetfilterMessageInner::NfTables(
                NfTablesMessage::NewSetElement(m) | NfTablesMessage::DeleteSetElement(m),
            ),
        ..
    }) = &msg.payload
    else {
        panic!("not a set element message");
    };
    m.attributes
        .iter()
        .find_map(|a| match a {
            SetElementList::Elements(e) => Some(e),
            _ => None,
        })
        .expect("elements")
        .iter()
        .filter_map(|item| match item {
            netlink_packet_netfilter::nftables::ListAttribute::Element(attrs) => {
                attrs.iter().find_map(|a| match a {
                    SetElementAttribute::Key(DataAttribute::Value(v)) => Some(v.clone()),
                    _ => None,
                })
            }
            _ => None,
        })
        .collect()
}

fn v4(n: u8) -> Vec<u8> {
    Ipv4Addr::new(10, 0, 0, n).elem_data()
}

fn rule(name: &str) -> Rule {
    vec![rules::jump(name)]
}

/// A table with one simple set `s` and one regular chain `c`.
fn table_with_set(keys: impl IntoIterator<Item = u8>) -> TableSync {
    let mut t = TableSync::default();
    t.sets.insert(
        "s".into(),
        SetSync::simple(keys.into_iter().map(|n| Ipv4Addr::new(10, 0, 0, n)), None),
    );
    t
}

fn table_with_chain(rules: Vec<Rule>) -> TableSync {
    let mut t = TableSync::default();
    t.chains.insert(
        "c".into(),
        ChainSync {
            base: None,
            rules,
            anon_sets: Vec::new(),
        },
    );
    t
}

fn table_all() -> TableSync {
    let mut t = table_with_set([1, 2, 3]);
    t.chains.insert(
        "c".into(),
        ChainSync {
            base: None,
            rules: vec![rule("other")],
            anon_sets: Vec::new(),
        },
    );
    t
}

#[test]
fn first_apply_is_a_full_create() {
    let next = table_all();
    let msgs = sync_all("t", None, &next);
    let s = steps(&msgs);

    // recreate, then the set and the chain
    assert_eq!(s[0], Step::Recreate);
    assert!(s.contains(&Step::NewSet("s".into())));
    assert!(s.contains(&Step::NewChain("c".into())));
    assert!(s.contains(&Step::NewRule("c".into())));
    // no container/element deletes on a first apply
    assert!(
        !s.iter().any(|x| matches!(
            x,
            Step::DeleteSet(_) | Step::DeleteChain(_) | Step::Elem(_, true)
        )),
        "unexpected deletes: {s:?}"
    );
    // the set is created before it is filled
    let create = s.iter().position(|x| *x == Step::NewSet("s".into()));
    let fill = s.iter().position(|x| *x == Step::Elem("s".into(), false));
    assert!(create < fill, "set created before filled");
}

#[test]
fn noop_emits_nothing() {
    let next = table_all();
    let prev = next.reference("t");
    assert!(sync_all("t", Some(&prev), &next).is_empty());
}

#[test]
fn set_element_add_and_remove() {
    let old = table_with_set([1, 2, 3]);
    let new = table_with_set([2, 3, 4]);

    let prev = old.reference("t");
    let msgs = sync_all("t", Some(&prev), &new);
    let s = steps(&msgs);

    // exactly one delete (10.0.0.1) then one add (10.0.0.4), no recreate
    assert_eq!(
        s,
        vec![Step::Elem("s".into(), true), Step::Elem("s".into(), false)]
    );
    assert_eq!(elem_keys(&msgs[0]), vec![v4(1)]);
    assert_eq!(elem_keys(&msgs[1]), vec![v4(4)]);
}

#[test]
fn unchanged_set_is_not_recreated() {
    let old = table_with_set([1, 2]);
    let new = table_with_set([1, 2]);
    let prev = old.reference("t");
    assert!(sync_all("t", Some(&prev), &new).is_empty());
}

#[test]
fn map_value_change_deletes_then_adds() {
    let mut old = TableSync::default();
    old.sets.insert(
        "m".into(),
        SetSync::map(
            [
                (Ipv4Addr::new(10, 0, 0, 1), 80u16),
                (Ipv4Addr::new(10, 0, 0, 2), 443u16),
            ],
            None,
        ),
    );
    let mut new = TableSync::default();
    new.sets.insert(
        "m".into(),
        SetSync::map(
            [
                (Ipv4Addr::new(10, 0, 0, 1), 8080u16),
                (Ipv4Addr::new(10, 0, 0, 2), 443u16),
            ],
            None,
        ),
    );

    let prev = old.reference("t");
    let msgs = sync_all("t", Some(&prev), &new);
    assert_eq!(
        steps(&msgs),
        vec![Step::Elem("m".into(), true), Step::Elem("m".into(), false)]
    );
    // the changed key (10.0.0.1) is deleted then re-added
    assert_eq!(elem_keys(&msgs[0]), vec![v4(1)]);
    assert_eq!(elem_keys(&msgs[1]), vec![v4(1)]);
}

#[test]
fn chain_rule_change_flushes_and_refills() {
    let old = table_with_chain(vec![rule("a")]);
    let new = table_with_chain(vec![rule("b")]);

    let prev = old.reference("t");
    let msgs = sync_all("t", Some(&prev), &new);
    assert_eq!(
        steps(&msgs),
        vec![Step::Flush("c".into()), Step::NewRule("c".into())]
    );
}

#[test]
fn unchanged_chain_is_not_flushed() {
    let old = table_with_chain(vec![rule("a")]);
    let new = table_with_chain(vec![rule("a")]);
    let prev = old.reference("t");
    assert!(sync_all("t", Some(&prev), &new).is_empty());
}

#[test]
fn set_metadata_change_is_a_full_recreate() {
    let old = table_with_set([1]);
    // same name, different key type (v6 instead of v4)
    let mut new = TableSync::default();
    new.sets
        .insert("s".into(), SetSync::simple([Ipv6Addr::LOCALHOST], None));

    let prev = old.reference("t");
    let msgs = sync_all("t", Some(&prev), &new);
    assert_eq!(
        classify(&msgs[0]),
        Step::Recreate,
        "expected a full recreate"
    );
    // and it rebuilds the new set
    assert!(steps(&msgs).contains(&Step::NewSet("s".into())));
}

#[test]
fn comment_only_change_reissues_the_set() {
    let old = table_with_set([1, 2]);
    let mut new = table_with_set([1, 2]);
    if let Some(SetSync::Set(s)) = new.sets.get_mut("s") {
        s.meta.comment = Some("hello".into());
    }

    let prev = old.reference("t");
    let msgs = sync_all("t", Some(&prev), &new);
    let s = steps(&msgs);
    // no recreate, no element diff; just a NewSet carrying the comment
    assert_eq!(s, vec![Step::NewSet("s".into())]);
    let new_set = msgs.iter().find_map(|m| match &m.payload {
        NetlinkPayload::InnerMessage(NetfilterMessage {
            inner: NetfilterMessageInner::NfTables(NfTablesMessage::NewSet(s)),
            ..
        }) => Some(s.attributes.clone()),
        _ => None,
    });
    let userdata = new_set.expect("a NewSet").iter().find_map(|a| match a {
        SetAttribute::UserData(u) => Some(u.clone()),
        _ => None,
    });
    assert_eq!(userdata.as_deref(), Some(&b"\x07\x06hello\x00"[..]));
}

#[test]
fn base_chain_change_is_a_full_recreate() {
    let old = table_with_chain(vec![rule("a")]);
    let mut new = table_with_chain(vec![rule("a")]);
    new.chains.get_mut("c").expect("c").base = Some(BaseChain {
        chain_type: chain::ChainType::Filter,
        hook: chain::InetHookNumber::Forward,
        priority: 0,
        policy: chain::ACCEPT,
    });

    let prev = old.reference("t");
    let msgs = sync_all("t", Some(&prev), &new);
    assert_eq!(classify(&msgs[0]), Step::Recreate);
}

#[test]
fn verdict_map_goto_new_chain_orders_chain_before_map_fill() {
    // `old` has no chain `pod`; `new` adds it and a vmap entry goto'ing it.
    let old = TableSync::default();

    let mut new = TableSync::default();
    new.chains.insert(
        "pod".into(),
        ChainSync {
            base: None,
            rules: vec![vec![rules::accept()]],
            anon_sets: Vec::new(),
        },
    );
    new.sets.insert(
        "vm".into(),
        SetSync::verdict_map(
            [(Ipv4Addr::new(10, 0, 0, 1), set::Verdict::Goto("pod".into()))],
            None,
        ),
    );

    let prev = old.reference("t");
    let msgs = sync_all("t", Some(&prev), &new);
    let s = steps(&msgs);

    let chain_create = s
        .iter()
        .position(|x| *x == Step::NewChain("pod".into()))
        .expect("chain created");
    let vmap_fill = s
        .iter()
        .position(|x| *x == Step::Elem("vm".into(), false))
        .expect("vmap filled");
    assert!(
        chain_create < vmap_fill,
        "chain must exist before its goto target is filled: {s:?}"
    );
}

#[test]
fn removed_set_and_chain_are_deleted_last() {
    let old = table_all();
    let mut new = table_with_set([1, 2, 3]);
    // drop the chain `c`, keep set `s`
    new.chains.clear();

    let prev = old.reference("t");
    let msgs = sync_all("t", Some(&prev), &new);
    let s = steps(&msgs);

    assert_eq!(s, vec![Step::DeleteChain("c".into())]);

    // and dropping a set too
    let empty = TableSync::default();
    let prev = old.reference("t");
    let msgs = sync_all("t", Some(&prev), &empty);
    let s = steps(&msgs);
    assert_eq!(
        s,
        vec![Step::DeleteChain("c".into()), Step::DeleteSet("s".into())]
    );
}

#[test]
fn reference_hash_detects_anonymous_set_content_change() {
    // a chain whose rule references an anon set; the rule itself is unchanged.
    let set1 = vec![SetSync::interval(
        [(Ipv4Addr::new(10, 0, 0, 1)..=Ipv4Addr::new(10, 0, 0, 1))],
        None,
    )];
    let set2 = vec![SetSync::interval(
        [(Ipv4Addr::new(10, 0, 0, 1)..=Ipv4Addr::new(10, 0, 0, 2))],
        None,
    )];

    let old = ChainSync {
        base: None,
        rules: vec![rule("x")],
        anon_sets: set1,
    };
    let new = ChainSync {
        base: None,
        rules: vec![rule("x")],
        anon_sets: set2,
    };

    let old_ref = ChainRef {
        base: None,
        hash: chain_hash("t", "c", &old),
    };
    let new_ref = ChainRef {
        base: None,
        hash: chain_hash("t", "c", &new),
    };
    assert_ne!(old_ref.hash, new_ref.hash);
}

//----------------------------------------------------------------------------
// Kernel golden scenario: a table mutated across several incremental syncs.
//----------------------------------------------------------------------------

fn ip(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
    Ipv4Addr::new(a, b, c, d)
}

/// A table with a set, a named interval set, a verdict map, a base chain and
/// three regular chains, one of which carries an anonymous port set.
fn scenario_states() -> Vec<TableSync> {
    let src = |keys: &[u8]| SetSync::simple(keys.iter().map(|n| Ipv4Addr::new(10, 0, 0, *n)), None);
    let pod_accept = || {
        let mut c = ChainSync::default();
        c.rules.push(vec![rules::accept()]);
        c
    };
    let pod_b = || {
        let mut c = ChainSync::default();
        let mut anon = SetSync::interval([(6u8, 80u16)..=(6u8, 80u16)], None);
        anon.set_anonymous();
        let mut r = rules::l4proto_dport_anon(0);
        r.push(rules::accept());
        c.rules.push(r);
        c.anon_sets.push(anon);
        c
    };
    let filter = |priority: i32, with_drop: bool| {
        let mut c = ChainSync {
            base: Some(BaseChain {
                chain_type: chain::ChainType::Filter,
                hook: chain::InetHookNumber::Forward,
                priority,
                policy: chain::ACCEPT,
            }),
            ..Default::default()
        };
        if with_drop {
            c.rules.push(vec![rules::drop()]);
        }
        let mut r = rules::ip_set(Family::V4, Dir::Dst, "src", false);
        r.push(rules::accept());
        c.rules.push(r);
        c.rules
            .push(rules::ip_vmap(Family::V4, Dir::Dst, "dispatch"));
        c
    };
    let dispatch = |entries: Vec<(Ipv4Addr, &str)>| {
        SetSync::verdict_map(
            entries
                .into_iter()
                .map(|(ip, chain)| (ip, set::Verdict::Goto(chain.into()))),
            None,
        )
    };
    let blocked = || SetSync::interval([ip(192, 168, 1, 0)..=ip(192, 168, 1, 255)], None);

    // state 0: first apply
    let mut s0 = TableSync::default();
    s0.sets.insert("src".into(), src(&[1, 2]));
    s0.sets.insert("blocked".into(), blocked());
    s0.sets.insert(
        "dispatch".into(),
        dispatch(vec![(ip(10, 0, 0, 1), "pod_a")]),
    );
    s0.chains.insert("filter".into(), filter(0, false));
    s0.chains.insert("pod_a".into(), pod_accept());
    s0.chains.insert("pod_b".into(), pod_b());

    // state 1: a set element is added and another removed
    let mut s1 = s0.clone();
    s1.sets.insert("src".into(), src(&[2, 3]));

    // state 2: a brand-new chain, plus a verdict-map entry that gotos it
    let mut s2 = s1.clone();
    s2.chains.insert("pod_c".into(), pod_accept());
    s2.sets.insert(
        "dispatch".into(),
        dispatch(vec![(ip(10, 0, 0, 1), "pod_a"), (ip(10, 0, 0, 3), "pod_c")]),
    );

    // state 3: a rule change (the chain flushes and refills)
    let mut s3 = s2.clone();
    s3.chains.insert("filter".into(), filter(0, true));

    // state 4: a structural base-chain change (full recreate)
    let mut s4 = s3.clone();
    s4.chains.insert("filter".into(), filter(10, true));

    // state 5: drop a set and a chain (deletes land last)
    let mut s5 = s4.clone();
    s5.sets.remove("blocked");
    s5.chains.remove("pod_c");
    s5.sets.insert(
        "dispatch".into(),
        dispatch(vec![(ip(10, 0, 0, 1), "pod_a")]),
    );

    // state 1 is repeated: a no-op update emits nothing.
    let s1_noop = s1.clone();

    vec![s0, s1, s1_noop, s2, s3, s4, s5]
}

/// A [`test_harness::System`] applying one of the scenario's states, selected by
/// `!custom <id>`, through a [`TableState`] (incremental, with a full-recreate
/// fallback if the kernel diverged).
struct TestSync {
    states: Vec<TableSync>,
    current: usize,
    state: TableState,
}

impl test_harness::System for TestSync {
    fn new(table: String) -> Self {
        Self {
            states: scenario_states(),
            current: 0,
            state: TableState::new(table),
        }
    }

    fn custom(&mut self, id: usize) {
        self.current = id;
    }

    async fn apply(&mut self, _table: &str) {
        self.state
            .update(self.states[self.current].clone())
            .await
            .expect("apply");
    }
}

/// Golden test: applies each scenario state incrementally and compares the
/// kernel table against the checked-in expected body.
///
/// Requires `CAP_NET_ADMIN`; run with `sudo -E cargo test -- --ignored`.
#[ignore = "requires CAP_NET_ADMIN and a real kernel"]
#[tokio::test]
async fn golden() {
    test_harness::golden_dir::<TestSync>(
        "test_assets/golden-nftables/table_sync",
        "knls-test-table-sync-",
    )
    .await;
}

/// Prints, for each scenario state, the kernel body a full create produces.
/// Used to (re)generate `basic.yaml`.
///
/// Requires `CAP_NET_ADMIN`; run with `sudo -E cargo test -- --ignored --nocapture`.
#[ignore = "requires CAP_NET_ADMIN and a real kernel"]
#[tokio::test]
async fn print_dumps() {
    for (i, state) in scenario_states().iter().enumerate() {
        let table = format!("knls-test-table-sync-print-{i}");
        let body = test_harness::capture(&table, sync(&table, None, state)).await;
        println!("=== state {i} ===\n{body}\n");
    }
}

#[test]
fn new_verdict_map_and_chain_are_created_before_the_referencing_rule() {
    // prev: a base chain with no rules, so a new vmap and a new goto target are
    // introduced together with the rule that references them.
    let mut old = TableSync::default();
    old.chains.insert(
        "filter".into(),
        ChainSync {
            base: Some(BaseChain {
                chain_type: chain::ChainType::Filter,
                hook: chain::InetHookNumber::Forward,
                priority: 0,
                policy: chain::ACCEPT,
            }),
            ..Default::default()
        },
    );

    let mut new = TableSync::default();
    new.chains.insert(
        "filter".into(),
        ChainSync {
            base: Some(BaseChain {
                chain_type: chain::ChainType::Filter,
                hook: chain::InetHookNumber::Forward,
                priority: 0,
                policy: chain::ACCEPT,
            }),
            rules: vec![rules::ip_vmap(Family::V4, Dir::Dst, "vm")],
            anon_sets: Vec::new(),
        },
    );
    new.chains.insert(
        "pod".into(),
        ChainSync {
            base: None,
            rules: vec![vec![rules::accept()]],
            anon_sets: Vec::new(),
        },
    );
    new.sets.insert(
        "vm".into(),
        SetSync::verdict_map(
            [(Ipv4Addr::new(10, 0, 0, 1), set::Verdict::Goto("pod".into()))],
            None,
        ),
    );

    let prev = old.reference("t");
    let msgs = sync_all("t", Some(&prev), &new);
    let s = steps(&msgs);

    let vm_create = s
        .iter()
        .position(|x| *x == Step::NewSet("vm".into()))
        .expect("vmap created");
    let vm_fill = s
        .iter()
        .position(|x| *x == Step::Elem("vm".into(), false))
        .expect("vmap filled");
    let filter_rule = s
        .iter()
        .position(|x| *x == Step::NewRule("filter".into()))
        .expect("filter rule added");
    let pod_create = s
        .iter()
        .position(|x| *x == Step::NewChain("pod".into()))
        .expect("goto target created");

    assert!(
        vm_create < filter_rule,
        "vmap must exist before the rule that references it: {s:?}"
    );
    assert!(
        pod_create < vm_fill,
        "goto target must exist before the vmap is filled: {s:?}"
    );
}

#[test]
fn scenario_yaml_parses() {
    // catches a malformed scenario (e.g. bad `!nft` block indentation) without a
    // kernel
    let yaml = include_str!("../../../test_assets/golden-nftables/table_sync/basic.yaml");
    let ops: Vec<test_harness::Op> = serde_yaml::from_str(yaml).expect("bad scenario yaml");

    let nfts: Vec<&str> = ops
        .iter()
        .filter_map(|op| match op {
            test_harness::Op::Nft(script) => Some(script.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(
        nfts,
        vec!["delete table inet {table}\n"],
        "the out-of-band script must have its block indentation stripped"
    );
}

/// The `Lookup::Set` name of the first `NewRule` in `msgs`, if any.
fn rule_lookup(msgs: &[Message]) -> Option<String> {
    use netlink_packet_netfilter::nftables::{
        ExpressionAttribute, Expressions, ListAttribute, Lookup, RuleAttribute,
    };

    for msg in msgs {
        let NetlinkPayload::InnerMessage(NetfilterMessage {
            inner: NetfilterMessageInner::NfTables(NfTablesMessage::NewRule(m)),
            ..
        }) = &msg.payload
        else {
            continue;
        };
        for attr in &m.attributes {
            let RuleAttribute::Expressions(exprs) = attr else {
                continue;
            };
            for expr in exprs {
                let ListAttribute::Element(attrs) = expr else {
                    continue;
                };
                for attr in attrs {
                    let ExpressionAttribute::Data(Expressions::Lookup(lookups)) = attr else {
                        continue;
                    };
                    for lookup in lookups {
                        if let Lookup::Set(name) = lookup {
                            return Some(name.clone());
                        }
                    }
                }
            }
        }
    }
    None
}

#[test]
fn sync_generates_and_resolves_anonymous_set_names() {
    let mut anon = SetSync::interval([(6u8, 80u16)..=(6u8, 80u16)], None);
    anon.set_anonymous();
    let mut table = TableSync::default();
    table.chains.insert(
        "c".into(),
        ChainSync {
            base: None,
            rules: vec![rules::l4proto_dport_anon(0)],
            anon_sets: vec![anon],
        },
    );

    let msgs = sync_all("t", None, &table);
    let s = steps(&msgs);

    // the anonymous set is created with a sync-generated name, before the rule
    // that references it, and the rule names that same set.
    let create = s
        .iter()
        .position(|x| *x == Step::NewSet("__set1".into()))
        .expect("anonymous set created");
    let rule = s
        .iter()
        .position(|x| *x == Step::NewRule("c".into()))
        .expect("rule added");
    assert!(create < rule, "anonymous set before its rule: {s:?}");
    assert_eq!(rule_lookup(&msgs).as_deref(), Some("__set1"));
}

/// The kernel commits an anonymous set only together with the rule that binds
/// it, so a set, its elements and its rule are one group; rule order and the
/// rest of the chain are preserved.
#[test]
fn sync_keeps_each_anonymous_set_in_its_rule_group() {
    let anon = |port: u16| {
        let mut set = SetSync::interval([(6u8, port)..=(6u8, port)], None);
        set.set_anonymous();
        set
    };
    let mut table = TableSync::default();
    table.chains.insert(
        "c".into(),
        ChainSync {
            base: None,
            rules: vec![rules::l4proto_dport_anon(0), rules::l4proto_dport_anon(1)],
            anon_sets: vec![anon(80), anon(443)],
        },
    );

    let groups = sync("t", None, &table);
    let group = |name: &str| {
        let group = groups
            .iter()
            .find(|g| {
                g.as_slice()
                    .iter()
                    .any(|m| classify(m) == Step::NewSet(name.to_string()))
            })
            .unwrap_or_else(|| panic!("no group with {name}: {groups:?}"));
        steps(group.as_slice())
    };

    assert_eq!(
        group("__set1"),
        vec![
            Step::NewSet("__set1".into()),
            Step::Elem("__set1".into(), false),
            Step::NewRule("c".into()),
        ],
        "a set, its elements and its binding rule must share one group"
    );
    assert_eq!(
        group("__set2"),
        vec![
            Step::NewSet("__set2".into()),
            Step::Elem("__set2".into(), false),
            Step::NewRule("c".into()),
        ],
        "a set, its elements and its binding rule must share one group"
    );
}
