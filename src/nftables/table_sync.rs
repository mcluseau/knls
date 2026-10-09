//! A whole `inet` table that can be **synced**: given the previous state and a
//! freshly rendered target state, [`sync`] emits the minimal set of netlink
//! messages turning one into the other.
//!
//! See `specs/nftables/table-sync.md`. The representation is netlink-native and
//! stores set/map contents as raw key/value bytes, so a set is diffable without
//! knowing its nft type, and the kernel can dump itself into the same shape.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::RangeInclusive;

use eyre::Result;
use netlink_packet_core::Emitable as _;
use netlink_packet_netfilter::nftables::{SetAttribute, SetFlags};
use xxhash_rust::xxh3::Xxh3;

use crate::netlink::netfilter::{self, NetlinkExt as _};

use super::{
    Message,
    chain::{Chain, InetHookNumber, Rule},
    set::{self, Data, Elem, MapElem, Verdict, VerdictElem},
    table,
};

/// The base-chain descriptor a chain is created with: the hook, type, priority
/// and policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BaseChain {
    /// The `inet` hook the chain is attached to.
    pub hook: InetHookNumber,
    /// The hook priority.
    pub priority: i32,
    /// The base-chain policy (`NF_ACCEPT` / `NF_DROP`).
    pub policy: u32,
}

/// A regular or base chain's desired content: its rules and the anonymous sets
/// its rules reference.
///
/// Rules are compared by their serialized netlink message (via a
/// [`Chain`] hash), never per-rule; the raw expressions are not `Eq`.
#[derive(Clone, Debug, Default)]
pub struct ChainSync {
    /// `None` for a regular chain, `Some` for a base chain.
    pub base: Option<BaseChain>,
    /// The chain's rules, each the expressions of one `add rule`.
    pub rules: Vec<Rule>,
    /// Anonymous sets this chain's rules reference, keyed by the anonymous
    /// set's generated name so a rule can name it.
    pub anon_sets: BTreeMap<String, SetSync>,
}

/// Metadata common to every named set/map: the `NFTA_SET_*` attributes minus
/// table/name/id and the content, plus the set-level flags and comment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetMeta {
    /// The set-level flags (`Interval`, `Map`, `Concat`, `Timeout`, …).
    pub flags: SetFlags,
    /// `KeyType`/`KeyLen`, optional `DataType`/`DataLen` and the concat
    /// descriptor, exactly as [`Elem::set_attributes`] returns them.
    pub attributes: Vec<SetAttribute>,
    /// Optional `NFTA_SET_USERDATA` comment.
    pub comment: Option<String>,
}

impl SetMeta {
    /// Builds the metadata implied by the [`Elem`] type `E`.
    pub fn from_elem<E: Elem>(comment: Option<String>) -> Self {
        Self {
            flags: E::SET_FLAGS,
            attributes: E::set_attributes(),
            comment,
        }
    }

    /// Whether two metadata describe the same on-kernel set, ignoring the
    /// comment (a comment-only change is not structural).
    pub fn same_structure(&self, other: &Self) -> bool {
        self.flags == other.flags && self.attributes == other.attributes
    }
}

/// A set of single keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetSpec {
    pub meta: SetMeta,
    pub keys: BTreeSet<Vec<u8>>,
}

/// A set of inclusive key ranges; each range is a pair of endpoint key blobs
/// (`start..=end`), both in the canonical key encoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntervalSetSpec {
    pub meta: SetMeta,
    pub ranges: BTreeSet<(Vec<u8>, Vec<u8>)>,
}

/// A map from key to plain value bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MapSpec {
    pub meta: SetMeta,
    pub entries: BTreeMap<Vec<u8>, Vec<u8>>,
}

/// A verdict map from key to verdict.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerdictMapSpec {
    pub meta: SetMeta,
    pub entries: BTreeMap<Vec<u8>, Verdict>,
}

/// A named set or map, by content shape.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SetSync {
    /// A set of keys.
    Set(SetSpec),
    /// A set of inclusive intervals.
    Interval(IntervalSetSpec),
    /// A map: key → value.
    Map(MapSpec),
    /// A verdict map: key → verdict.
    VerdictMap(VerdictMapSpec),
}

impl SetSync {
    /// The set's metadata.
    pub fn meta(&self) -> &SetMeta {
        match self {
            Self::Set(s) => &s.meta,
            Self::Interval(s) => &s.meta,
            Self::Map(s) => &s.meta,
            Self::VerdictMap(s) => &s.meta,
        }
    }

    /// Whether this is a verdict map.
    pub fn is_verdict_map(&self) -> bool {
        matches!(self, Self::VerdictMap(_))
    }

    /// The set's metadata, mutably.
    pub fn meta_mut(&mut self) -> &mut SetMeta {
        match self {
            Self::Set(s) => &mut s.meta,
            Self::Interval(s) => &mut s.meta,
            Self::Map(s) => &mut s.meta,
            Self::VerdictMap(s) => &mut s.meta,
        }
    }

    /// Marks the set anonymous (`NFT_SET_ANONYMOUS`).
    ///
    /// The kernel binds an anonymous set to a single rule and `nft` prints it
    /// inline (`{ tcp . 80, … }`) rather than as a named `@set`.
    pub fn set_anonymous(&mut self) {
        self.meta_mut().flags |= SetFlags::Anonymous;
    }

    /// A set of keys of `keys`.
    pub fn simple<K: Data>(keys: impl IntoIterator<Item = K>, comment: Option<String>) -> Self {
        Self::Set(SetSpec {
            meta: SetMeta::from_elem::<K>(comment),
            keys: keys.into_iter().map(|k| k.elem_data()).collect(),
        })
    }

    /// A set of inclusive intervals of `ranges`.
    pub fn interval<K: Data>(
        ranges: impl IntoIterator<Item = RangeInclusive<K>>,
        comment: Option<String>,
    ) -> Self {
        Self::Interval(IntervalSetSpec {
            meta: SetMeta::from_elem::<RangeInclusive<K>>(comment),
            ranges: ranges
                .into_iter()
                .map(|r| (r.start().elem_data(), r.end().elem_data()))
                .collect(),
        })
    }

    /// A map from `entries`.
    pub fn map<K: Data, V: Data>(
        entries: impl IntoIterator<Item = (K, V)>,
        comment: Option<String>,
    ) -> Self {
        Self::Map(MapSpec {
            meta: SetMeta::from_elem::<MapElem<K, V>>(comment),
            entries: entries
                .into_iter()
                .map(|(k, v)| (k.elem_data(), v.elem_data()))
                .collect(),
        })
    }

    /// A verdict map from `entries`.
    pub fn verdict_map<K: Data>(
        entries: impl IntoIterator<Item = (K, Verdict)>,
        comment: Option<String>,
    ) -> Self {
        Self::VerdictMap(VerdictMapSpec {
            meta: SetMeta::from_elem::<VerdictElem<K>>(comment),
            entries: entries
                .into_iter()
                .map(|(k, v)| (k.elem_data(), v))
                .collect(),
        })
    }
}

/// A whole `inet` table's desired state (contents only; the table name is
/// supplied to [`sync`]).
#[derive(Clone, Debug, Default)]
pub struct TableSync {
    /// Regular and base chains, by name.
    pub chains: BTreeMap<String, ChainSync>,
    /// Named sets and maps, by name.
    pub sets: BTreeMap<String, SetSync>,
}

/// A per-chain fingerprint: enough to diff a fresh chain's content against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainRef {
    /// The base-chain descriptor, kept literally (a change is structural).
    pub base: Option<BaseChain>,
    /// Fingerprint of the chain's rules and anonymous sets.
    pub hash: u128,
}

/// A compact previous state: enough to diff a fresh [`TableSync`] against.
///
/// Chains are kept as a fingerprint (holding every rule alive between updates
/// is a lot of baseline memory); named sets are kept in full.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TableSyncRef {
    pub chains: BTreeMap<String, ChainRef>,
    pub sets: BTreeMap<String, SetSync>,
}

impl TableSync {
    /// Builds the reference used as the `prev` input of the next [`sync`].
    pub fn reference(&self, table: &str) -> TableSyncRef {
        TableSyncRef {
            chains: self
                .chains
                .iter()
                .map(|(name, chain)| {
                    (
                        name.clone(),
                        ChainRef {
                            base: chain.base,
                            hash: chain_hash(table, name, chain),
                        },
                    )
                })
                .collect(),
            sets: self.sets.clone(),
        }
    }
}

/// The fingerprint of a chain: its rules (folded by [`Chain::hash`], which
/// seeds with the table/chain names and the serialized rule messages) plus its
/// anonymous sets' names and contents, so a change only in an anonymous set is
/// detected.
fn chain_hash(table: &str, name: &str, chain: &ChainSync) -> u128 {
    let mut c = Chain::new(table, name);
    c.extend(chain.rules.iter().cloned());

    let mut hasher = Xxh3::new();
    hasher.update(&c.hash().to_le_bytes());
    for (set_name, set) in &chain.anon_sets {
        hasher.update(set_name.as_bytes());
        hasher.update(&[0]);
        hash_set(set, &mut hasher);
    }
    hasher.digest128()
}

/// Feeds a set's metadata and content into `hasher`.
///
/// `SetAttribute`s are not `Hash`, so each is serialized with its netlink
/// encoding; its `kind` is already part of that encoding.
fn hash_set(set: &SetSync, hasher: &mut Xxh3) {
    let meta = set.meta();
    hasher.update(&meta.flags.bits().to_le_bytes());
    for attr in &meta.attributes {
        let mut buf = vec![0u8; attr.buffer_len()];
        attr.emit(&mut buf);
        hash_bytes(hasher, &buf);
    }
    if let Some(comment) = &meta.comment {
        hash_bytes(hasher, comment.as_bytes());
    }

    match set {
        SetSync::Set(s) => {
            for key in &s.keys {
                hash_bytes(hasher, key);
            }
        }
        SetSync::Interval(s) => {
            for (start, end) in &s.ranges {
                hash_bytes(hasher, start);
                hash_bytes(hasher, end);
            }
        }
        SetSync::Map(s) => {
            for (key, value) in &s.entries {
                hash_bytes(hasher, key);
                hash_bytes(hasher, value);
            }
        }
        SetSync::VerdictMap(s) => {
            for (key, verdict) in &s.entries {
                hash_bytes(hasher, key);
                hash_verdict(hasher, verdict);
            }
        }
    }
}

fn hash_bytes(hasher: &mut Xxh3, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn hash_verdict(hasher: &mut Xxh3, verdict: &Verdict) {
    use Verdict::*;
    match verdict {
        Accept => hasher.update(&[0]),
        Drop => hasher.update(&[1]),
        Return => hasher.update(&[2]),
        Continue => hasher.update(&[3]),
        Break => hasher.update(&[4]),
        Jump(chain) => {
            hasher.update(&[5]);
            hasher.update(chain.as_bytes());
        }
        Goto(chain) => {
            hasher.update(&[6]);
            hasher.update(chain.as_bytes());
        }
    }
    hasher.update(&[0]);
}

/// Diffs `next` against `prev`, emitting the minimal messages to turn the
/// kernel table into `next`.
///
/// `prev == None` (or a structural change that cannot be applied in place)
/// emits a full (re)create; otherwise an incremental sync.
pub fn sync(table: &str, prev: Option<&TableSyncRef>, next: &TableSync) -> Vec<Message> {
    let Some(prev) = prev else {
        return full_create(table, next);
    };
    if structural(prev, next) {
        return full_create(table, next);
    }
    incremental(table, prev, next)
}

/// Whether the change hits a structural attribute that cannot be applied in
/// place: a set's metadata or a base chain's hook. A comment-only change (or a
/// content-only change) is not structural.
fn structural(prev: &TableSyncRef, next: &TableSync) -> bool {
    for (name, set) in &next.sets {
        if let Some(old) = prev.sets.get(name)
            && !old.meta().same_structure(set.meta())
        {
            return true;
        }
    }
    for (name, chain) in &next.chains {
        if let Some(old) = prev.chains.get(name)
            && old.base != chain.base
        {
            return true;
        }
    }
    false
}

/// A [`set::Raw`] view of `set`, addressed by `name` and `id`.
fn raw_set<'a>(table: &'a str, name: &str, id: u32, set: &'a SetSync) -> set::Raw<'a> {
    let meta = set.meta();
    set::Raw {
        table,
        name: name.into(),
        id,
        flags: meta.flags,
        attributes: &meta.attributes,
        comment: meta.comment.as_deref(),
    }
}

/// The message creating the named set `set` with a fresh `id`.
fn create_set_msg(table: &str, name: &str, id: u32, set: &SetSync) -> Message {
    raw_set(table, name, id, set).create()
}

/// The message creating the chain `chain`.
fn create_chain_msg(table: &str, name: &str, chain: &ChainSync) -> Message {
    let c = Chain::new(table, name);
    match chain.base {
        Some(base) => c.create_base(base.hook, base.priority, base.policy),
        None => c.create(),
    }
}

/// Messages filling `set` with all of its elements.
fn fill_all(table: &str, name: &str, set: &SetSync) -> Vec<Message> {
    let raw = raw_set(table, name, 0, set);
    match set {
        SetSync::Set(s) => raw
            .fill(s.keys.iter().map(|key| set::Element::key(key.clone())))
            .collect(),
        SetSync::Interval(s) => {
            let concat = s.meta.flags.contains(SetFlags::Concat);
            raw.fill(
                s.ranges
                    .iter()
                    .map(|(start, end)| set::Element::interval(start.clone(), end.clone(), concat)),
            )
            .collect()
        }
        SetSync::Map(s) => raw
            .fill(
                s.entries
                    .iter()
                    .map(|(key, value)| set::Element::map_entry(key.clone(), value.clone())),
            )
            .collect(),
        SetSync::VerdictMap(s) => raw
            .fill(
                s.entries.iter().map(|(key, verdict)| {
                    set::Element::verdict_entry(key.clone(), verdict.clone())
                }),
            )
            .collect(),
    }
}

/// Messages emitting the element diff (deletes first, then adds) turning `old`
/// into `new`. A no-op when the content is equal.
fn set_diff(table: &str, name: &str, old: &SetSync, new: &SetSync) -> Vec<Message> {
    let raw = raw_set(table, name, 0, new);
    let mut out = Vec::new();
    match (old, new) {
        (SetSync::Set(a), SetSync::Set(b)) => {
            out.extend(
                raw.delete_elems(
                    a.keys
                        .difference(&b.keys)
                        .map(|key| set::Element::key(key.clone())),
                ),
            );
            out.extend(
                raw.fill(
                    b.keys
                        .difference(&a.keys)
                        .map(|key| set::Element::key(key.clone())),
                ),
            );
        }
        (SetSync::Interval(a), SetSync::Interval(b)) => {
            let concat = b.meta.flags.contains(SetFlags::Concat);
            out.extend(
                raw.delete_elems(a.ranges.difference(&b.ranges).map(|(start, end)| {
                    set::Element::interval(start.clone(), end.clone(), concat)
                })),
            );
            out.extend(
                raw.fill(b.ranges.difference(&a.ranges).map(|(start, end)| {
                    set::Element::interval(start.clone(), end.clone(), concat)
                })),
            );
        }
        (SetSync::Map(a), SetSync::Map(b)) => {
            out.extend(
                raw.delete_elems(
                    a.entries
                        .iter()
                        .filter(|(key, value)| b.entries.get(*key) != Some(*value))
                        .map(|(key, _)| set::Element::key(key.clone())),
                ),
            );
            out.extend(
                raw.fill(
                    b.entries
                        .iter()
                        .filter(|(key, value)| a.entries.get(*key) != Some(*value))
                        .map(|(key, value)| set::Element::map_entry(key.clone(), value.clone())),
                ),
            );
        }
        (SetSync::VerdictMap(a), SetSync::VerdictMap(b)) => {
            out.extend(
                raw.delete_elems(
                    a.entries
                        .iter()
                        .filter(|(key, value)| b.entries.get(*key) != Some(*value))
                        .map(|(key, _)| set::Element::key(key.clone())),
                ),
            );
            out.extend(
                raw.fill(
                    b.entries
                        .iter()
                        .filter(|(key, value)| a.entries.get(*key) != Some(*value))
                        .map(|(key, value)| {
                            set::Element::verdict_entry(key.clone(), value.clone())
                        }),
                ),
            );
        }
        // a variant change is structural, handled by the full recreate
        _ => {}
    }
    out
}

/// Messages replacing the chain's rules and anonymous sets, leaving its (empty)
/// existence untouched.
fn fill_chain(table: &str, name: &str, chain: &ChainSync, id: &mut u32) -> Vec<Message> {
    let mut c = Chain::new(table, name);
    c.extend(chain.rules.iter().cloned());

    let mut out = Vec::new();
    // flush first: it drops the old rules, and with them the old anonymous sets
    // they were bound to, so the fresh anonymous sets below are unbound names.
    out.push(c.flush());
    for (set_name, set) in &chain.anon_sets {
        *id += 1;
        out.push(create_set_msg(table, set_name, *id, set));
        out.extend(fill_all(table, set_name, set));
    }
    out.extend(c.rules().iter().cloned());
    out
}

/// Emits a full (re)create: drop the table and build it in two passes so no
/// fill ever references a container that does not exist yet.
fn full_create(table: &str, next: &TableSync) -> Vec<Message> {
    let mut out: Vec<Message> = table::recreate(table).to_vec();
    let mut id = 0u32;

    // pass 1: create every named set/map and every chain, empty.
    for (name, set) in &next.sets {
        id += 1;
        out.push(create_set_msg(table, name, id, set));
    }
    for (name, chain) in &next.chains {
        out.push(create_chain_msg(table, name, chain));
    }

    // pass 2: fill the named sets/maps, then the chains. Every chain already
    // exists, so a verdict-map entry that `goto`s one is safe.
    for (name, set) in &next.sets {
        out.extend(fill_all(table, name, set));
    }
    for (name, chain) in &next.chains {
        out.extend(fill_chain(table, name, chain, &mut id));
    }

    out
}

/// Emits the incremental diff. `prev` and `next` are known not to differ
/// structurally.
fn incremental(table: &str, prev: &TableSyncRef, next: &TableSync) -> Vec<Message> {
    let mut out = Vec::new();
    let mut id = 0u32;

    // 1. named sets/maps. A new verdict map is created empty here so a rule
    //    added in step 2 can reference it; its elements (which may `goto`
    //    chains) are filled in step 3.
    for (name, set) in &next.sets {
        if set.is_verdict_map() {
            if !prev.sets.contains_key(name) {
                id += 1;
                out.push(create_set_msg(table, name, id, set));
            }
            continue;
        }
        match prev.sets.get(name) {
            None => {
                id += 1;
                out.push(create_set_msg(table, name, id, set));
                out.extend(fill_all(table, name, set));
            }
            Some(old) => {
                if old == set {
                    continue;
                }
                if old.meta().comment != set.meta().comment {
                    // re-issuing NewSet updates the userdata in place
                    id += 1;
                    out.push(create_set_msg(table, name, id, set));
                }
                out.extend(set_diff(table, name, old, set));
            }
        }
    }

    // 2. chains: create the missing ones, then refill every changed one.
    for (name, chain) in &next.chains {
        if prev.chains.contains_key(name) {
            continue;
        }
        out.push(create_chain_msg(table, name, chain));
    }
    for (name, chain) in &next.chains {
        let changed = match prev.chains.get(name) {
            None => true,
            Some(old) => old.hash != chain_hash(table, name, chain),
        };
        if changed {
            out.extend(fill_chain(table, name, chain, &mut id));
        }
    }

    // 3. verdict maps: their elements may `goto` chains, which now exist.
    for (name, set) in &next.sets {
        if !set.is_verdict_map() {
            continue;
        }
        match prev.sets.get(name) {
            // created empty in step 1
            None => out.extend(fill_all(table, name, set)),
            Some(old) => {
                if old == set {
                    continue;
                }
                if old.meta().comment != set.meta().comment {
                    id += 1;
                    out.push(create_set_msg(table, name, id, set));
                }
                out.extend(set_diff(table, name, old, set));
            }
        }
    }

    // 4. delete what `next` no longer references: chains then sets/maps.
    for name in prev.chains.keys() {
        if !next.chains.contains_key(name) {
            out.push(Chain::new(table, name).delete());
        }
    }
    for name in prev.sets.keys() {
        if !next.sets.contains_key(name) {
            out.push(set::delete(table, name));
        }
    }

    out
}

/// Holds the table name and the reference to the currently applied state, and
/// applies fresh [`TableSync`] targets incrementally.
pub struct TableState {
    table: String,
    /// The state currently applied; `None` until a successful apply.
    current: Option<TableSyncRef>,
}

impl TableState {
    /// A manager for the `inet` table `table`, with no applied state yet.
    pub fn new(table: impl Into<String>) -> Self {
        Self {
            table: table.into(),
            current: None,
        }
    }

    /// The table's name.
    pub fn table(&self) -> &str {
        &self.table
    }

    /// Diffs `next` against the applied state and applies it.
    ///
    /// An incremental apply that fails (the kernel state diverged, e.g. an
    /// out-of-band edit) is retried as a full recreate. On success `current` is
    /// updated; on failure it is left unset so the next update recreates.
    pub async fn update(&mut self, next: TableSync) -> Result<()> {
        let nl = netfilter::new_link()?;

        let messages = sync(&self.table, self.current.as_ref(), &next);
        if nl.send_as_transactions(messages.into_iter()).await.is_ok() {
            self.current = Some(next.reference(&self.table));
            return Ok(());
        }

        self.current = None;
        let messages = sync(&self.table, None, &next);
        match nl.send_as_transactions(messages.into_iter()).await {
            Ok(()) => {
                self.current = Some(next.reference(&self.table));
                Ok(())
            }
            Err(e) => {
                self.current = None;
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests;
