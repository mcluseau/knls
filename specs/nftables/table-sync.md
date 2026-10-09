# Sync'able nftables table

Status: draft.

## Problem

Every nftables subsystem today rebuilds its table from scratch on each update:

- `netpol` (`src/netpol/nftables.rs`) emits `table::recreate()` then
  create+fills every set and every chain, every time.
- `firewall` (`src/firewall.rs`) does the same in three steps.
- `proxy` (`src/proxy/nftables.rs`) already tracks changes in userspace
  (`TableTracker` + `change::Tracker`) but renders an nft **script** and pipes
  it to the `nft` binary; it is the only subsystem that does incremental
  updates.

The full rebuild is correct but wasteful: a single pod change re-applies the
whole table, and large sets (country IPs) are re-sent wholesale. The proxy's
tracker proves incremental sync works but is stringly-typed (it hashes rendered
text), depends on the `nft` CLI, and is not shared.

We want a single, typed, netlink-native representation of a whole `inet` table
that can be **synced**: given the previous state and a freshly rendered target
state, emit the minimal set of netlink messages turning one into the other, and
handle the "no previous state" (first apply) case.

## Goals

- One struct describing an entire nftables table: chains + their rules +
  anonymous sets, plus named sets/maps with their contents and metadata.
- A `sync(table, prev, next)` that emits the diff — set element changes, chain
  flushes/refills, deletes — in an order the kernel accepts (sets before rules
  that reference them, chains before verdict maps that jump to them, etc).
- Contents stored as raw key/value bytes (`Vec<u8>`), so a set is diffable
  without knowing its nft type, and the kernel can dump itself into the same
  shape for a future "adopt existing table" path.
- Netlink-native (consistent with `src/nftables/`); no `nft` CLI, no script
  strings.

## Non-goals

- Reading the live kernel table to bootstrap `prev`. `sync` takes `prev` from
  the caller; the first sync is `sync(table, None, next)` (a full create). A
  `from_kernel` reader is a possible follow-up, not this spec.
- Changing the rule/expression builders (`rules.rs`). The table stores the
  netlink `Message`s those produce.
- Multi-table management; one `TableSync` and one `sync` call per `inet` table.

## Representation

`TableSync` is the target state of one table. Names are unique within the table.
The table's own name is **not** part of `TableSync`; it is passed to `sync` (and
to the manager), so the same structure can be rendered against whatever table
the caller targets.

```rust
/// A whole `inet` table's desired state (contents only; the table name is
/// supplied to `sync`).
struct TableSync {
    /// Regular and base chains, by name.
    chains: BTreeMap<String, ChainSync>,
    /// Named sets and maps, by name.
    sets: BTreeMap<String, SetSync>,
}
```

### Previous-state reference

`sync`'s `prev` is not a full `TableSync`: holding every chain's rules alive
between updates is a lot of baseline memory for what is only a comparison
input. Instead `prev` is a `TableSyncRef`, which keeps a per-chain
**fingerprint** and the sets in full (set keys and values are small enough
that hashing them buys nothing).

```rust
/// A compact previous state: enough to diff a fresh `TableSync` against.
struct TableSyncRef {
    /// Per-chain fingerprint.
    chains: BTreeMap<String, ChainRef>,
    /// Named sets/maps, kept in full (their contents are small).
    sets: BTreeMap<String, SetSync>,
}

struct ChainRef {
    /// The base-chain descriptor, kept literally (it is tiny and a change is
    /// structural, not a mere rule change).
    base: Option<BaseChain>,
    /// Fingerprint of the chain's rules and anonymous sets.
    hash: u128,
}
```

`TableSync::reference(&self, table: &str) -> TableSyncRef` builds it by
rendering each chain into a `Chain` and taking `Chain::hash()` (which already
folds in the table and chain names and the serialized rule messages), plus the
anonymous sets' element contents so that a change *only* in an anonymous set is
detected. `ChainRef.hash` is therefore the chain's full content fingerprint.

### Chains

```rust
struct ChainSync {
    /// `None` for a regular chain; `Some` for a base chain (the hook, type,
    /// priority and policy it is created with).
    base: Option<BaseChain>,
    /// The chain's rules, each the expressions of one `add rule`.
    rules: Vec<Rule>,
    /// Anonymous sets this chain's rules reference, bound to the rule index
    /// that uses them. Keyed by the anonymous set's generated name so a rule
    /// can name it.
    anon_sets: BTreeMap<String, SetSync>,
}

struct BaseChain {
    hook: InetHookNumber,
    priority: i32,
    policy: u32, // NF_ACCEPT / NF_DROP
}
```

`Rule` is `chain::Rule` (`Vec<ListAttribute<ExpressionAttribute>>`), the same
type `Chain::push` takes. Rules are compared **by their serialized netlink
message**, as `Chain` already hashes them; the raw expressions are not `Eq`.

Anonymous sets are created before, and filled with, the rule that references
them. They live next to the chain (not in `TableSync::sets`) because the kernel
binds an anonymous set to a single rule. Their names (`__set{n}` today) are
generated by the renderer and stored in the rule's lookup expressions; `sync`
does not interpret those names, it only orders the messages (see below).

### Sets and maps

A named set has metadata (its `NFTA_SET_*` attributes, minus table/name/id) and
content keyed by raw element bytes. The content differs by shape:

- a simple set is a set of keys → `BTreeSet<key>`;
- an interval set is a set of inclusive key ranges → keys are their endpoints;
- a map is a set of key → value;
- a verdict map is a set of key → verdict.

Because the key/value are raw bytes, the shape can be captured by one enum:

```rust
enum SetSync {
    /// A named set (`flags` may include `Interval`/`Concat`/…).
    Set(SetSpec),
    /// A named map: key → value.
    Map(MapSpec),
    /// A named verdict map: key → verdict.
    VerdictMap(VerdictMapSpec),
}
```

with metadata split from content:

```rust
/// Metadata common to every named set/map: the `NFTA_SET_*` attributes minus
/// table/name/id and the content.
struct SetMeta {
    /// `KeyType`/`KeyLen`, optional `DataType`/`DataLen`, the concat
    /// descriptor, and flags (`Interval`, `Map`, `Concat`, `Timeout`, …).
    attributes: Vec<SetAttribute>,
    /// Optional `NFTA_SET_USERDATA` comment.
    comment: Option<String>,
}

/// A set of keys.
struct SetSpec {
    meta: SetMeta,
    keys: BTreeSet<Vec<u8>>,
}

/// A set of inclusive intervals; each range is a pair of endpoint key blobs
/// (`start..=end`), both encoded exactly as the kernel stores them.
struct IntervalSetSpec {
    meta: SetMeta,
    ranges: BTreeSet<(Vec<u8>, Vec<u8>)>,
}

/// A map from key to value.
struct MapSpec {
    meta: SetMeta,
    entries: BTreeMap<Vec<u8>, Vec<u8>>,
}

/// A verdict map from key to verdict.
struct VerdictMapSpec {
    meta: SetMeta,
    entries: BTreeMap<Vec<u8>, Verdict>,
}
```

Ids (`NFTA_SET_ID`) are **not** part of the target state. They are only needed
within a single transaction, where a rule/element may reference a set that is
created in the same batch; `sync` assigns a fresh id to each emitted `create`.
Only **names** are compared between `prev` and `next`.

Element order is implicit: every content container is a `BTreeSet`/`BTreeMap`,
so two states with the same names and contents compare equal without any
ordering step, and the sync diff is a straight structural comparison.

Notes:

- `RangeInclusive<Vec<u8>>` is not `Ord`, hence the `(Vec<u8>, Vec<u8>)` pair
  with a lexicographic order. `BTreeSet` gives canonical, sorted content.
- `Verdict` is `set::Verdict`; it is `Ord`-able once derived, so a `BTreeMap`
  keyed by bytes can hold it. (Add the derives if missing.)
- Storing keys as bytes means the interval encoding quirks (scalar `start` +
  exclusive `end+1` vs concatenated inclusive `KEY_END`,
  `SET_ELEM_F_INTERVAL_OPEN` for open ranges; see `set.rs`) are *applied at
  render time* and the stored blob is always the **canonical kernel
  representation**. `sync` diffs those blobs directly, as `sync_raw_set` already
  does.
- A key or value that is a verdict is stored as `Verdict`, not bytes: it is not
  a plain data blob and the renderer needs the chain name / code. For maps with
  plain values, bytes suffice because the value type is opaque to the diff.

The `SetSpec`/`IntervalSetSpec`/`MapSpec`/`VerdictMapSpec` enum tag mirrors the
existing `Elem` implementations (`T`, `RangeInclusive<T>`, `MapElem<K, D>`,
`VerdictElem<K>`) so rendering reuses `Set::create`/`Set::fill`.

## Deriving the target state

A subsystem renders a fresh `TableSync` from its `State` on each update. The
existing builders map onto this directly:

- `netpol`: `Builder::into_messages` becomes `Builder::into_table() ->
  TableSync`; the `NamedSets` struct fills `TableSync::sets` and each anonymous
  set is attached to its chain.
- `firewall`: sets become `TableSync::sets`; the free-form chain scripts must be
  replaced by `rules.rs` builders (a prerequisite, since `TableSync` stores
  `Rule`s, not strings).
- `proxy`: `write_service_slices_elements` / `ctr` become typed builders. This
  is the big one; it is where the current text-based tracker is replaced.

The target state must be **deterministic in names and content**: an unchanged
state renders an equal `TableSync` (same names, same `BTree` contents) and
`sync` emits nothing. Ids need not be stable; `sync` assigns them per emission.

## Sync algorithm

```rust
sync(table: &str, prev: Option<&TableSyncRef>, next: &TableSync) -> Vec<Message>
```

where `table` is the `inet` table's name.

If `prev` is `None` (or the table may not exist), or the diff hits a
**structural** change that cannot be applied in place — a set's metadata
attributes, or a base chain's hook — emit a **full (re)create**. Otherwise
emit an **incremental sync**.

### Full (re)create

`table::recreate(table)`, then build the table in two passes so that no fill
ever references a container that does not exist yet:

1. **Create every top-level object empty.** `Set::create` / `Map` / vmap for
   each named set/map, and `Chain::create` / `create_base` for each chain, with
   no elements and no rules. Anonymous sets are the exception: the kernel binds
   one to a single rule, so they are created and filled in pass 2 alongside that
   rule.
2. **Fill everything.** Element messages for the named sets/maps, then
   `Chain::fill` per chain (a flush, a no-op on the just-created chain, then the
   rules), with each chain's anonymous sets created and filled immediately
   before the rules that reference them.

Because every chain already exists after pass 1, a verdict-map entry that
`goto`s a chain is safe, and because every set/map already exists, a rule that
looks one up is safe — no dependency analysis is needed. `TableSync` need only
to agree on names.

When `prev` is `Some` this recreate also serves the structural-change fallback:
the table is dropped and rebuilt exactly as on a first apply.

### Incremental sync

When `prev` is `Some` and the change is not structural, emit, in this order:

1. **Named sets/maps**: never recreate an existing set just because its content
   changed — some sets are huge (service dispatch, per-endpoint maps, country
   IPs), and re-filling them on every update is exactly what we are trying to
   stop.
   - in `next` but not `prev`: `Set::create(comment)` with a fresh id, then fill
     all elements.
   - in both:
     - unchanged (`next` entry `==` `prev` entry): nothing.
     - same metadata, content changed: emit an **element diff**, exactly as
       `sync_raw_set` does — deletes (in `prev`, not `next`) first, then adds
       (in `next`, not `prev`), batched by `MAX_ELEMS_BYTES`. The set is not
       touched otherwise. For interval sets the unit is a whole range (an
       endpoint pair is never split); for maps, a changed value is a
       delete-then-add of its key.
     - **metadata changed (structural): fall back to a full (re)create** (see
       above). A set's key/value type or length, `Interval`/`Map`/`Concat`
       flags, concat descriptor or timeout cannot be changed in place; the
       kernel requires a fresh set. A comment-only change is *not* structural:
       re-issuing `NewSet` (no `NLM_F_EXCL`) updates the userdata in place and
       keeps the elements.
   - a set/map in `prev` but not `next` is deleted in step 4.

2. **Chains**:
   - create missing chains (base chains with their hook). A chain in `prev`
     whose `ChainRef.base` differs from `next`'s is structural: fall back to a
     full (re)create.
   - **never diff rules.** For every chain whose fingerprint changed — its
     `ChainRef.hash` differs from the freshly computed hash of `next`'s chain
     (rules and anonymous sets) — emit `Chain::fill()`: a `flush` followed by
     the whole stored `add rule` list. Rules are compared via the hash, not
     per-rule.
   - unchanged chains (same `base`, same hash): nothing.
   - anonymous sets are created and filled immediately before the rule that
     references them, within that chain's fill. They are folded into the
     chain's fingerprint, so a change to one refills the chain.

3. **Verdict maps**: because a verdict map value may `goto`/`jump` a chain, the
   map must be filled after those chains exist. In the current netpol renderer
   this is step 3 of `into_messages`. In `sync`, changes to a verdict map must
   be emitted after chain creation. The element diff for a verdict map follows
   the same rule as any other set (delete removed keys, add new/changed ones),
   but is emitted in this last phase so any `goto` target already exists.
   Ordinary sets can be diffed any time after their own create.

4. **Delete removed chains and sets/maps**, now that nothing in the new state
   references them: every chain in `prev` but not `next`, then every set/map in
   `prev` but not `next`. Because verdict maps were already refilled in step 3
   (dropping their entries for the deleted chains), and rules that referenced
   removed sets live only in chains that were flushed in step 2, the deletion
   step can ignore references entirely.

Ordering constraints, collected:

- set/map create before any rule or element referencing it;
- chain create before a vmap element that `goto`s it;
- anonymous set create + fill before its rule, within one chain fill;
- chain and set/map deletes last, in step 4, after all creations/fills.

The kernel validates a whole `send_as_transactions` batch with a single commit,
so an ordering that is wrong (e.g. a rule referencing a not-yet-created set)
fails the entire transaction. `sync` must therefore be exact, which the golden
tests verify.

## Applying

`sync` returns `Vec<Message>`. The caller sends them with
`netfilter::NetlinkExt::send_as_transactions`, which already chunks them into
bounded atomic batches.

A thin manager holds the table name and the current state's reference,
analogous to the proxy's `TableTracker` but typed:

```rust
struct TableState {
    table: String,
    /// The reference to the state currently applied; `None` until a first
    /// successful apply.
    current: Option<TableSyncRef>,
}

impl TableState {
    /// Renders `next` from state, diffs against `current`, applies, and only
    /// on success updates `current` with `next.reference(&self.table)`.
    async fn update(&mut self, next: TableSync) -> Result<()>;
}
```

Because `current` is a `TableSyncRef` (per-chain hashes, sets in full),
holding it between updates is cheap: no chain's rules are retained.

`netpol` and `firewall` each own one `TableState` per table. When `sync` decides
the change is structural (a set's metadata, a base chain's hook), it emits a
full recreate instead of a diff; `TableState` treats that identically — the
whole table is rebuilt and `current` replaced.

An **incremental** apply can still fail even though the diff is correct: the
kernel state may have diverged from `current` — most likely a user or third
party edited the table behind our back (the same hazard the proxy works around
with its `table.clear()` fallback). So `TableState::update` treats a failed
incremental send as a signal to rebuild:

1. Emit `sync(&self.table, self.current.as_ref(), next)` and send it. On
   success, set `current = Some(next.reference(&self.table))`.
2. If that send fails, discard `current` and re-run `sync(&self.table, None,
   next)` (a full recreate), then send that. On success, set `current =
   Some(next.reference(&self.table))`.
3. If the full recreate also fails, leave `current = None` and return the error;
   the next update starts from a full recreate again.

This makes an out-of-band edit self-healing on the next update at the cost of
one wasted incremental attempt. A structural change already goes through the
full-recreate path directly, so it does not pay for the extra attempt.

## Testing

Same strategy as the rest of `src/nftables/`: golden dumps through the real
kernel (`#[ignore]`, `sudo -E cargo test -- --ignored`), never substring
asserts.

Add a `test_harness::System` impl for `TableState` (or a scenario driver) so a
scenario can:

- `!ingest` watch events → render `TableSync`, apply `sync(table, None, next)`;
- then more `!ingest` → render a new `TableSync`, apply
  `sync(table, Some(&prev), next)` where `prev` is the previous render's
  `TableSyncRef`, and `!verify` the resulting table body.

This exercises the **diff path**, not just the initial render: a scenario
applies the table, mutates state, and verifies the table after the incremental
update equals the table after a fresh full render of the same target.

New golden scenarios under `test_assets/golden-ntables/<subsystem>/` should
cover at least:

- first apply (full create);
- no-op update (equal `TableSync` emits zero messages);
- add/remove a set element, a map entry, a chain, a rule (the chain flushes and
  refills in full);
- change set metadata (e.g. a set's type/flags) or a base chain hook: a full
  table recreate, producing the same table as a first apply;
- a verdict map gaining an entry that `goto`s a brand-new chain (ordering);
- delete a set that a removed rule referenced, and a chain that a changed vmap
  no longer points at (both land in step 4, after the fills).

Pure-logic unit tests (no kernel) cover the diff itself: given a `TableSync` and
a `TableSyncRef` derived from another `TableSync`, assert the emitted message
sequence classifies as the expected element diff / chain fill / delete steps
(and, for a structural change, a full recreate), mirroring `set.rs`'s
`sync_deletes_then_adds`.

