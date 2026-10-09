# Proxy on TableSync: pure-netlink kube-proxy

Status: draft.

## Problem

`src/proxy/nftables.rs` is the last nftables subsystem still built on the `nft`
CLI. It:

- renders an nft **script** (text) and pipes it to `nft -f -`;
- tracks changes in userspace with a hand-rolled `TableTracker` /
  `TableUpdater` (`change::Tracker`), storing **hashes of rendered text**
  (`ctr`, `map_element`, `set_element`);
- carries an `nft`-specific workaround (redefining maps inline) and depends on
  the `nft` binary being present.

`netpol` has already moved to `nftables::table_sync` (`daf5b5f`), which is
typed, netlink-native and shares the diff/sync machinery. `proxy` is the "big
one": it exercises almost every nftables feature (nat chains, `nat`/`dnat`/
`redirect`/`masquerade`, `fib`, `numgen`, `ct original`, `meta mark`, timeout and
dynamic sets, verdict maps, concatenated keys).

## Goals

- `proxy` renders a `TableSync` and applies it through
  `table_sync::TableState`, exactly like `netpol`.
- The kernel table produced is **identical to today's**, including incremental
  updates: a fresh full render, an incremental render, and the old script path
  must all leave the same `nft list` body.
- Delete `TableTracker`/`TableUpdater` and the `nft` CLI dependency from proxy.
- Keep the existing chain/set names, so the output is stable and comparable.

## Non-goals

- Changing proxy semantics or chain topology. This is a representation/transport
  migration, not a redesign.
- Conntrack cleanup (`src/proxy/conntrack.rs`), which is already netlink-native
  and independent.
- A kernel-table reader (`from_kernel`) to bootstrap `prev`; `TableState` keeps
  its own reference. (A follow-up, see `table-sync.md`.)
- Reworking the random-endpoint `numgen` scheme into something simpler. It is
  reproduced as-is first; simplifying is a possible later change.

## Current behavior contract

This is what the moved implementation (and its goldens) must reproduce. Default
`inet` table name: `kube-proxy` (configurable). Marks:
`MASQ_MARK = 1 << 14`.

Naming helpers (`keys::Object = {namespace, name}`):

| helper | value |
| --- | --- |
| `obj_chain(prefix, key)` | `{prefix}_{ns}_{name}` |
| `svc_chain(key)` | `svc_{ns}_{name}` |
| `svc_chain_ext(key, svc)` | `svc_chain` + (`_ext` iff `needs_ext_chain()`, i.e. has external IPs) |
| `affinity_set(key, ipv)` | `affinity{4\|6}_{ns}_{name}` |
| endpoint chain | `{svc_chain}_ep_{hex(ip)}` |

Objects and rules, in render order:

1. **Per-service dispatch map + chain**, for `internal_slices` (always) and
   (if `needs_ext_chain`) `external_slices`:
   - a **map** named `{svc_chain}` / `{svc_chain}_ext` with
     `typeof numgen random mod 1 : verdict`; elements `{ n : goto
     {chain}_ep_{hex} }`, one per endpoint IP, `n = 0,1,2…`;
   - a **chain** with the *same name* (see "Namespace" below), built by:
     - optional session-affinity pre-rules (see 3);
     - the endpoint dispatch: `meta nfproto ipv4 numgen random mod {n4} vmap
       @{svc_chain}`, and the same for `ipv6`, or `meta nfproto {ipv4,ipv6}
       reject` when that family has no endpoints;
     - (ext only) an `external_allow_list` pre-rule:
       `ip saddr != { <ips> } reject`.
   - an **endpoint chain** `{chain}_ep_{hex}` per endpoint IP, holding:
     - session-affinity `update @affinity_set { ip saddr . ip }`;
     - one dnat rule per service port and per node port:
       - `meta nfproto ipv4|ipv6 {tcp|udp|sctp} dport {port} [fib daddr type
         local] redirect to {target_port}` for ports on this node's IPs;
       - else `meta nfproto ipv4|ipv6 ... mark set mark or {MASQ_MARK} dnat to
         {ip}:{target_port}`.

2. **`service_ips`** map: `type ipv4_addr . inet_proto . inet_service : verdict`
   (v4-only, as today). Elements, for services with `cluster_ips`, per port:
   `{ cluster_ip . proto . port : goto {svc_chain} }` and
   `{ external_ip . proto . port : goto {svc_chain_ext} }`.

3. **Session affinity** (`ClientIP { timeout }`): per family `4`/`6`, a **set**
   `affinity{v}_{ns}_{name}` (type `ipv{4,6}_addr . ipv{4,6}_addr`, `timeout
   {N}s`), plus a pre-rule in each svc chain and endpoint chain:
   `ip saddr . {ip} @{affinity_set} goto {ep_chain}` (per endpoint).

4. **`service_nodeports`** map: `type inet_proto . inet_service : verdict`.
   Elements per service node port: `{ proto . port : goto {svc_chain_ext} }`.

5. **`dispatch`** chain (regular): `ip daddr . ip protocol . th dport vmap
   @service_ips` then `fib daddr type local ip protocol . th dport vmap
   @service_nodeports`.

6. **Base chains** (`type nat`):
   - `a_hook_dnat_prerouting`: hook prerouting, prio 0, `jump dispatch`;
   - `a_hook_dnat_output`: hook output, prio 0, `jump dispatch`;
   - `a_hook_dnat_postrouting`: hook postrouting, prio 0:
     - `ip saddr . ip daddr . ct original ip daddr @need_masquerade
       masquerade`;
     - `ip6 saddr . ip6 daddr . ct original ip6 daddr @need_masquerade6
       masquerade`;
     - per `my_node.pod_cidrs`: `ip|ip6 saddr {cidr} return` and
       `ip|ip6 daddr {cidr} return`;
     - `mark and {MASQ_MARK} == 0 return`;
     - `mark set mark xor {MASQ_MARK} masquerade fully-random`.

7. **`need_masquerade` / `need_masquerade6`** sets:
   `type ipv4_addr . ipv4_addr . ipv4_addr` /
   `type ipv6_addr . ipv6_addr . ipv6_addr`. Elements for each node-local
   endpoint not on this node: `{ ep_ip . ep_ip . svc_ip }`, for each matching
   `cluster_ip`/`external_ip`.

### Namespace note

The per-service **map and chain share the same name** (`svc_ns_name`), which
`nft` and the kernel accept (chains and sets are distinct namespaces; a set/map
is referenced with `@name`). This contradicts `table-sync.md`'s "Names are
unique within the table" and must be corrected there and covered by a golden.
`TableSync { chains, sets }` already keys chains and sets separately, so the
data model is fine; only the wording and the diff/deletion paths need to allow
a chain `X` and a set/map `X` to coexist.

## Foundation gaps

`table_sync` and the builders are missing pieces proxy needs. These land before
(or alongside) the proxy renderer, each pinned by a test.

### `chain.rs` / `table_sync.rs`

- `ChainSync::base` (`table_sync::BaseChain`) has no chain **type**; `nft` needs
  `type nat` vs `type filter`. `Chain::create_base` hardcodes `"filter"`
  (`chain.rs:130`). Add `type` to `BaseChain` (e.g. `filter: bool` or a
  `ChainType` enum) and thread it into `create_base`; a change is structural.
  This is required by all three proxy base chains (and harmless for netpol,
  which keeps `filter`).

### `rules.rs` (new builders)

- **concat payload + verdict-map lookup**: `ip daddr . ip protocol . th dport
  vmap @m` (v4 3-field concat) and `ip protocol . th dport` (`inet_proto .
  inet_service`), loading fields into the concatenated register and
  `lookup_vmap`. netpol's `ip_vmap`/`l4proto_dport_*` cover pieces; proxy needs
  the mixed payload/protocol concat and a v4 `ip daddr`+l4 vmap.
- **`fib daddr type local`** (`Expressions::Fib`) and the nodeport guard.
- **`numgen random mod N`** (`Expressions::Numgen`) used as a rule value feeding
  a vmap lookup (`... numgen random mod N vmap @m`).
- **`meta mark`**: load (`meta mark`), `and MASK == 0` (bitwise+cmp),
  `mark set mark xor MASK`, `mark set mark or MASK` (meta set / immediate).
- **conntrack**: `ct original ip daddr` / `ip6 daddr` (`Expressions::Ct`).
- **nat**: `masquerade` (`fully-random`), `dnat to ip:port`, `redirect to
  port` (`Expressions::Nat` with `NFT_NAT_*`).
- **dynset**: `update @set { ip saddr . ip }` (`Expressions::Dynset`).
- **inline set literal**: `ip saddr != { a, b } reject` — an anonymous interval
  set + inverted lookup + `reject`, plus the `meta nfproto` guard, as netpol's
  `except_clause` does. (Reuse `SetSync::interval` + `lookup_anon_inv`.)
- **`meta nfproto {ipv4,ipv6} reject`** for an endpoint-less family.

### `set.rs` / `table_sync.rs`

- **timeout sets**: `SetMeta` must express `NFTA_SET_TIMEOUT` (and the
  `dynamic`/`eval` flag that `update @set` implies). `SetMeta.attributes` can
  carry the timeout attribute, but `SetFlags` needs `Timeout`/`Eval` support and
  the diff must treat them as part of the structure.
- **`numgen`-keyed map**: the dispatch map's key type is `numgen random mod 1`,
  which is not a `set::Data` type. Rather than invent a `Data` impl, add a
  raw-meta escape hatch to `SetSync` so a caller can supply `SetMeta` (flags +
  `Vec<SetAttribute>`) directly, with raw key bytes for the elements. Confirm
  the kernel key encoding via a golden (the key is an integer-like value).
- **concat `(inet_proto, inet_service)` maps** already work via
  `Data for u8` + `Data for u16` (`MapElem<u8, u16>`).
- Verify the v4 `ipv4_addr . inet_proto . inet_service` verdict map renders as
  today (`service_ips`).

## Target design

Replace `update_table_to`/`TableTracker`/`TableUpdater` with:

```rust
/// Renders the whole proxy table for `state` as a target TableSync.
fn render(my_node: &Node, cfg: &proxy::State) -> TableSync;
```

- `watch` keeps its event loop, but holds a `TableState` and calls
  `table.update(render(my_node, &cfg)).await`, like `netpol::watch`.
- The builder is a plain struct accumulating `chains: BTreeMap<String,
  ChainSync>` and `sets: BTreeMap<String, SetSync>`; all iteration over
  `cfg`/slices uses the existing `BTree` collections, so the target is
  deterministic.
- Names are unchanged from today.
- The `nft`-map-redefinition workaround is dropped: it was an `nft`-CLI parser
  bug, and `sync` creates every set before the rules that reference it.

## Migration plan

### Phase 0 — golden tests against the current implementation (first PR)

Capture today's kernel output as the contract before changing anything. The
`nft list` body is the comparison level, so it is independent of whether the
messages come from a script or netlink.

- Add a scenario driver in `src/proxy/nftables/tests.rs`:
  - holds `crate::state::State` (proxy state via `state::proxy::from_state`), a
    `my_node`, a `Config`, and a persistent `TableTracker`;
  - `ingest` feeds `kube_watch::Event`s;
  - overrides `test_harness::System::apply` to render the current script (call
    `update_table_to` into a `Vec<u8>`), then `crate::nftables::apply_script`,
    then `TableTracker::update_done` on success (mirroring `update_table`).
- Scenarios under `test_assets/golden-nftables/proxy/`, seeded with `MyNode`,
  `Service` and `EndpointSlice` events. Cover at least:
  - `basic`: one ClusterIP, one local endpoint, v4;
  - `multi-endpoint`: several endpoints → `numgen` map with `N > 1`;
  - `nodeport`: node ports enabled;
  - `external`: external IPs + `external_allow_list` + differing external
    traffic policy → `_ext` chain/slices;
  - `affinity`: `ClientIP` with timeout (`dynamic,timeout` set, `update @set`);
  - `masquerade`: local pod IPs (not the node's own IPs), both families, plus
    `pod_cidrs` (`need_masquerade{,6}`, postrouting returns);
  - `churn`: incremental updates — add/remove endpoint, change ports, delete a
    service — `!verify` at each step;
  - `noop`: re-ingest with no change (must emit nothing);
  - `out-of-band`: `!nft delete table inet {table}` then apply → full recreate
    (only meaningful once `TableState`'s retry-on-failure path exists).
- Add a `print_goldens` `#[ignore]` test (like netpol's) that regenerates the
  expected bodies from the current code.
- Run with `sudo -E cargo test -- --ignored`; read every dump before checking it
  in.

This phase also *proves* the contract is reproducible and surfaces any surprise
(e.g. the `numgen` key encoding, the `dynamic` flag) while the old code still
works.

Landed: `basic`, `multi-endpoint`, `nodeport`, `external`, `affinity`, `churn`
and `noop` under `test_assets/golden-nftables/proxy/`, driven through the
script renderer by `proxy::nftables::tests::TestSystem`, plus `doc-*` scenarios
transcribed from `content/en/docs/concepts/services-networking/service.md`
(`doc-my-service`, `doc-multi-port`, `doc-nodeport`, `doc-loadbalancer`,
`doc-external-ips`, `doc-externalname`); these pin, among other things, that a
LoadBalancer's `status.loadBalancer.ingress` is *not* programmed and that
ExternalName is not proxied. The `masquerade` v6 and `out-of-band` scenarios are
follow-ups (the latter needs the `TableState` apply path).

### Phase 1 — foundation

Land the `BaseChain` type, new `rules.rs` builders, and the `set.rs`/`set_sync`
metadata support, each with a focused unit/golden test. Extend
`table-sync.md`'s namespace wording.

### Phase 2 — typed renderer

Implement `render() -> TableSync`, and a `TestSystem` that applies it through
`TableState`. Point the Phase 0 scenarios at it: **the same goldens must pass**,
now driving the netlink path. Keep the old script renderer behind the test until
this is green.

### Phase 3 — cutover and delete

Switch `watch()` to `TableState`; delete `TableTracker`, `TableUpdater`,
`CtrKind`, `DnatWriter`, the string-based `tests::test_table_tracker`, and the
`nft` process spawn. `conntrack.rs` is untouched.

## Testing

- Goldens through the real kernel, `#[ignore]`, `sudo -E cargo test --
  --ignored`, exactly as `netpol`; never substring asserts for table behavior.
- The Phase 0 goldens are reused verbatim in Phase 2: passing them after the
  representation change is the migration's acceptance test.
- Pure-logic unit tests for the renderer: an unchanged state renders an equal
  `TableSync` (so `sync` emits nothing), and the dispatch/family logic (no
  endpoints → `reject`; endpoint count → `numgen mod N`; ext vs internal).
- The `TableSync` itself is already covered by
  `src/nftables/table_sync/tests.rs`; proxy adds render/ingest coverage, not new
  diff machinery.

## Risks / notes

- **Same-name chain/map** (above) is the first thing a golden must confirm, and
  may force a small correction in `sync`'s structural/deletion logic.
- **Kernel-mutated set flags**: adding an `update @set` rule can leave the
  affinity set with `dynamic` in `nft list` even if only `timeout` was declared.
  `TableState.current` tracks the *rendered* target, so this does not thrash;
  the golden pins the actual flags so the renderer declares them up front.
- **`numgen` key bytes**: the dispatch map's raw key encoding is only known once
  dumped; the golden decides it, not a guess.
- **Message sequence differs** from the script path (no inline map
  redefinition, `sync`'s ordering); only the resulting table body is compared.
