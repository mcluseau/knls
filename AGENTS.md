# AGENTS.md

Guidance for agents working in this repository.

## What knls is

A node-local Kubernetes service that watches the API server and programs
node-level networking: a kube-proxy replacement in `nftables`, authoritative
DNS, and pod connectivity over wireguard.

## Testing strategy

The interesting behavior is the **nftables tables** knls programs. We test them
by applying the tables a subsystem *actually emits over netlink* to a real
kernel and comparing the resulting `nft list` output against a checked-in
expected dump (a "golden"). This catches encoding bugs that a hand-written
assertion would miss.

There are two layers:

1. **Unit tests** (`cargo test`, no privileges). Pure logic: selector matching,
   message shapes, hashing, config parsing. Prefer these for anything that
   doesn't need the kernel.

2. **Golden tests** (need `CAP_NET_ADMIN`). A subsystem renders its table, the
   harness pushes the netlink messages to the kernel, then compares
   `nft list table inet <table>` against the golden.

Run the golden tests with:

```sh
sudo -E cargo test -- --ignored
```

They are `#[ignore]`d precisely because they need root and a real kernel. On a
machine with passwordless sudo, `sudo -n -E cargo test -- --ignored` works
non-interactively. CI/dev images can grant `CAP_NET_ADMIN` instead of full root.

### The golden harness

`src/nftables.rs` exposes `#[cfg(test)] pub mod test_harness`, shared by every
nftables subsystem:

- `System` trait — a subsystem under test implements `new(table)`, `ingest(event)`
  and `render() -> Vec<Message>` (`Message` is a netfilter netlink message).
- `golden(table, yaml)` — runs one scenario.
- `golden_dir(dir, table_prefix)` — runs every `*.yaml` in `dir`, each against a
  table named `{table_prefix}{file_stem}`.

A scenario is a YAML list of ops:

```yaml
- !ingest
  - stream: Namespace
    event: !init_done
  - stream: Pod
    event: !init_apply
      metadata: { name: a, namespace: default, labels: { app: a } }
      spec: { nodeName: n1 }
      status: { podIPs: [{ ip: 10.0.0.1 }] }
- !verify |
    map pods_ingress {
        type ipv4_addr : verdict
        elements = { 10.0.0.1 : goto ingress_pod_default_a }
    }
    ...
```

- `!ingest` feeds a list of `kube_watch::Event`s (see `src/kube_watch.rs`) into
  the `System`, simulating watch events.
- `!verify` applies the current rendering to the kernel and compares the table
  **body** — the harness strips the surrounding `table <name> { … }` wrapper, so
  the golden only holds the table's contents.

The comparison `normalize`s whitespace (line wrapping/indentation in `nft list`
doesn't matter), but is otherwise exact. A mismatch prints the full actual dump
to make updating the golden easy.

Golden files live under `test_assets/golden-ntables/<subsystem>/<name>.yaml`.
Scenarios use serde_yaml 0.9, which requires the `!tag` syntax for enums and
cannot deserialize nested enums — hence `kube_watch::Event` is adjacently
tagged over a `stream`/`event` pair.

Currently:

- `src/netpol/nftables.rs` runs `golden_dir("test_assets/golden-ntables/netpol", "knls-test-netpol-")`.
- `src/firewall.rs` has an older, equivalent in-file golden (`firewall/tests.yaml`)
  with the expected dump embedded per case; prefer the `test_harness` style for
  new tests.

New nftables subsystems should register a `test_harness::System` impl and a
`golden_dir` test, rather than hand-rolling apply/compare code.

### Keeping a golden honest

A golden is only meaningful if a human can read it and see that it's a correct
netpol/proxy rendering. When a test fails, **read the actual dump** the harness
prints; only update the golden once you understand *why* it changed. If the new
output looks wrong, the bug is in `render`, not the golden.

Do not assert on substrings (`dump.contains(...)`) for table behavior — write or
extend a golden scenario instead. Substring checks are for existence-only
smoke tests.

## nftables notes

- We program nftables over netlink directly (`netlink-packet-netfilter`); the
  helpers in `src/nftables/{chain,set,rules,table}.rs` build the messages.
- `nft list` prints a set **inline** (`meta l4proto . th dport { tcp . 80, … }`)
  iff the kernel set carries `NFT_SET_ANONYMOUS`; otherwise it prints `@name`.
  An anonymous set is bound to a single rule, so each generated rule that needs
  one gets its own (`Set::create_anonymous`). Named sets are created/filled
  independently and can be flushed and refilled.
- The kernel accepts interval encoding over netlink that nft's own grammar
  rejects (e.g. concatenated ranges, `udp . 0-65535`) — validate through the
  golden tests rather than assuming nft's CLI syntax is the limit.

## Building and checking

- `cargo build` — build.
- `cargo test` — unit tests.
- `cargo clippy --all-targets -- -D warnings` — lints (must pass).
- `cargo fmt` — formatting. Note: `cargo fmt` currently reformats
  `src/nftables/rules.rs` (unrelated pre-existing style); avoid committing that
  churn unless you mean to.
- `sudo -E cargo test -- --ignored` — golden/kernel tests.
