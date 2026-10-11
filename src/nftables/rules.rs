//! Builders for the `Rule` expressions [`Chain`](super::chain::Chain) stores.
//!
//! These mirror the netlink encoding nft produces, verified against the kernel:
//! loading a header field into a register, comparing it, looking a value up in a
//! set/map, and applying a verdict (including `reject`).

use netlink_packet_core::DefaultNla;
use netlink_packet_netfilter::nftables::{
    Bitwise, Cmp, DataAttribute, ExpressionAttribute, Expressions, Immediate, ListAttribute,
    Lookup, Meta, MetaKey, Operator, Payload, Register, Verdict as NlVerdict, VerdictAttribute,
};
use std::net::IpAddr;

/// A single rule expression (see [`Rule`](super::chain::Rule)).
pub type Expr = ListAttribute<ExpressionAttribute>;

/// `NFTA_PAYLOAD_NETWORK_HEADER`: payload offset from the network header.
pub const NETWORK_HEADER: u32 = 1;
/// `NFTA_PAYLOAD_TRANSPORT_HEADER`: payload offset from the transport header.
pub const TRANSPORT_HEADER: u32 = 2;

/// A verdict expression: `accept`, `drop`, `return`, `jump <chain>`, …
pub fn verdict(verdict: Verdict) -> Expr {
    Expressions::Immediate(vec![
        Immediate::DestinationRegister(Register::Verdict),
        Immediate::Data(DataAttribute::Verdict(verdict.attrs())),
    ])
    .into()
}

/// The verdicts a rule can apply, with the netlink encoding nft uses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    Accept,
    Drop,
    Return,
    /// Jump to `chain` (pushing the current chain on the jump stack).
    Jump(String),
    /// Go to `chain` without pushing the current chain on the jump stack.
    Goto(String),
}

impl Verdict {
    fn attrs(&self) -> Vec<VerdictAttribute> {
        use VerdictAttribute::*;
        match self {
            Self::Accept => vec![Code(NlVerdict::Other(1 /* NF_ACCEPT */))],
            Self::Drop => vec![Code(NlVerdict::Other(0 /* NF_DROP */))],
            Self::Return => vec![Code(NlVerdict::Return)],
            Self::Jump(chain) => vec![Code(NlVerdict::Jump), Chain(chain.clone())],
            Self::Goto(chain) => vec![Code(NlVerdict::Goto), Chain(chain.clone())],
        }
    }
}

/// The reject type (`NFTA_REJECT_TYPE`), an `nft_reject_types`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum RejectType {
    /// Reject with ICMP unreachable.
    IcmpUnreach = 0, // NFT_REJECT_ICMP_UNREACH
    /// Reject with a TCP reset.
    TcpRst = 1, // NFT_REJECT_TCP_RST
    /// Abstracted ICMP unreachable, usable from an `inet` table.
    IcmpxUnreach = 2, // NFT_REJECT_ICMPX_UNREACH
}

/// The reject code (`NFTA_REJECT_ICMP_CODE`), an `nft_reject_inet_code`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum RejectIcmpCode {
    NoRoute = 0,
    #[default]
    PortUnreachable = 1,
    HostUnreachable = 2,
    AdminProhibited = 3,
}

/// A `reject` statement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reject {
    /// The family-agnostic ICMP reject netpol uses.
    Icmp(RejectIcmpCode),
}

impl Default for Reject {
    /// `reject`, i.e. `icmpx` with `port-unreachable`.
    fn default() -> Self {
        Self::Icmp(RejectIcmpCode::default())
    }
}

impl From<Reject> for Expr {
    fn from(reject: Reject) -> Self {
        use netlink_packet_core::DefaultNla;

        // NFTA_REJECT_TYPE, then NFTA_REJECT_ICMP_CODE.
        const NFTA_REJECT_TYPE: u16 = 1;
        const NFTA_REJECT_ICMP_CODE: u16 = 2;

        let (ty, code) = match reject {
            Reject::Icmp(code) => (RejectType::IcmpxUnreach, code as u8),
        };

        let attrs = vec![
            DefaultNla::new(NFTA_REJECT_TYPE, (ty as u32).to_be_bytes().to_vec()),
            DefaultNla::new(NFTA_REJECT_ICMP_CODE, vec![code]),
        ];

        Expressions::Other {
            expression_type: "reject".into(),
            attributes: attrs,
        }
        .into()
    }
}

/// `reject`, the default reject statement (`Reject::default()`).
pub fn reject() -> Expr {
    Reject::default().into()
}

/// `accept`.
pub fn accept() -> Expr {
    verdict(Verdict::Accept)
}

/// `drop`.
pub fn drop() -> Expr {
    verdict(Verdict::Drop)
}

/// `jump <chain>`.
pub fn jump(chain: impl Into<String>) -> Expr {
    verdict(Verdict::Jump(chain.into()))
}

/// `goto <chain>`.
pub fn goto(chain: impl Into<String>) -> Expr {
    verdict(Verdict::Goto(chain.into()))
}

/// Loads the `meta` key into `reg`.
pub fn meta(key: MetaKey, reg: Register) -> Expr {
    Expressions::Meta(vec![Meta::Key(key), Meta::DestinationRegister(reg)]).into()
}

/// Loads `len` bytes at `offset` (from `base`) of the packet into `reg`.
pub fn payload(reg: Register, base: u32, offset: u32, len: u32) -> Expr {
    Expressions::Payload(vec![
        Payload::DestinationRegister(reg),
        Payload::Base(base),
        Payload::Offset(offset),
        Payload::Len(len),
    ])
    .into()
}

/// `reg <op> value`, with `value` the raw (already big-endian) bytes.
pub fn cmp(reg: Register, op: Operator, value: impl Into<Vec<u8>>) -> Expr {
    Expressions::Cmp(vec![
        Cmp::SourceRegister(reg),
        Cmp::Op(op),
        Cmp::Data(DataAttribute::Value(value.into())),
    ])
    .into()
}

/// `reg == value`, with `value` the raw (already big-endian) bytes.
pub fn eq(reg: Register, value: impl Into<Vec<u8>>) -> Expr {
    cmp(reg, Operator::Equal, value)
}

/// `reg in @set`, without a destination register (plain membership).
pub fn lookup_set(reg: Register, set: impl Into<String>) -> Expr {
    Expressions::Lookup(vec![Lookup::SourceRegister(reg), Lookup::Set(set.into())]).into()
}

/// `reg != @set`, i.e. an inverted membership test.
pub fn lookup_set_inv(reg: Register, set: impl Into<String>) -> Expr {
    Expressions::Lookup(vec![
        Lookup::SourceRegister(reg),
        Lookup::Set(set.into()),
        Lookup::Flags(1), // NFT_LOOKUP_F_INV
    ])
    .into()
}

/// `reg in anon#index`: a lookup in an *anonymous* set, referenced by its
/// position in the chain's anonymous sets.
///
/// The reference is emitted as `NFTA_LOOKUP_SET_ID`; [`sync`] replaces it with
/// the anonymous set's generated name before the rule reaches the kernel.
///
/// [`sync`]: super::table_sync::sync
pub fn lookup_anon(reg: Register, index: u32) -> Expr {
    Expressions::Lookup(vec![Lookup::SourceRegister(reg), Lookup::SetId(index)]).into()
}

/// `reg != anon#index`, i.e. an inverted anonymous-set lookup.
pub fn lookup_anon_inv(reg: Register, index: u32) -> Expr {
    Expressions::Lookup(vec![
        Lookup::SourceRegister(reg),
        Lookup::SetId(index),
        Lookup::Flags(1), // NFT_LOOKUP_F_INV
    ])
    .into()
}

/// `reg in @set`, storing the looked-up value into `dreg` (a map).
pub fn lookup_map(reg: Register, dreg: Register, map: impl Into<String>) -> Expr {
    Expressions::Lookup(vec![
        Lookup::SourceRegister(reg),
        Lookup::Set(map.into()),
        Lookup::DestinationRegister(dreg),
    ])
    .into()
}

/// `reg in @set`, storing the verdict in `Verdict` (a `vmap`).
pub fn lookup_vmap(reg: Register, map: impl Into<String>) -> Expr {
    lookup_map(reg, Register::Verdict, map)
}

/// Masks `reg` with `mask` (and xors with `xor`), storing back in `reg`.
pub fn bitwise(reg: Register, len: u32, mask: Vec<u8>, xor: Vec<u8>) -> Expr {
    Expressions::Bitwise(vec![
        Bitwise::SourceRegister(reg),
        Bitwise::DestinationRegister(reg),
        Bitwise::Length(len),
        Bitwise::Mask(DataAttribute::Value(mask)),
        Bitwise::Xor(DataAttribute::Value(xor)),
    ])
    .into()
}

/// `meta nfproto` loaded into `reg`.
///
/// nft pairs this with a [`cmp`] against `NFPROTO_IPV4` (`2`) / `NFPROTO_IPV6`
/// (`10`) to guard `ip`/`ip6` matches in an `inet` table.
pub fn meta_nfproto(reg: Register) -> Expr {
    meta(MetaKey::Nfproto, reg)
}

/// The address family of an `ip`/`ip6` match.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    V4,
    V6,
}

impl Family {
    /// The `NFPROTO_*` value used in the `meta nfproto` guard.
    ///
    /// nft emits this as a 1-byte comparison (see its own payload dumps), which
    /// renders cleanly as `ip …`/`ip6 …`; a wider value is accepted by the kernel
    /// but renders as a spurious concatenation.
    fn nfproto(self) -> Vec<u8> {
        vec![match self {
            Self::V4 => 2,  // NFPROTO_IPV4
            Self::V6 => 10, // NFPROTO_IPV6
        }]
    }

    /// The `NFPROTO_*` value as a `u32`, for netlink attributes that carry it
    /// as a big-endian word (e.g. the `nat` expression's family).
    fn nfproto_u32(self) -> u32 {
        match self {
            Self::V4 => 2,
            Self::V6 => 10,
        }
    }

    /// The address length in bytes.
    fn len(self) -> u32 {
        match self {
            Self::V4 => 4,
            Self::V6 => 16,
        }
    }

    /// The offset of the source/destination address in the network header.
    fn offset(self, dir: Dir) -> u32 {
        match (self, dir) {
            (Self::V4, Dir::Src) => 12,
            (Self::V4, Dir::Dst) => 16,
            (Self::V6, Dir::Src) => 8,
            (Self::V6, Dir::Dst) => 24,
        }
    }
}

/// Whether a rule matches the source or destination address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dir {
    Src,
    Dst,
}

/// `ip saddr @set` / `ip6 daddr @set` (with the `meta nfproto` guard nft emits
/// in an `inet` table). `invert` produces `!= @set`.
pub fn ip_set(family: Family, dir: Dir, set: &str, invert: bool) -> Vec<Expr> {
    let mut exprs = vec![
        meta_nfproto(Register::Reg1),
        eq(Register::Reg1, family.nfproto()),
        payload(
            Register::Reg1,
            NETWORK_HEADER,
            family.offset(dir),
            family.len(),
        ),
    ];
    exprs.push(if invert {
        lookup_set_inv(Register::Reg1, set)
    } else {
        lookup_set(Register::Reg1, set)
    });
    exprs
}

/// `ip saddr @anon#index` / `ip6 daddr @anon#index`, cf. [`ip_set`] with an
/// anonymous set reference. `invert` produces `!=`.
pub fn ip_set_anon(family: Family, dir: Dir, index: u32, invert: bool) -> Vec<Expr> {
    let mut exprs = vec![
        meta_nfproto(Register::Reg1),
        eq(Register::Reg1, family.nfproto()),
        payload(
            Register::Reg1,
            NETWORK_HEADER,
            family.offset(dir),
            family.len(),
        ),
    ];
    exprs.push(if invert {
        lookup_anon_inv(Register::Reg1, index)
    } else {
        lookup_anon(Register::Reg1, index)
    });
    exprs
}

/// `ip saddr 1.2.3.0/24` / `ip6 daddr 2001:db8::/32` (with the `meta nfproto`
/// guard nft emits in an `inet` table). `invert` produces `!=`.
///
/// `network` is the full-length network address bytes (host part zero), `prefix`
/// the number of leading bits. A byte-aligned prefix loads only the significant
/// bytes; otherwise the whole field is loaded and masked, as nft does.
pub fn ip_prefix(
    family: Family,
    dir: Dir,
    prefix: u8,
    network: impl Into<Vec<u8>>,
    invert: bool,
) -> Vec<Expr> {
    let network = network.into();
    let op = if invert {
        Operator::NotEqual
    } else {
        Operator::Equal
    };

    let mut exprs = vec![
        meta_nfproto(Register::Reg1),
        eq(Register::Reg1, family.nfproto()),
    ];

    let bytes = prefix as usize / 8;
    if prefix > 0 && prefix.is_multiple_of(8) {
        // byte-aligned: load and compare only the significant bytes
        exprs.push(payload(
            Register::Reg1,
            NETWORK_HEADER,
            family.offset(dir),
            bytes as u32,
        ));
        exprs.push(cmp(Register::Reg1, op, network[..bytes].to_vec()));
    } else {
        // otherwise load the whole field, mask it, and compare
        let len = family.len() as usize;
        exprs.push(payload(
            Register::Reg1,
            NETWORK_HEADER,
            family.offset(dir),
            family.len(),
        ));
        exprs.push(bitwise(
            Register::Reg1,
            family.len(),
            prefix_mask(len, prefix),
            vec![0; len],
        ));
        exprs.push(cmp(Register::Reg1, op, network));
    }

    exprs
}

/// The big-endian mask with the first `prefix` bits set.
fn prefix_mask(len: usize, prefix: u8) -> Vec<u8> {
    let mut mask = vec![0u8; len];
    for bit in 0..prefix as usize {
        mask[bit / 8] |= 0x80 >> (bit % 8);
    }
    mask
}

/// `ip daddr vmap @map` / `ip6 saddr vmap @map` (verdict map lookup).
pub fn ip_vmap(family: Family, dir: Dir, map: &str) -> Vec<Expr> {
    vec![
        meta_nfproto(Register::Reg1),
        eq(Register::Reg1, family.nfproto()),
        payload(
            Register::Reg1,
            NETWORK_HEADER,
            family.offset(dir),
            family.len(),
        ),
        lookup_vmap(Register::Reg1, map),
    ]
}

/// `meta l4proto . th dport @set`, a lookup in an
/// `inet_proto . inet_service` concat set.
///
/// `meta l4proto` (1 byte) loads at [`Register::Reg1`] and `th dport` (2 bytes)
/// at the next 4-byte slot, [`Register::Reg32_01`]; the lookup sources the
/// concatenation from [`Register::Reg1`].
pub fn l4proto_dport_set(set: &str) -> Vec<Expr> {
    vec![
        meta(MetaKey::L4Proto, Register::Reg1),
        payload(Register::Reg32_01, TRANSPORT_HEADER, 2, 2),
        lookup_set(Register::Reg1, set),
    ]
}

/// `meta l4proto . th dport @anon#index`, cf. [`l4proto_dport_set`] with an
/// anonymous set reference.
pub fn l4proto_dport_anon(index: u32) -> Vec<Expr> {
    vec![
        meta(MetaKey::L4Proto, Register::Reg1),
        payload(Register::Reg32_01, TRANSPORT_HEADER, 2, 2),
        lookup_anon(Register::Reg1, index),
    ]
}

/// `ip|ip6 daddr . meta l4proto . th dport @anon#index`, a lookup in an
/// `ipv4_addr|ipv6_addr . inet_proto . inet_service` concat set.
///
/// Unlike [`l4proto_dport_anon`], the port is bound to a destination address, so
/// a named port resolves per destination pod instead of to the union of every
/// pod's container ports.
pub fn addr_l4proto_dport_anon(family: Family, index: u32) -> Vec<Expr> {
    let (daddr_off, daddr_len) = match family {
        Family::V4 => (16, 4),
        Family::V6 => (24, 16),
    };
    let mut c = Concat::default();
    let daddr = c.add(daddr_len);
    let proto = c.add(1);
    let dport = c.add(2);

    vec![
        meta_nfproto(Register::Reg1),
        eq(Register::Reg1, family.nfproto()),
        payload(daddr, NETWORK_HEADER, daddr_off, daddr_len),
        meta(MetaKey::L4Proto, proto),
        payload(dport, TRANSPORT_HEADER, 2, 2),
        lookup_anon(Register::Reg1, index),
    ]
}

/// `meta l4proto == <proto>`, a protocol-only match (no port constraint).
///
/// A 1-byte compare, as nft emits it.
pub fn l4proto_eq(proto: u8) -> Vec<Expr> {
    vec![
        meta(MetaKey::L4Proto, Register::Reg1),
        eq(Register::Reg1, vec![proto]),
    ]
}

// ---------------------------------------------------------------------------
// Builders for the proxy (kube-proxy replacement): expressions the crate does
// not model, emitted as `Expressions::Other` with the exact attributes nft
// produces (verified against a kernel dump).
// ---------------------------------------------------------------------------

/// A raw netlink attribute with `kind` and an already-encoded `value`.
fn nla(kind: u16, value: Vec<u8>) -> DefaultNla {
    DefaultNla::new(kind, value)
}

/// An expression the crate does not model, addressed by its nft type name.
fn other(expression_type: &str, attributes: Vec<DefaultNla>) -> Expr {
    Expressions::Other {
        expression_type: expression_type.into(),
        attributes,
    }
    .into()
}

fn be32(value: u32) -> Vec<u8> {
    value.to_be_bytes().to_vec()
}

fn be64(value: u64) -> Vec<u8> {
    value.to_be_bytes().to_vec()
}

/// A 32-bit `nft` integer datatype value (`mark`, a `fib` result) as it sits in
/// a register: host byte order, unlike the big-endian wire attributes.
fn ne32(value: u32) -> Vec<u8> {
    value.to_ne_bytes().to_vec()
}

/// `reg = <value>` (an immediate load).
pub fn load_immediate(reg: Register, value: impl Into<Vec<u8>>) -> Expr {
    Expressions::Immediate(vec![
        Immediate::DestinationRegister(reg),
        Immediate::Data(DataAttribute::Value(value.into())),
    ])
    .into()
}

/// `meta <key> = reg` (a store).
pub fn meta_store(key: MetaKey, reg: Register) -> Expr {
    Expressions::Meta(vec![Meta::Key(key), Meta::SourceRegister(reg)]).into()
}

/// `reg = reg | value`, encoded as nft's `bitwise(!value, value)`.
pub fn bitwise_or(reg: Register, len: u32, value: Vec<u8>) -> Expr {
    let mask = value.iter().map(|b| !b).collect();
    bitwise(reg, len, mask, value)
}

/// `reg = reg ^ value`.
pub fn bitwise_xor(reg: Register, len: u32, value: Vec<u8>) -> Expr {
    bitwise(reg, len, vec![0xff; len as usize], value)
}

/// `reg = reg & value`.
pub fn bitwise_and(reg: Register, len: u32, value: Vec<u8>) -> Expr {
    bitwise(reg, len, value, vec![0u8; len as usize])
}

/// The register a concatenated-key field starting at byte `offset` with field
/// length `len` loads into, as nft lays concat fields out: a 16-byte field
/// aligned on a 16-byte boundary uses a legacy 16-byte register (`Reg1`, `Reg2`,
/// …); every other field uses a 32-bit register at its byte offset.
pub fn concat_register(offset: u32, len: u32) -> Register {
    if offset == 0 {
        Register::Reg1
    } else if len == 16 && offset.is_multiple_of(16) {
        Register::from(offset / 16 + 1)
    } else {
        Register::from(8 + offset / 4)
    }
}

/// Tracks the byte offset of the next concatenated field and hands out its
/// register.
#[derive(Default)]
struct Concat {
    offset: u32,
}

impl Concat {
    fn add(&mut self, len: u32) -> Register {
        let reg = concat_register(self.offset, len);
        self.offset += len.div_ceil(4) * 4;
        reg
    }
}

/// `fib daddr type local` into `reg`, followed by the `== RTN_LOCAL` compare.
pub fn fib_daddr_type_local(reg: Register) -> Vec<Expr> {
    const NFTA_FIB_DREG: u16 = 1;
    const NFTA_FIB_RESULT: u16 = 2;
    const NFTA_FIB_FLAGS: u16 = 3;
    const NFT_FIB_RESULT_ADDRTYPE: u32 = 3;
    const NFT_FIB_F_DADDR: u32 = 2;
    const RTN_LOCAL: u32 = 2;

    vec![
        other(
            "fib",
            vec![
                nla(NFTA_FIB_DREG, be32(reg.into())),
                nla(NFTA_FIB_RESULT, be32(NFT_FIB_RESULT_ADDRTYPE)),
                nla(NFTA_FIB_FLAGS, be32(NFT_FIB_F_DADDR)),
            ],
        ),
        cmp(reg, Operator::Equal, ne32(RTN_LOCAL)),
    ]
}

/// `fib saddr type local` into `reg`, followed by the `== RTN_LOCAL` compare.
///
/// Matches packets whose *source* address is one of this host's addresses, i.e.
/// locally-originated traffic (used for the `Local` external-traffic-policy
/// short-circuit).
pub fn fib_saddr_type_local(reg: Register) -> Vec<Expr> {
    const NFTA_FIB_DREG: u16 = 1;
    const NFTA_FIB_RESULT: u16 = 2;
    const NFTA_FIB_FLAGS: u16 = 3;
    const NFT_FIB_RESULT_ADDRTYPE: u32 = 3;
    const NFT_FIB_F_SADDR: u32 = 1;
    const RTN_LOCAL: u32 = 2;

    vec![
        other(
            "fib",
            vec![
                nla(NFTA_FIB_DREG, be32(reg.into())),
                nla(NFTA_FIB_RESULT, be32(NFT_FIB_RESULT_ADDRTYPE)),
                nla(NFTA_FIB_FLAGS, be32(NFT_FIB_F_SADDR)),
            ],
        ),
        cmp(reg, Operator::Equal, ne32(RTN_LOCAL)),
    ]
}

/// `numgen random mod <modulus>` into `reg`.
pub fn numgen_random(reg: Register, modulus: u32) -> Expr {
    const NFTA_NGEN_DREG: u16 = 1;
    const NFTA_NGEN_MODULUS: u16 = 2;
    const NFTA_NGEN_TYPE: u16 = 3;
    const NFTA_NGEN_OFFSET: u16 = 4;
    const NFT_NG_RANDOM: u32 = 1;

    other(
        "numgen",
        vec![
            nla(NFTA_NGEN_DREG, be32(reg.into())),
            nla(NFTA_NGEN_MODULUS, be32(modulus)),
            nla(NFTA_NGEN_TYPE, be32(NFT_NG_RANDOM)),
            nla(NFTA_NGEN_OFFSET, be32(0)),
        ],
    )
}

/// `ct state` loaded into `reg`.
pub fn ct_state(reg: Register) -> Expr {
    const NFTA_CT_DREG: u16 = 1;
    const NFTA_CT_KEY: u16 = 2;
    const NFT_CT_STATE: u32 = 0;

    other(
        "ct",
        vec![
            nla(NFTA_CT_DREG, be32(reg.into())),
            nla(NFTA_CT_KEY, be32(NFT_CT_STATE)),
        ],
    )
}

/// `ct state established,related`: whether the packet belongs to an
/// already-established flow.
///
/// `ct state` is a 4-byte host-endian bitmask on `ct->status`; the bits are
/// `NF_CT_STATE_BIT(ctinfo) = 1 << (ctinfo % IP_CT_IS_REPLY + 1)`, so
/// `established` (0) is `1 << 1` and `related` (1) is `1 << 2`.
pub fn ct_state_established_related(reg: Register) -> Vec<Expr> {
    const ESTABLISHED_RELATED: u32 = (1 << 1) | (1 << 2);

    vec![
        ct_state(reg),
        bitwise_and(reg, 4, ne32(ESTABLISHED_RELATED)),
        cmp(reg, Operator::NotEqual, vec![0u8; 4]),
    ]
}

/// `ct original ip daddr` (v4) / `ip6 daddr` (v6) into `reg`.
pub fn ct_original_daddr(family: Family, reg: Register) -> Expr {
    const NFTA_CT_DREG: u16 = 1;
    const NFTA_CT_KEY: u16 = 2;
    const NFTA_CT_DIRECTION: u16 = 3;
    const NFT_CT_DST_IP: u32 = 20;
    const NFT_CT_DST_IP6: u32 = 22;
    const IP_CT_DIR_ORIGINAL: u8 = 0;

    let key = match family {
        Family::V4 => NFT_CT_DST_IP,
        Family::V6 => NFT_CT_DST_IP6,
    };
    other(
        "ct",
        vec![
            nla(NFTA_CT_DREG, be32(reg.into())),
            nla(NFTA_CT_KEY, be32(key)),
            nla(NFTA_CT_DIRECTION, vec![IP_CT_DIR_ORIGINAL]),
        ],
    )
}

/// `dnat <family> to <addr>:<port>`, the address and port taken from
/// `addr_reg` and `port_reg`.
pub fn dnat(family: Family, addr: Register, port: Register) -> Expr {
    const NFTA_NAT_TYPE: u16 = 1;
    const NFTA_NAT_FAMILY: u16 = 2;
    const NFTA_NAT_REG_ADDR_MIN: u16 = 3;
    const NFTA_NAT_REG_ADDR_MAX: u16 = 4;
    const NFTA_NAT_REG_PROTO_MIN: u16 = 5;
    const NFTA_NAT_REG_PROTO_MAX: u16 = 6;
    const NFTA_NAT_FLAGS: u16 = 7;
    const NFT_NAT_DNAT: u32 = 1;

    other(
        "nat",
        vec![
            nla(NFTA_NAT_TYPE, be32(NFT_NAT_DNAT)),
            nla(NFTA_NAT_FAMILY, be32(family.nfproto_u32())),
            nla(NFTA_NAT_REG_ADDR_MIN, be32(addr.into())),
            nla(NFTA_NAT_REG_ADDR_MAX, be32(addr.into())),
            nla(NFTA_NAT_REG_PROTO_MIN, be32(port.into())),
            nla(NFTA_NAT_REG_PROTO_MAX, be32(port.into())),
            nla(NFTA_NAT_FLAGS, be32(3)),
        ],
    )
}

/// `masquerade` (or `masquerade fully-random`).
pub fn masquerade(fully_random: bool) -> Expr {
    const NFTA_MASQ_FLAGS: u16 = 1;
    const NF_NAT_RANGE_PROTO_RANDOM_FULLY: u32 = 0x10;

    let attributes = if fully_random {
        vec![nla(NFTA_MASQ_FLAGS, be32(NF_NAT_RANGE_PROTO_RANDOM_FULLY))]
    } else {
        Vec::new()
    };
    other("masq", attributes)
}

/// `update @set { key }`, adding/updating an element from packet data.
pub fn dynset_update(set: &str, key: Register) -> Expr {
    const NFTA_DYNSET_SET_NAME: u16 = 1;
    const NFTA_DYNSET_OP: u16 = 3;
    const NFTA_DYNSET_SREG_KEY: u16 = 4;
    const NFTA_DYNSET_TIMEOUT: u16 = 6;
    const NFTA_DYNSET_FLAGS: u16 = 9;
    const NFT_DYNSET_OP_UPDATE: u32 = 1;

    let mut name = set.as_bytes().to_vec();
    name.push(0);

    other(
        "dynset",
        vec![
            nla(NFTA_DYNSET_SET_NAME, name),
            nla(NFTA_DYNSET_OP, be32(NFT_DYNSET_OP_UPDATE)),
            nla(NFTA_DYNSET_SREG_KEY, be32(key.into())),
            nla(NFTA_DYNSET_TIMEOUT, be64(0)),
            nla(NFTA_DYNSET_FLAGS, be32(0)),
        ],
    )
}

/// `reject with icmp port-unreachable` (v4) / `icmpv6 port-unreachable` (v6),
/// the family-specific reject nft emits inside an `ip`/`ip6` match.
pub fn reject_icmp(family: Family) -> Expr {
    const NFTA_REJECT_TYPE: u16 = 1;
    const NFTA_REJECT_ICMP_CODE: u16 = 2;
    const NFT_REJECT_ICMP_UNREACH: u32 = 0;

    let code = match family {
        Family::V4 => 3,
        Family::V6 => 4,
    };
    other(
        "reject",
        vec![
            nla(NFTA_REJECT_TYPE, be32(NFT_REJECT_ICMP_UNREACH)),
            nla(NFTA_REJECT_ICMP_CODE, vec![code]),
        ],
    )
}

/// `ip daddr . ip protocol . th dport vmap @map` (IPv4 service dispatch).
pub fn ip_daddr_ip_proto_dport_vmap(map: &str) -> Vec<Expr> {
    let mut c = Concat::default();
    let daddr = c.add(4);
    let proto = c.add(1);
    let dport = c.add(2);

    vec![
        meta_nfproto(Register::Reg1),
        eq(Register::Reg1, Family::V4.nfproto()),
        payload(daddr, NETWORK_HEADER, 16, 4),
        payload(proto, NETWORK_HEADER, 9, 1),
        payload(dport, TRANSPORT_HEADER, 2, 2),
        lookup_vmap(Register::Reg1, map),
    ]
}

/// `fib daddr type local ip protocol . th dport vmap @map` (NodePort
/// dispatch; the `fib` guard restricts to locally-destined packets).
pub fn fib_daddr_local_ip_proto_dport_vmap(map: &str) -> Vec<Expr> {
    let mut c = Concat::default();
    let proto = c.add(1);
    let dport = c.add(2);

    let mut exprs = fib_daddr_type_local(Register::Reg1);
    exprs.push(meta_nfproto(Register::Reg1));
    exprs.push(eq(Register::Reg1, Family::V4.nfproto()));
    exprs.push(payload(proto, NETWORK_HEADER, 9, 1));
    exprs.push(payload(dport, TRANSPORT_HEADER, 2, 2));
    exprs.push(lookup_vmap(Register::Reg1, map));
    exprs
}

/// `meta nfproto <family> numgen random mod <modulus> vmap @map` (endpoint
/// selection).
pub fn numgen_vmap(family: Family, modulus: u32, map: &str) -> Vec<Expr> {
    vec![
        meta_nfproto(Register::Reg1),
        eq(Register::Reg1, family.nfproto()),
        numgen_random(Register::Reg1, modulus),
        lookup_vmap(Register::Reg1, map),
    ]
}

/// `ip|ip6 saddr . daddr . ct original <addr> @set masquerade`.
pub fn ct_masquerade(family: Family, set: &str) -> Vec<Expr> {
    let (saddr, daddr, len) = match family {
        Family::V4 => (12, 16, 4),
        Family::V6 => (8, 24, 16),
    };

    let mut c = Concat::default();
    let s = c.add(len);
    let d = c.add(len);
    let ct = c.add(len);

    vec![
        meta_nfproto(Register::Reg1),
        eq(Register::Reg1, family.nfproto()),
        payload(s, NETWORK_HEADER, saddr, len),
        payload(d, NETWORK_HEADER, daddr, len),
        ct_original_daddr(family, ct),
        lookup_set(Register::Reg1, set),
        masquerade(false),
    ]
}

/// `meta mark & <mask> == 0`.
pub fn mark_and_eq_zero(reg: Register, mask: u32) -> Vec<Expr> {
    vec![
        meta(MetaKey::Mark, reg),
        bitwise_and(reg, 4, ne32(mask)),
        eq(reg, vec![0u8; 4]),
    ]
}

/// `meta mark set meta mark ^ <mask>`.
pub fn mark_xor(reg: Register, mask: u32) -> Vec<Expr> {
    vec![
        meta(MetaKey::Mark, reg),
        bitwise_xor(reg, 4, ne32(mask)),
        meta_store(MetaKey::Mark, reg),
    ]
}

/// The address a `dnat`/`redirect` statement targets.
pub enum Dnat {
    /// `dnat to <ip>:<port>` with no masquerade mark: the endpoint is on this
    /// node, so the source address is preserved.
    ///
    /// A `redirect` would send the packet to the node's *local* address, which
    /// a hostNetwork endpoint listening on the node IP (not `127.0.0.1`) does
    /// not accept.
    Local { ip: IpAddr, port: u16 },
    /// `mark set mark | <mark> dnat to <ip>:<port>` (the endpoint is remote).
    Masquerade { ip: IpAddr, port: u16, mark: u32 },
}

/// `[fib daddr type local] meta nfproto <family> <proto> dport <port>` followed
/// by the `redirect`/`dnat` statement of `target`.
pub fn dnat_rule(family: Family, proto: u8, port: u16, node_port: bool, target: Dnat) -> Vec<Expr> {
    let mut exprs = Vec::new();
    if node_port {
        exprs.extend(fib_daddr_type_local(Register::Reg1));
    }
    exprs.push(meta_nfproto(Register::Reg1));
    exprs.push(eq(Register::Reg1, family.nfproto()));
    exprs.push(meta(MetaKey::L4Proto, Register::Reg1));
    exprs.push(eq(Register::Reg1, vec![proto]));
    exprs.push(payload(Register::Reg1, TRANSPORT_HEADER, 2, 2));
    exprs.push(eq(Register::Reg1, port.to_be_bytes().to_vec()));

    match target {
        Dnat::Local { ip, port } => {
            exprs.push(load_immediate(Register::Reg1, ip_bytes(ip)));
            exprs.push(load_immediate(Register::Reg2, port.to_be_bytes().to_vec()));
            exprs.push(dnat(family, Register::Reg1, Register::Reg2));
        }
        Dnat::Masquerade { ip, port, mark } => {
            exprs.push(meta(MetaKey::Mark, Register::Reg1));
            exprs.push(bitwise_or(Register::Reg1, 4, ne32(mark)));
            exprs.push(meta_store(MetaKey::Mark, Register::Reg1));
            exprs.push(load_immediate(Register::Reg1, ip_bytes(ip)));
            exprs.push(load_immediate(Register::Reg2, port.to_be_bytes().to_vec()));
            exprs.push(dnat(family, Register::Reg1, Register::Reg2));
        }
    }
    exprs
}

fn ip_bytes(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(ip) => ip.octets().to_vec(),
    }
}

/// `meta nfproto <family> reject` — a family-specific reject for a chain that
/// has no endpoints of that family.
pub fn nfproto_reject(family: Family) -> Vec<Expr> {
    vec![
        meta_nfproto(Register::Reg1),
        eq(Register::Reg1, family.nfproto()),
        reject_icmp(family),
    ]
}

/// `ip|ip6 saddr . <addr> @set goto <chain>` — the session-affinity match that
/// pins a client to an endpoint.
pub fn affinity_goto(family: Family, set: &str, addr: IpAddr, chain: &str) -> Vec<Expr> {
    let (offset, len) = match family {
        Family::V4 => (12, 4),
        Family::V6 => (8, 16),
    };

    let mut c = Concat::default();
    let saddr = c.add(len);
    let addr_reg = c.add(len);

    vec![
        meta_nfproto(Register::Reg1),
        eq(Register::Reg1, family.nfproto()),
        payload(saddr, NETWORK_HEADER, offset, len),
        load_immediate(addr_reg, ip_bytes(addr)),
        lookup_set(Register::Reg1, set),
        goto(chain),
    ]
}

/// `update @set { ip|ip6 saddr . <addr> }` — records the client/endpoint pair
/// in the session-affinity set.
pub fn affinity_update(family: Family, set: &str, addr: IpAddr) -> Vec<Expr> {
    let (offset, len) = match family {
        Family::V4 => (12, 4),
        Family::V6 => (8, 16),
    };

    let mut c = Concat::default();
    let saddr = c.add(len);
    let addr_reg = c.add(len);

    vec![
        meta_nfproto(Register::Reg1),
        eq(Register::Reg1, family.nfproto()),
        payload(saddr, NETWORK_HEADER, offset, len),
        load_immediate(addr_reg, ip_bytes(addr)),
        dynset_update(set, Register::Reg1),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use netlink_packet_netfilter::nftables::VerdictAttribute;

    /// The nested verdict attributes of an immediate-verdict expression.
    fn verdict_attrs(e: &Expr) -> &[VerdictAttribute] {
        let ListAttribute::Element(attrs) = e else {
            panic!("not an element");
        };
        attrs
            .iter()
            .find_map(|a| match a {
                ExpressionAttribute::Data(Expressions::Immediate(imm)) => {
                    imm.iter().find_map(|i| match i {
                        Immediate::Data(DataAttribute::Verdict(v)) => Some(v.as_slice()),
                        _ => None,
                    })
                }
                _ => None,
            })
            .expect("verdict")
    }

    #[test]
    fn accept_and_drop_codes() {
        assert_eq!(
            verdict_attrs(&accept()),
            &[VerdictAttribute::Code(NlVerdict::Other(1))]
        );
        assert_eq!(
            verdict_attrs(&drop()),
            &[VerdictAttribute::Code(NlVerdict::Other(0))]
        );
    }

    #[test]
    fn jump_carries_chain() {
        assert_eq!(
            verdict_attrs(&jump("t")),
            &[
                VerdictAttribute::Code(NlVerdict::Jump),
                VerdictAttribute::Chain("t".into()),
            ]
        );
        assert_eq!(
            verdict_attrs(&goto("g")),
            &[
                VerdictAttribute::Code(NlVerdict::Goto),
                VerdictAttribute::Chain("g".into()),
            ]
        );
    }

    #[test]
    fn reject_is_its_own_expression() {
        let expr: Expr = Reject::default().into();
        let ListAttribute::Element(attrs) = expr else {
            panic!("not an element");
        };
        let name = attrs.iter().find_map(|a| match a {
            ExpressionAttribute::Name(n) => Some(n.as_str()),
            _ => None,
        });
        assert_eq!(name, Some("reject"));

        // type = ICMPX_UNREACH (2, 4 bytes), code = PORT_UNREACH (1, 1 byte)
        let data = attrs
            .iter()
            .find_map(|a| match a {
                ExpressionAttribute::Data(Expressions::Other { attributes, .. }) => {
                    Some(attributes.clone())
                }
                _ => None,
            })
            .expect("reject attributes");
        use netlink_packet_core::Nla;
        let get = |kind: u16| {
            data.iter().find(|a| a.kind() == kind).map(|a| {
                let mut buf = vec![0u8; a.value_len()];
                a.emit_value(&mut buf);
                buf
            })
        };
        assert_eq!(get(1), Some(2u32.to_be_bytes().to_vec()));
        assert_eq!(get(2), Some(vec![1u8]));
    }

    #[test]
    fn ip_set_has_nfproto_guard_and_lookup() {
        // v4 saddr @s
        let e = ip_set(Family::V4, Dir::Src, "s", false);
        assert_eq!(e.len(), 4);
        // first two: meta nfproto load + cmp
        assert!(matches!(e[0], ListAttribute::Element(_)));
        // payload loads 4 bytes @ network header + 12
        let ListAttribute::Element(attrs) = &e[2] else {
            panic!()
        };
        let payload = attrs.iter().find_map(|a| match a {
            ExpressionAttribute::Data(Expressions::Payload(p)) => Some(p),
            _ => None,
        });
        let payload = payload.expect("payload");
        assert!(payload.contains(&Payload::Base(NETWORK_HEADER)));
        assert!(payload.contains(&Payload::Offset(12)));
        assert!(payload.contains(&Payload::Len(4)));
    }

    #[test]
    fn ip_set_invert_sets_flag() {
        let e = ip_set(Family::V4, Dir::Src, "s", true);
        let ListAttribute::Element(attrs) = &e[3] else {
            panic!()
        };
        let lookup = attrs.iter().find_map(|a| match a {
            ExpressionAttribute::Data(Expressions::Lookup(l)) => Some(l),
            _ => None,
        });
        assert!(
            lookup.expect("lookup").contains(&Lookup::Flags(1)),
            "inverted lookup must carry NFT_LOOKUP_F_INV"
        );
    }

    #[test]
    fn l4proto_dport_uses_concat_registers() {
        let e = l4proto_dport_set("p");
        assert_eq!(e.len(), 3);
        // dport loads at the register after l4proto's slot
        let ListAttribute::Element(attrs) = &e[1] else {
            panic!()
        };
        let payload = attrs.iter().find_map(|a| match a {
            ExpressionAttribute::Data(Expressions::Payload(p)) => Some(p),
            _ => None,
        });
        assert!(
            payload
                .expect("payload")
                .contains(&Payload::DestinationRegister(Register::Reg32_01))
        );
    }

    /// The lookup attrs of `e`.
    fn lookup_attrs(e: &Expr) -> Vec<Lookup> {
        let ListAttribute::Element(attrs) = e else {
            panic!("not an element");
        };
        attrs
            .iter()
            .find_map(|a| match a {
                ExpressionAttribute::Data(Expressions::Lookup(l)) => Some(l.clone()),
                _ => None,
            })
            .expect("lookup")
    }

    #[test]
    fn lookup_variants() {
        // plain membership: no destination register
        assert_eq!(
            lookup_attrs(&lookup_set(Register::Reg1, "s")),
            vec![
                Lookup::SourceRegister(Register::Reg1),
                Lookup::Set("s".into())
            ]
        );

        // map: explicit destination register
        assert_eq!(
            lookup_attrs(&lookup_map(Register::Reg1, Register::Reg2, "m")),
            vec![
                Lookup::SourceRegister(Register::Reg1),
                Lookup::Set("m".into()),
                Lookup::DestinationRegister(Register::Reg2),
            ]
        );

        // verdict map: destination is the verdict register
        assert_eq!(
            lookup_attrs(&lookup_vmap(Register::Reg1, "v")),
            vec![
                Lookup::SourceRegister(Register::Reg1),
                Lookup::Set("v".into()),
                Lookup::DestinationRegister(Register::Verdict),
            ]
        );

        // inverted membership
        assert_eq!(
            lookup_attrs(&lookup_set_inv(Register::Reg1, "s")),
            vec![
                Lookup::SourceRegister(Register::Reg1),
                Lookup::Set("s".into()),
                Lookup::Flags(1),
            ]
        );
    }

    #[test]
    fn anon_lookups_use_set_id_placeholders() {
        // an anonymous reference carries only its index (`NFTA_LOOKUP_SET_ID`);
        // `sync` lowers it to a name.
        assert_eq!(
            lookup_attrs(&lookup_anon(Register::Reg1, 3)),
            vec![Lookup::SourceRegister(Register::Reg1), Lookup::SetId(3),]
        );
        assert_eq!(
            lookup_attrs(&lookup_anon_inv(Register::Reg1, 3)),
            vec![
                Lookup::SourceRegister(Register::Reg1),
                Lookup::SetId(3),
                Lookup::Flags(1),
            ]
        );

        // the concat and ip variants use the same placeholder in their lookup
        assert_eq!(
            lookup_attrs(l4proto_dport_anon(7).last().expect("lookup")),
            vec![Lookup::SourceRegister(Register::Reg1), Lookup::SetId(7),]
        );
        assert_eq!(
            lookup_attrs(
                ip_set_anon(Family::V4, Dir::Src, 9, true)
                    .last()
                    .expect("lookup")
            ),
            vec![
                Lookup::SourceRegister(Register::Reg1),
                Lookup::SetId(9),
                Lookup::Flags(1),
            ]
        );
    }

    /// The expressions of `ip_prefix`, as a compact `(kind, ...)` view.
    fn prefix_shape(e: &[Expr]) -> Vec<&'static str> {
        e.iter()
            .map(|x| {
                let ListAttribute::Element(attrs) = x else {
                    panic!("not an element");
                };
                attrs
                    .iter()
                    .find_map(|a| match a {
                        ExpressionAttribute::Data(Expressions::Meta(_)) => Some("meta"),
                        ExpressionAttribute::Data(Expressions::Cmp(_)) => Some("cmp"),
                        ExpressionAttribute::Data(Expressions::Payload(_)) => Some("payload"),
                        ExpressionAttribute::Data(Expressions::Bitwise(_)) => Some("bitwise"),
                        _ => None,
                    })
                    .expect("expression")
            })
            .collect()
    }

    #[test]
    fn ip_prefix_byte_aligned_loads_prefix_bytes() {
        // /24 => meta nfproto, cmp nfproto, payload 3 bytes, cmp; no bitwise
        let e = ip_prefix(Family::V4, Dir::Src, 24, vec![192, 168, 42, 0], false);
        assert_eq!(prefix_shape(&e), ["meta", "cmp", "payload", "cmp"]);

        let ListAttribute::Element(attrs) = &e[2] else {
            panic!()
        };
        let payload = attrs.iter().find_map(|a| match a {
            ExpressionAttribute::Data(Expressions::Payload(p)) => Some(p),
            _ => None,
        });
        assert!(payload.expect("payload").contains(&Payload::Len(3)));
    }

    #[test]
    fn ip_prefix_unaligned_masks() {
        // /20 => payload 4 bytes, bitwise, cmp
        let e = ip_prefix(Family::V4, Dir::Src, 20, vec![1, 2, 0, 0], false);
        assert_eq!(
            prefix_shape(&e),
            ["meta", "cmp", "payload", "bitwise", "cmp"]
        );
    }

    #[test]
    fn prefix_mask_covers_prefix() {
        assert_eq!(prefix_mask(4, 20), vec![0xff, 0xff, 0xf0, 0x00]);
        assert_eq!(prefix_mask(4, 32), vec![0xff, 0xff, 0xff, 0xff]);
        assert_eq!(prefix_mask(4, 0), vec![0, 0, 0, 0]);
    }
}
