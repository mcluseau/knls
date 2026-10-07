//! Builders for the `Rule` expressions [`Chain`](super::chain::Chain) stores.
//!
//! These mirror the netlink encoding nft produces, verified against the kernel:
//! loading a header field into a register, comparing it, looking a value up in a
//! set/map, and applying a verdict (including `reject`).

use netlink_packet_netfilter::nftables::{
    Bitwise, Cmp, DataAttribute, ExpressionAttribute, Expressions, Immediate, ListAttribute,
    Lookup, Meta, MetaKey, Operator, Payload, Register, Verdict as NlVerdict, VerdictAttribute,
};

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

/// `meta l4proto == <proto>`, a protocol-only match (no port constraint).
///
/// A 1-byte compare, as nft emits it.
pub fn l4proto_eq(proto: u8) -> Vec<Expr> {
    vec![
        meta(MetaKey::L4Proto, Register::Reg1),
        eq(Register::Reg1, vec![proto]),
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
