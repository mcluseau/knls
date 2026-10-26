//! nft's `NFTA_SET_USERDATA` encoding, used to record a set's `typeof` key/value
//! annotations (and its comment) so `nft list` can print them.
//!
//! The wire format (`libnftnl/src/udata.c`) is a flat stream of
//! `[type: u8][len: u8][value]` TLVs; a nested value is simply more TLVs.
//! [`UdataBuf`] mirrors `struct nftnl_udata_buf`, and [`SetUdata`] mirrors the
//! tree `nft` builds in `nftables/src/mnl.c::mnl_nft_set_add` /
//! `set_key_expression`.
//!
//! We need it because nft has no *named* plain-integer datatype — `integer` is
//! unnameable, `mark` prints hex, and `gid`/`uid`/`realm`/… reject a `numgen`
//! key — so a `typeof numgen random mod 1` annotation is the only way to render
//! a base-10 integer key.
#![allow(dead_code)] // the `*Attr` enums mirror the C ones verbatim

/// `enum nftnl_udata_set_types` (`libnftnl/include/libnftnl/udata.h`).
#[repr(u8)]
enum SetAttr {
    KeyByteOrder = 0,
    DataByteOrder = 1,
    MergeElements = 2,
    KeyTypeof = 3,
    DataTypeof = 4,
    Expr = 5,
    DataInterval = 6,
    Comment = 7,
}

/// `enum { NFTNL_UDATA_SET_TYPEOF_EXPR, NFTNL_UDATA_SET_TYPEOF_DATA }`
/// (`libnftnl/include/libnftnl/udata.h`).
#[repr(u8)]
enum TypeofAttr {
    Expr = 0,
    Data = 1,
}

/// `NFTNL_UDATA_NUMGEN_*` (`nftables/src/numgen.c`).
#[repr(u8)]
enum NumgenAttr {
    Type = 0,
    Mod = 1,
    Offset = 2,
}

/// `enum expr_types` (`nftables/include/expression.h`).
#[repr(u32)]
enum ExprType {
    Verdict = 1,
    Numgen = 23,
}

/// `enum nft_ng_types` (`uapi/linux/netfilter/nf_tables.h`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum NgType {
    Incremental = 0,
    Random = 1,
}

/// `enum byteorder` (`nftables/include/datatype.h`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum ByteOrder {
    Invalid = 0,
    HostEndian = 1,
    BigEndian = 2,
}

/// A builder for a userdata TLV stream, mirroring `struct nftnl_udata_buf`.
///
/// Each [`put`](Self::put) appends one `[type: u8][len: u8][value]` TLV;
/// [`nest`](Self::nest) wraps a sub-stream and patches the outer length once it
/// ends, exactly like `nftnl_udata_nest_start` / `nftnl_udata_nest_end`.
#[derive(Default)]
pub struct UdataBuf {
    bytes: Vec<u8>,
}

impl UdataBuf {
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends a TLV (`nftnl_udata_put`).
    pub fn put(&mut self, kind: u8, value: &[u8]) -> &mut Self {
        debug_assert!(value.len() <= u8::MAX as usize, "nft userdata TLV too long");
        self.bytes.reserve(2 + value.len());
        self.bytes.push(kind);
        self.bytes.push(value.len() as u8);
        self.bytes.extend_from_slice(value);
        self
    }

    /// Appends a TLV carrying a host-endian `u32` (`nftnl_udata_put_u32`).
    pub fn put_u32(&mut self, kind: u8, value: u32) -> &mut Self {
        self.put(kind, &value.to_ne_bytes())
    }

    /// Appends a TLV carrying a NUL-terminated string (`nftnl_udata_put_strz`).
    pub fn put_strz(&mut self, kind: u8, value: &str) -> &mut Self {
        let mut strz = Vec::with_capacity(value.len() + 1);
        strz.extend_from_slice(value.as_bytes());
        strz.push(0);
        self.put(kind, &strz)
    }

    /// Runs `f` inside a nested TLV `kind`: writes the header with a
    /// placeholder length, then patches it to the nested stream's length once
    /// `f` returns.
    pub fn nest<R>(&mut self, kind: u8, f: impl FnOnce(&mut Self) -> R) -> R {
        self.bytes.push(kind);
        self.bytes.push(0);
        let start = self.bytes.len();
        let r = f(self);
        let len = self.bytes.len() - start;
        self.bytes[start - 1] = len as u8;
        r
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// A `typeof` annotation: the expression type of a set's key or value plus the
/// expression-specific sub-tree `nft` records for it (`build_udata`).
///
/// Only the expressions knls programs sets with are modelled; more variants
/// drop in as callers need them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Typeof {
    /// A verdict (`typeof <key> : verdict`).
    Verdict,
    /// A `numgen <kind> mod <modulus> [offset <offset>]` expression.
    Numgen {
        kind: NgType,
        modulus: u32,
        offset: u32,
    },
}

impl Typeof {
    /// A `numgen random mod <modulus>` annotation (offset 0).
    pub fn numgen_random(modulus: u32) -> Self {
        Self::Numgen {
            kind: NgType::Random,
            modulus,
            offset: 0,
        }
    }

    fn expr_type(self) -> ExprType {
        match self {
            Self::Verdict => ExprType::Verdict,
            Self::Numgen { .. } => ExprType::Numgen,
        }
    }

    /// Writes the expression-specific sub-stream (`expr_ops(expr)->build_udata`).
    fn build_udata(self, buf: &mut UdataBuf) {
        match self {
            // `verdict_expr_build_udata` writes nothing.
            Self::Verdict => {}
            Self::Numgen {
                kind,
                modulus,
                offset,
            } => {
                buf.put_u32(NumgenAttr::Type as u8, kind as u32);
                buf.put_u32(NumgenAttr::Mod as u8, modulus);
                buf.put_u32(NumgenAttr::Offset as u8, offset);
            }
        }
    }
}

/// A typed builder for the `NFTA_SET_USERDATA` of a named set or map.
///
/// Each method appends one field in the order `nft` writes them
/// (`mnl_nft_set_add`); [`build`](Self::build) yields the raw blob for
/// `SetAttribute::UserData` (or an embedded comment).
#[derive(Default)]
pub struct SetUdata {
    buf: UdataBuf,
}

impl SetUdata {
    pub fn new() -> Self {
        Self::default()
    }

    /// `NFTNL_UDATA_SET_KEYBYTEORDER`.
    pub fn key_byte_order(mut self, order: ByteOrder) -> Self {
        self.buf.put_u32(SetAttr::KeyByteOrder as u8, order as u32);
        self
    }

    /// `NFTNL_UDATA_SET_DATABYTEORDER` (data maps only).
    pub fn data_byte_order(mut self, order: ByteOrder) -> Self {
        self.buf.put_u32(SetAttr::DataByteOrder as u8, order as u32);
        self
    }

    /// `NFTNL_UDATA_SET_MERGE_ELEMENTS`.
    pub fn merge_elements(mut self, value: u32) -> Self {
        self.buf.put_u32(SetAttr::MergeElements as u8, value);
        self
    }

    /// `NFTNL_UDATA_SET_KEY_TYPEOF`: the `typeof` annotation of the key.
    pub fn key_typeof(mut self, expr: Typeof) -> Self {
        self.write_typeof(SetAttr::KeyTypeof, expr);
        self
    }

    /// `NFTNL_UDATA_SET_DATA_TYPEOF`: the `typeof` annotation of the value.
    pub fn data_typeof(mut self, expr: Typeof) -> Self {
        self.write_typeof(SetAttr::DataTypeof, expr);
        self
    }

    /// `NFTNL_UDATA_SET_DATA_INTERVAL` (whether the value is an interval).
    pub fn data_interval(mut self, interval: bool) -> Self {
        self.buf
            .put_u32(SetAttr::DataInterval as u8, interval as u32);
        self
    }

    /// `NFTNL_UDATA_SET_COMMENT`: a free-form string shown by `nft list`.
    pub fn comment(mut self, comment: &str) -> Self {
        // The TLV length is a single byte covering the comment and its
        // terminating NUL.
        let mut end = comment.len().min(254);
        while !comment.is_char_boundary(end) {
            end -= 1;
        }
        self.buf.put_strz(SetAttr::Comment as u8, &comment[..end]);
        self
    }

    /// The userdata blob.
    pub fn build(self) -> Vec<u8> {
        self.buf.into_bytes()
    }

    /// A `{ expr type, expr data }` nest, as `set_key_expression` writes it.
    fn write_typeof(&mut self, kind: SetAttr, expr: Typeof) {
        self.buf.nest(kind as u8, |buf| {
            buf.put_u32(TypeofAttr::Expr as u8, expr.expr_type() as u32);
            buf.nest(TypeofAttr::Data as u8, |buf| expr.build_udata(buf));
        });
    }
}

/// The `NFTA_SET_USERDATA` of a bare comment: a `NFTNL_UDATA_SET_COMMENT` TLV.
///
/// Appending this to an existing userdata blob adds the comment to it; `nft`
/// writes a set's `typeof` annotation and its comment into a single
/// `NFTA_SET_USERDATA` stream, the comment last.
pub fn comment_tlv(comment: &str) -> Vec<u8> {
    SetUdata::new().comment(comment).build()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The generated bytes match what nft writes (captured from a kernel dump),
    /// so `nft list` renders the decimal integer key.
    #[test]
    fn numgen_verdict_map_matches_nft() {
        const EXPECTED: &[u8] = &[
            0, 4, 1, 0, 0, 0, 1, 4, 0, 0, 0, 0, 3, 26, 0, 4, 23, 0, 0, 0, 1, 18, 0, 4, 1, 0, 0, 0,
            1, 4, 1, 0, 0, 0, 2, 4, 0, 0, 0, 0, 4, 8, 0, 4, 1, 0, 0, 0, 1, 0, 6, 4, 0, 0, 0, 0,
        ];
        let got = SetUdata::new()
            .key_byte_order(ByteOrder::HostEndian)
            .data_byte_order(ByteOrder::Invalid)
            .key_typeof(Typeof::numgen_random(1))
            .data_typeof(Typeof::Verdict)
            .data_interval(false)
            .build();
        assert_eq!(got, EXPECTED);
    }

    /// A comment is a `[type][len][strz]` TLV, independent of any annotation.
    #[test]
    fn comment_is_a_strz_tlv() {
        assert_eq!(
            SetUdata::new().comment("hello").build(),
            b"\x07\x06hello\x00"
        );
    }

    /// The comment is truncated to what the one-byte TLV length can hold,
    /// on a character boundary.
    #[test]
    fn long_comment_is_truncated() {
        let comment = "€".repeat(100); // 300 bytes, 3 per char
        let bytes = SetUdata::new().comment(&comment).build();
        assert_eq!(bytes[0], SetAttr::Comment as u8);
        let payload = &bytes[2..bytes.len() - 1];
        assert_eq!(payload.len(), 252); // 254 rounded down to a char boundary
        assert_eq!(bytes[1] as usize, payload.len() + 1);
        assert!(std::str::from_utf8(payload).is_ok());
    }

    /// A nested TLV's length is patched to its payload, not its header.
    #[test]
    fn nest_patches_length() {
        let mut buf = UdataBuf::new();
        buf.put(1, &[0xaa]);
        buf.nest(2, |buf| {
            buf.put_u32(3, 0x11223344);
        });
        assert_eq!(
            buf.into_bytes(),
            [1, 1, 0xaa, 2, 6, 3, 4, 0x44, 0x33, 0x22, 0x11]
        );
    }
}
