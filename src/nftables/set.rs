use netlink_packet_core::{
    Emitable, NLM_F_ACK, NLM_F_CREATE, NLM_F_REQUEST, NetlinkHeader, NetlinkMessage,
};
use netlink_packet_netfilter::{
    NetfilterMessage,
    nftables::{
        ListAttribute, NfTablesMessage, SetAttribute, SetDescription, SetElementAttribute,
        SetElementList, SetElementMessage, SetFlags, SetMessage, Verdict as NlVerdict,
    },
};
use std::{
    marker::PhantomData,
    net::{Ipv4Addr, Ipv6Addr},
    ops::RangeInclusive,
};

use super::{Message, nft_header};

/// A named set of single keys.
pub type SimpleSet<T> = Set<T>;

/// A named set of intervals over keys of type `T`. `fill` takes inclusive
/// `RangeInclusive<T>`.
pub type IntervalSet<T> = Set<RangeInclusive<T>>;

/// A named map from key type `K` to data type `D`.
pub type MapSet<K, D> = Set<MapElem<K, D>>;

/// A named map from key type `K` to verdicts of value type `V`.
pub type VerdictMapSet<K> = Set<VerdictElem<K>>;

/// Maximum size of the `NFTA_SET_ELEM_LIST_ELEMENTS` attribute payload.
///
/// `nlattr.nla_len` is 16-bit and includes the 4-byte header, so the payload
/// itself must stay below `u16::MAX - 4`.
const MAX_ELEMS_BYTES: usize = u16::MAX as usize - 4;

/// `NFT_DATA_VERDICT`: data type of map values that are verdicts.
const NFT_DATA_VERDICT: u32 = 0xffffff00;

/// A verdict map value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Accept the packet (`NF_ACCEPT`).
    Accept,
    /// Drop the packet (`NF_DROP`).
    Drop,
    /// Return from the current chain.
    Return,
    /// Continue evaluation of the current rule.
    Continue,
    /// Terminate evaluation of the current rule.
    Break,
    /// Jump to `chain` (pushing the current chain on the jump stack).
    Jump(String),
    /// Go to `chain` without pushing the current chain on the jump stack.
    Goto(String),
}

impl Verdict {
    /// The netfilter verdict code and, for `goto`/`jump`, the target chain.
    fn code(&self) -> (NlVerdict, Option<&str>) {
        match self {
            Self::Accept => (NlVerdict::Other(1), None), // NF_ACCEPT
            Self::Drop => (NlVerdict::Other(0), None),   // NF_DROP
            Self::Return => (NlVerdict::Return, None),
            Self::Continue => (NlVerdict::Continue, None),
            Self::Break => (NlVerdict::Break, None),
            Self::Jump(chain) => (NlVerdict::Jump, Some(chain)),
            Self::Goto(chain) => (NlVerdict::Goto, Some(chain)),
        }
    }
}

/// The map value payload of an element.
#[doc(hidden)]
pub enum DataAttr {
    /// A plain value (raw bytes).
    Value(Vec<u8>),
    /// A verdict, carried as a nested verdict attribute.
    Verdict(Verdict),
}

mod attr {
    use netlink_packet_netfilter::nftables::{
        DataAttribute,
        ListAttribute::{self, Element},
        SetElementAttribute::{self, Data, Flags, Key, UserData},
        SetElementFlags, VerdictAttribute,
    };

    use super::{DataAttr, Verdict};

    fn verdict_data(verdict: Verdict) -> SetElementAttribute {
        let (code, chain) = verdict.code();
        let mut attrs = vec![VerdictAttribute::Code(code)];
        if let Some(chain) = chain {
            attrs.push(VerdictAttribute::Chain(chain.to_string()));
        }
        Data(DataAttribute::Verdict(attrs))
    }

    /// The key attribute, plus the map data (if any) as a sibling attribute.
    fn elem_key(key: Vec<u8>, data: Option<DataAttr>) -> Vec<SetElementAttribute> {
        let mut attrs = vec![Key(DataAttribute::Value(key))];
        if let Some(data) = data {
            attrs.push(match data {
                DataAttr::Value(bytes) => Data(DataAttribute::Value(bytes)),
                DataAttr::Verdict(verdict) => verdict_data(verdict),
            });
        }
        attrs
    }

    pub(super) fn key(key: Vec<u8>) -> ListAttribute<SetElementAttribute> {
        Element(elem_key(key, None))
    }

    /// A key carrying map data; only [`MapElem`](super::MapElem) uses this.
    pub(super) fn key_with_data(
        key: Vec<u8>,
        data: DataAttr,
    ) -> ListAttribute<SetElementAttribute> {
        Element(elem_key(key, Some(data)))
    }

    pub(super) fn interval_start(start: Vec<u8>) -> ListAttribute<SetElementAttribute> {
        Element(elem_key(start, None))
    }

    pub(super) fn open_interval(start: Vec<u8>) -> ListAttribute<SetElementAttribute> {
        let mut attrs = elem_key(start, None);
        attrs.push(nft_elem_flags(SET_ELEM_F_INTERVAL_OPEN));
        Element(attrs)
    }

    /// The interval end never carries map data: the kernel rejects it.
    pub(super) fn interval_end(end: Vec<u8>) -> ListAttribute<SetElementAttribute> {
        let mut attrs = elem_key(end, None);
        attrs.push(Flags(SetElementFlags::IntervalEnd));
        Element(attrs)
    }

    /// The `NFTNL_SET_ELEM_F_INTERVAL_OPEN` bit within it.
    const SET_ELEM_F_INTERVAL_OPEN: u32 = 0x1;

    fn nft_elem_flags(flags: u32) -> SetElementAttribute {
        // nft's own TLV layout: [type: u8][len: u8][value], native-endian u32.
        // Only used by userspace to print/dump the element as `key-`; the kernel
        // ignores it.
        let mut udata = vec![0u8; 6];
        udata[0] = 1; // `NFTNL_UDATA_SET_ELEM_FLAGS` userdata attribute type.
        udata[1] = 4;
        udata[2..6].copy_from_slice(&flags.to_ne_bytes());

        UserData(udata)
    }
}

/// A value that can be a set element: a key, or (for interval sets) an
/// inclusive range of keys.
///
/// [`set_attributes`](Elem::set_attributes) returns the set-level attributes
/// (key/data types and lengths, flags, and the concat descriptor);
/// [`attributes`](Elem::attributes) returns the element attributes for the
/// value, treated as an atomic block by the fill iterator (an interval's start
/// and end never split across messages).
pub trait Elem {
    /// The full set-level flags (data-implied flags, e.g. `Concat`, composed
    /// with the element shape's, e.g. `Interval`/`Map`).
    const SET_FLAGS: SetFlags;

    /// The set-level attributes for `NFTA_SET_*`, minus table/name/id/flags.
    fn set_attributes() -> Vec<SetAttribute>;

    /// Element attributes for this value, treated as an atomic block by the
    /// fill iterator (an interval's start and end never split across messages).
    fn attributes(&self) -> Vec<ListAttribute<SetElementAttribute>>;
}

/// `NFTA_SET_DESC` with a concat descriptor for the given (unpadded) field
/// lengths. `NFTA_SET_FIELD_LEN` is a big-endian u32; each field is a nested
/// `NFTA_LIST_ELEM`.
fn concat_desc(field_lens: &[u32]) -> SetAttribute {
    use netlink_packet_core::{DefaultNla, Emitable, NLA_F_NESTED};

    const NFTA_LIST_ELEM: u16 = 1;
    const NFTA_SET_FIELD_LEN: u16 = 1;

    let mut fields = Vec::with_capacity(field_lens.len());
    for &len in field_lens {
        let mut inner = vec![0u8; 4];
        inner.copy_from_slice(&len.to_be_bytes());
        let field = DefaultNla::new(NFTA_SET_FIELD_LEN, inner);

        let mut buf = vec![0u8; field.buffer_len()];
        field.emit(&mut buf);
        fields.push(DefaultNla::new(NFTA_LIST_ELEM | NLA_F_NESTED, buf));
    }

    SetAttribute::Description(vec![SetDescription::Concat(fields)])
}

/// The set-level `KeyType`/`KeyLen` attributes, plus the concat descriptor for
/// concatenated keys.
fn key_attributes<K: Data>() -> Vec<SetAttribute> {
    let mut attrs = vec![SetAttribute::KeyType(K::TYPE), SetAttribute::KeyLen(K::LEN)];
    if K::SET_FLAGS.contains(SetFlags::Concat) {
        attrs.push(concat_desc(&K::field_lens()));
    }
    attrs
}

/// Builds the elements of an inclusive range key:
/// an empty range yields nothing, a range ending on the maximum key is open,
/// and every other range is `start..end+1`. `data` rides the start element only.
fn interval_elems(start: Vec<u8>, mut end: Vec<u8>) -> Vec<ListAttribute<SetElementAttribute>> {
    if start > end {
        return vec![];
    }

    let is_open = end.iter().all(|b| *b == u8::MAX);

    if is_open {
        vec![attr::open_interval(start)]
    } else {
        increment_be(&mut end);
        vec![attr::interval_start(start), attr::interval_end(end)]
    }
}

impl<T: Data> Elem for T {
    const SET_FLAGS: SetFlags = T::SET_FLAGS;

    fn set_attributes() -> Vec<SetAttribute> {
        key_attributes::<T>()
    }

    fn attributes(&self) -> Vec<ListAttribute<SetElementAttribute>> {
        vec![attr::key(self.elem_data())]
    }
}

impl<T: Data> Elem for RangeInclusive<T> {
    // intervals do not support concatenation
    const SET_FLAGS: SetFlags = SetFlags::Interval;

    fn set_attributes() -> Vec<SetAttribute> {
        key_attributes::<T>()
    }

    fn attributes(&self) -> Vec<ListAttribute<SetElementAttribute>> {
        interval_elems(self.start().elem_data(), self.end().elem_data())
    }
}

/// A value usable as a set/map key or map value.
///
/// `TYPE` is the nft datatype id (informational for the kernel, used for
/// display), `LEN` the wire size in bytes. Tuples concatenate their fields:
/// the type is `A::TYPE << 6 | B::TYPE` and every field is padded to a 4-byte
/// boundary, matching how nft lays concatenated keys out.
pub trait Data {
    const TYPE: u32;
    const LEN: u32;
    /// Set-level flags implied by this type (`Concat` for concatenations).
    const SET_FLAGS: SetFlags = SetFlags::empty();

    fn elem_data(&self) -> Vec<u8>;

    /// The unpadded byte length of each field, for the concat descriptor.
    /// A single entry for non-concatenated types.
    fn field_lens() -> Vec<u32> {
        vec![Self::LEN]
    }
}

/// Rounds `bytes` up to the next 4-byte boundary (netlink padding).
const fn padded(bytes: u32) -> u32 {
    bytes.div_ceil(4) * 4
}

/// Appends `bytes`, padded to a 4-byte boundary, to `out`.
fn push_padded(out: &mut Vec<u8>, bytes: impl AsRef<[u8]>) {
    out.extend_from_slice(bytes.as_ref());
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
}

impl Data for Ipv4Addr {
    const TYPE: u32 = 7; // TYPE_IPADDR
    const LEN: u32 = 4;

    fn elem_data(&self) -> Vec<u8> {
        self.octets().into()
    }
}

impl Data for Ipv6Addr {
    const TYPE: u32 = 8; // TYPE_IP6ADDR
    const LEN: u32 = 16;

    fn elem_data(&self) -> Vec<u8> {
        self.octets().into()
    }
}

impl Data for u8 {
    const TYPE: u32 = 12; // TYPE_INET_PROTOCOL
    const LEN: u32 = 1;

    fn elem_data(&self) -> Vec<u8> {
        vec![*self]
    }
}

impl Data for u16 {
    const TYPE: u32 = 13; // TYPE_INET_SERVICE
    const LEN: u32 = 2;

    fn elem_data(&self) -> Vec<u8> {
        self.to_be_bytes().into()
    }
}

impl<A: Data, B: Data> Data for (A, B) {
    const TYPE: u32 = (A::TYPE << 6) | B::TYPE;
    const LEN: u32 = padded(A::LEN) + padded(B::LEN);
    const SET_FLAGS: SetFlags = SetFlags::Concat;

    fn elem_data(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::LEN as usize);
        push_padded(&mut out, self.0.elem_data());
        push_padded(&mut out, self.1.elem_data());
        out
    }

    fn field_lens() -> Vec<u32> {
        let mut lens = A::field_lens();
        lens.extend(B::field_lens());
        lens
    }
}

impl<A: Data, B: Data, C: Data> Data for (A, B, C) {
    const TYPE: u32 = (A::TYPE << 12) | (B::TYPE << 6) | C::TYPE;
    const LEN: u32 = padded(A::LEN) + padded(B::LEN) + padded(C::LEN);
    const SET_FLAGS: SetFlags = SetFlags::Concat;

    fn elem_data(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::LEN as usize);
        push_padded(&mut out, self.0.elem_data());
        push_padded(&mut out, self.1.elem_data());
        push_padded(&mut out, self.2.elem_data());
        out
    }

    fn field_lens() -> Vec<u32> {
        let mut lens = A::field_lens();
        lens.extend(B::field_lens());
        lens.extend(C::field_lens());
        lens
    }
}

/// A map element: a key plus its data value.
pub struct MapElem<K, D>(pub K, pub D);

impl<K, D> From<(K, D)> for MapElem<K, D> {
    fn from((key, data): (K, D)) -> Self {
        Self(key, data)
    }
}

impl<K: Data, D: Data> Elem for MapElem<K, D> {
    const SET_FLAGS: SetFlags = K::SET_FLAGS.union(SetFlags::Map);

    fn set_attributes() -> Vec<SetAttribute> {
        let mut attrs = key_attributes::<K>();
        attrs.push(SetAttribute::DataType(D::TYPE));
        attrs.push(SetAttribute::DataLen(D::LEN));
        attrs
    }

    fn attributes(&self) -> Vec<ListAttribute<SetElementAttribute>> {
        vec![attr::key_with_data(
            self.0.elem_data(),
            DataAttr::Value(self.1.elem_data()),
        )]
    }
}

/// A verdict map element: a key mapping to a [`Verdict`].
pub struct VerdictElem<K>(pub K, pub Verdict);

impl<K> From<(K, Verdict)> for VerdictElem<K> {
    fn from((key, verdict): (K, Verdict)) -> Self {
        Self(key, verdict)
    }
}

impl<K: Data> Elem for VerdictElem<K> {
    const SET_FLAGS: SetFlags = K::SET_FLAGS.union(SetFlags::Map);

    fn set_attributes() -> Vec<SetAttribute> {
        let mut attrs = key_attributes::<K>();
        // the kernel derives the data length for verdicts; no DataLen
        attrs.push(SetAttribute::DataType(NFT_DATA_VERDICT));
        attrs
    }

    fn attributes(&self) -> Vec<ListAttribute<SetElementAttribute>> {
        vec![attr::key_with_data(
            self.0.elem_data(),
            DataAttr::Verdict(self.1.clone()),
        )]
    }
}

/// Adds one to a big-endian byte string, in place.
///
/// Must not be called on the maximum value (all `0xff`).
fn increment_be(bytes: &mut [u8]) {
    for byte in bytes.iter_mut().rev() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            return;
        }
    }
}

/// A named nftables set inside an `inet` table.
pub struct Set<T> {
    table: String,
    name: String,
    id: u32,
    _marker: PhantomData<T>,
}

impl<'a, T> Set<T>
where
    T: Elem,
{
    pub fn new(table: impl Into<String>, name: impl Into<String>, id: u32) -> Self {
        Self {
            table: table.into(),
            name: name.into(),
            id,
            _marker: PhantomData,
        }
    }

    pub fn create(&self) -> Message {
        new_set_msg::<T>(&self.table, &self.name, self.id)
    }

    pub fn flush(&self) -> Message {
        flush_msg(&self.table, &self.name)
    }

    /// Add (or update) every given element.
    pub fn fill<I: Iterator<Item = T>>(&self, items: I) -> impl Iterator<Item = Message> {
        fill_msgs::<T, I>(&self.table, &self.name, items)
    }

    pub fn create_flush_fill<I: Iterator<Item = T>>(
        &self,
        items: I,
    ) -> impl Iterator<Item = Message> {
        std::iter::once(self.create())
            .chain(std::iter::once(self.flush()))
            .chain(fill_msgs(&self.table, &self.name, items))
    }
}

fn new_set_msg<T>(table: &str, name: &str, id: u32) -> Message
where
    T: Elem,
{
    let mut header = NetlinkHeader::default();
    header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE;

    let mut attributes = vec![
        SetAttribute::Table(table.to_string()),
        SetAttribute::Name(name.to_string()),
        // the kernel requires an id even for named sets
        SetAttribute::Id(id),
    ];
    attributes.extend(T::set_attributes());
    if !T::SET_FLAGS.is_empty() {
        attributes.push(SetAttribute::Flags(T::SET_FLAGS));
    }

    let msg = NfTablesMessage::NewSet(SetMessage { attributes });

    NetlinkMessage::new(header, NetfilterMessage::new(nft_header(), msg).into())
}

fn flush_msg(table: &str, name: &str) -> Message {
    let mut header = NetlinkHeader::default();
    header.flags = NLM_F_REQUEST | NLM_F_ACK;

    // A `DeleteSetElement` without elements means "flush the whole set".
    let msg = NfTablesMessage::DeleteSetElement(SetElementMessage {
        attributes: vec![
            SetElementList::Table(table.to_string()),
            SetElementList::Set(name.to_string()),
        ],
    });

    NetlinkMessage::new(header, NetfilterMessage::new(nft_header(), msg).into())
}

fn fill_msgs<'a, T, I>(table: impl Into<String>, name: impl Into<String>, items: I) -> FillMsgs<I>
where
    T: Elem,
    I: Iterator<Item = T>,
{
    FillMsgs::<I> {
        table: table.into(),
        name: name.into(),
        items,
        buf: Vec::new(),
        bytes: 0,
    }
}

/// Iterator over the `NEWSETELEM` messages for a fill.
///
/// Only the message currently under construction is buffered in `buf`, with its
/// serialized size tracked in `bytes`; the allocation is recycled from one
/// message to the next. An item's elements (an interval's start and end) are
/// appended as a unit, so they never split across messages.
struct FillMsgs<I> {
    table: String,
    name: String,
    items: I,
    buf: Vec<ListAttribute<SetElementAttribute>>,
    bytes: usize,
}

impl<T, I> Iterator for FillMsgs<I>
where
    T: Elem,
    I: Iterator<Item = T>,
{
    type Item = Message;

    fn next(&mut self) -> Option<Self::Item> {
        for item in self.items.by_ref() {
            let before = self.buf.len();
            let mut added = 0;

            for attr in item.attributes() {
                added += attr.buffer_len();
                self.buf.push(attr);
            }

            if before > 0 && self.bytes + added > MAX_ELEMS_BYTES {
                // the item that overflows starts the next message
                let overflow = self.buf.split_off(before);
                let elems = std::mem::replace(&mut self.buf, overflow);
                self.bytes = added;
                return Some(elem_msg(&self.table, &self.name, elems));
            }

            self.bytes += added;
        }

        // items exhausted: emit the remaining message, if any
        if !self.buf.is_empty() {
            self.bytes = 0;
            return Some(elem_msg(
                &self.table,
                &self.name,
                std::mem::take(&mut self.buf),
            ));
        }

        None
    }
}

fn elem_msg(table: &str, name: &str, elements: Vec<ListAttribute<SetElementAttribute>>) -> Message {
    let mut header = NetlinkHeader::default();
    // No NLM_F_EXCL: adding an existing element updates it.
    header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE;

    let msg = NfTablesMessage::NewSetElement(SetElementMessage {
        attributes: vec![
            SetElementList::Table(table.to_string()),
            SetElementList::Set(name.to_string()),
            SetElementList::Elements(elements),
        ],
    });

    NetlinkMessage::new(header, NetfilterMessage::new(nft_header(), msg).into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use netlink_packet_core::NetlinkPayload;
    use netlink_packet_netfilter::{
        NetfilterMessageInner,
        nftables::{DataAttribute, SetElementFlags, VerdictAttribute},
    };

    /// `(key, flags, is_open)` for every element produced by `items`.
    fn parts<T>(items: impl IntoIterator<Item = T>) -> Vec<(Vec<u8>, SetElementFlags, bool)>
    where
        T: Elem,
    {
        let mut out = Vec::new();
        for msg in fill_msgs::<T, _>("t", "s", items.into_iter()) {
            let NetlinkPayload::InnerMessage(NetfilterMessage {
                inner: NetfilterMessageInner::NfTables(NfTablesMessage::NewSetElement(m)),
                ..
            }) = msg.payload
            else {
                panic!("not a NewSetElement message");
            };

            let elems = m
                .attributes
                .iter()
                .find_map(|a| match a {
                    SetElementList::Elements(e) => Some(e),
                    _ => None,
                })
                .expect("elements");

            for item in elems {
                let ListAttribute::Element(attrs) = item else {
                    continue;
                };
                let mut key = None;
                let mut flags = SetElementFlags::empty();
                let mut open = false;
                for attr in attrs {
                    match attr {
                        SetElementAttribute::Key(DataAttribute::Value(v)) => key = Some(v.clone()),
                        SetElementAttribute::Flags(f) => flags = *f,
                        // the userdata TLV is [type][len][u32 value]
                        SetElementAttribute::UserData(u) if u.first() == Some(&1) => {
                            open = u[2..] == 1u32.to_ne_bytes();
                        }
                        _ => {}
                    }
                }
                out.push((key.expect("key"), flags, open));
            }
        }
        out
    }

    fn new_set_attrs<T>() -> Vec<SetAttribute>
    where
        T: Elem,
    {
        let msg = new_set_msg::<T>("t", "s", 1);
        let NetlinkPayload::InnerMessage(NetfilterMessage {
            inner: NetfilterMessageInner::NfTables(NfTablesMessage::NewSet(m)),
            ..
        }) = msg.payload
        else {
            panic!("not a NewSet message");
        };
        m.attributes
    }

    fn get_u32(attrs: &[SetAttribute], f: impl Fn(&SetAttribute) -> Option<u32>) -> Option<u32> {
        attrs.iter().find_map(f)
    }

    #[test]
    fn increment_be_wraps() {
        let mut b = [0x00, 0x00, 0xff];
        increment_be(&mut b);
        assert_eq!(b, [0x00, 0x01, 0x00]);

        let mut b = [0x00, 0x00, 0x00];
        increment_be(&mut b);
        assert_eq!(b, [0x00, 0x00, 0x01]);
    }

    #[test]
    fn simple_set_key_type_and_len() {
        let attrs = new_set_attrs::<Ipv4Addr>();
        assert_eq!(
            get_u32(&attrs, |a| match a {
                SetAttribute::KeyType(t) => Some(*t),
                _ => None,
            }),
            Some(7)
        );
        assert_eq!(
            get_u32(&attrs, |a| match a {
                SetAttribute::KeyLen(l) => Some(*l),
                _ => None,
            }),
            Some(4)
        );
        assert!(!attrs.iter().any(|a| matches!(a, SetAttribute::Flags(_))));

        let attrs = new_set_attrs::<Ipv6Addr>();
        assert_eq!(
            get_u32(&attrs, |a| match a {
                SetAttribute::KeyType(t) => Some(*t),
                _ => None,
            }),
            Some(8)
        );
        assert_eq!(
            get_u32(&attrs, |a| match a {
                SetAttribute::KeyLen(l) => Some(*l),
                _ => None,
            }),
            Some(16)
        );
    }

    #[test]
    fn concat_type_len_and_desc() {
        // ipv4_addr . inet_proto . inet_service
        let attrs = new_set_attrs::<(Ipv4Addr, u8, u16)>();
        assert_eq!(
            get_u32(&attrs, |a| match a {
                SetAttribute::KeyType(t) => Some(*t),
                _ => None,
            }),
            Some((7 << 12) | (12 << 6) | 13)
        );
        assert_eq!(
            get_u32(&attrs, |a| match a {
                SetAttribute::KeyLen(l) => Some(*l),
                _ => None,
            }),
            Some(4 + 4 + 4) // each field padded to 4 bytes
        );

        // concat descriptor: one NFTA_LIST_ELEM per field, each with the
        // unpadded length
        let desc = attrs.iter().find_map(|a| match a {
            SetAttribute::Description(d) => Some(d),
            _ => None,
        });
        let concat = desc
            .and_then(|d| {
                d.iter().find_map(|s| match s {
                    SetDescription::Concat(fields) => Some(fields),
                    _ => None,
                })
            })
            .expect("a concat descriptor");
        // the `NFT_SET_CONCAT` flag is set
        assert!(
            attrs
                .iter()
                .any(|a| matches!(a, SetAttribute::Flags(f) if f.contains(SetFlags::Concat)))
        );

        let lens: Vec<u32> = concat
            .iter()
            .map(|f| {
                // NFTA_LIST_ELEM (outer nla header 4) nests a single
                // NFTA_SET_FIELD_LEN (inner nla header 4, then be32 value)
                let mut buf = vec![0u8; f.buffer_len()];
                f.emit(&mut buf);
                u32::from_be_bytes(buf[8..12].try_into().expect("4 bytes"))
            })
            .collect();
        assert_eq!(lens, vec![4, 1, 2]);
    }

    #[test]
    fn concat_elem_data_is_padded() {
        let data = (Ipv4Addr::new(10, 0, 0, 1), 6u8, 53u16).elem_data();
        assert_eq!(data, vec![10, 0, 0, 1, 6, 0, 0, 0, 0, 53, 0, 0]);
    }

    #[test]
    fn interval_set_has_interval_flag() {
        let attrs = new_set_attrs::<RangeInclusive<Ipv4Addr>>();
        assert!(
            attrs
                .iter()
                .any(|a| matches!(a, SetAttribute::Flags(f) if *f == SetFlags::Interval))
        );
        // key type/len come from the underlying address
        assert_eq!(
            get_u32(&attrs, |a| match a {
                SetAttribute::KeyType(t) => Some(*t),
                _ => None,
            }),
            Some(7)
        );
        assert_eq!(
            get_u32(&attrs, |a| match a {
                SetAttribute::KeyLen(l) => Some(*l),
                _ => None,
            }),
            Some(4)
        );
    }

    #[test]
    fn simple_elements_have_no_flags() {
        let elems = parts::<Ipv4Addr>([Ipv4Addr::new(10, 0, 0, 1)]);
        assert_eq!(
            elems,
            vec![(vec![10, 0, 0, 1], SetElementFlags::empty(), false)]
        );
    }

    /// Extracts the `(key, data)` attributes of the first element produced.
    fn key_and_data(item: &impl Elem) -> (Vec<u8>, Option<Vec<u8>>) {
        let (_, attrs) = match item.attributes().into_iter().next().expect("one element") {
            ListAttribute::Element(attrs) => ((), attrs),
            _ => panic!("not an Element"),
        };

        let mut key = None;
        let mut data = None;
        for attr in attrs {
            match attr {
                SetElementAttribute::Key(DataAttribute::Value(v)) => key = Some(v),
                SetElementAttribute::Data(DataAttribute::Value(v)) => data = Some(v),
                _ => {}
            }
        }
        (key.expect("key"), data)
    }

    #[test]
    fn map_set_has_key_and_data_types() {
        let attrs = new_set_attrs::<MapElem<Ipv4Addr, u16>>();
        let get = |f: fn(&SetAttribute) -> Option<u32>| get_u32(&attrs, f);
        assert_eq!(
            get(|a| match a {
                SetAttribute::KeyType(t) => Some(*t),
                _ => None,
            }),
            Some(7)
        );
        assert_eq!(
            get(|a| match a {
                SetAttribute::KeyLen(l) => Some(*l),
                _ => None,
            }),
            Some(4)
        );
        assert_eq!(
            get(|a| match a {
                SetAttribute::DataType(t) => Some(*t),
                _ => None,
            }),
            Some(13)
        );
        assert_eq!(
            get(|a| match a {
                SetAttribute::DataLen(l) => Some(*l),
                _ => None,
            }),
            Some(2)
        );
        assert!(
            attrs
                .iter()
                .any(|a| matches!(a, SetAttribute::Flags(f) if *f == SetFlags::Map))
        );
    }

    #[test]
    fn map_key_carries_data() {
        // built from a tuple via `From`
        let elem = MapElem::from((Ipv4Addr::new(10, 0, 0, 1), 8080u16));
        let (key, data) = key_and_data(&elem);
        assert_eq!(key, [10, 0, 0, 1]);
        assert_eq!(data.as_deref(), Some(&8080u16.to_be_bytes()[..]));

        // a plain key has no Data attribute
        let (_, data) = key_and_data(&Ipv4Addr::new(10, 0, 0, 1));
        assert!(data.is_none());
    }

    #[test]
    fn verdict_map_data_types() {
        let attrs = new_set_attrs::<VerdictElem<Ipv4Addr>>();
        let get = |f: fn(&SetAttribute) -> Option<u32>| get_u32(&attrs, f);
        assert_eq!(
            get(|a| match a {
                SetAttribute::KeyType(t) => Some(*t),
                _ => None,
            }),
            Some(7)
        );
        assert_eq!(
            get(|a| match a {
                SetAttribute::KeyLen(l) => Some(*l),
                _ => None,
            }),
            Some(4)
        );
        assert_eq!(
            get(|a| match a {
                SetAttribute::DataType(t) => Some(*t),
                _ => None,
            }),
            Some(0xffffff00)
        );
        // verdicts carry no DataLen
        assert!(!attrs.iter().any(|a| matches!(a, SetAttribute::DataLen(_))));
        assert!(
            attrs
                .iter()
                .any(|a| matches!(a, SetAttribute::Flags(f) if *f == SetFlags::Map))
        );
    }

    /// The nested verdict attributes of the first element produced.
    fn verdict_attrs(elem: &impl Elem) -> Vec<VerdictAttribute> {
        let (_, attrs) = match elem.attributes().into_iter().next().expect("one element") {
            ListAttribute::Element(attrs) => ((), attrs),
            _ => panic!("not an Element"),
        };
        attrs
            .iter()
            .find_map(|a| match a {
                SetElementAttribute::Data(DataAttribute::Verdict(v)) => Some(v.clone()),
                _ => None,
            })
            .expect("a verdict Data attribute")
    }

    #[test]
    fn verdict_goto_carries_chain() {
        let elem =
            VerdictElem::from((Ipv4Addr::new(10, 0, 0, 1), Verdict::Goto("my_chain".into())));
        assert_eq!(
            verdict_attrs(&elem),
            vec![
                VerdictAttribute::Code(NlVerdict::Goto),
                VerdictAttribute::Chain("my_chain".into()),
            ]
        );

        let elem = VerdictElem::from((Ipv4Addr::new(10, 0, 0, 1), Verdict::Jump("jmp".into())));
        assert_eq!(
            verdict_attrs(&elem),
            vec![
                VerdictAttribute::Code(NlVerdict::Jump),
                VerdictAttribute::Chain("jmp".into()),
            ]
        );
    }

    #[test]
    fn verdict_simple_has_no_chain() {
        let elem = VerdictElem::from((Ipv4Addr::new(10, 0, 0, 1), Verdict::Accept));
        assert_eq!(
            verdict_attrs(&elem),
            vec![VerdictAttribute::Code(NlVerdict::Other(1))] // NF_ACCEPT
        );
    }

    #[test]
    fn interval_is_start_and_exclusive_end() {
        // inclusive 10.0.0.0-10.0.0.10 is stored as start + (end + 1, END)
        let elems = parts::<RangeInclusive<Ipv4Addr>>([
            Ipv4Addr::new(10, 0, 0, 0)..=Ipv4Addr::new(10, 0, 0, 10)
        ]);
        assert_eq!(
            elems,
            vec![
                (vec![10, 0, 0, 0], SetElementFlags::empty(), false),
                (vec![10, 0, 0, 11], SetElementFlags::IntervalEnd, false),
            ]
        );
    }

    #[test]
    fn interval_single_point() {
        let elems = parts::<RangeInclusive<Ipv4Addr>>([
            Ipv4Addr::new(10, 0, 0, 5)..=Ipv4Addr::new(10, 0, 0, 5)
        ]);
        assert_eq!(
            elems,
            vec![
                (vec![10, 0, 0, 5], SetElementFlags::empty(), false),
                (vec![10, 0, 0, 6], SetElementFlags::IntervalEnd, false),
            ]
        );
    }

    #[test]
    fn interval_open_has_no_end() {
        let elems =
            parts::<RangeInclusive<Ipv4Addr>>([Ipv4Addr::new(20, 0, 0, 0)..=Ipv4Addr::BROADCAST]);
        assert_eq!(
            elems,
            vec![(vec![20, 0, 0, 0], SetElementFlags::empty(), true)]
        );
    }

    #[test]
    fn interval_empty_is_skipped() {
        let elems = parts::<RangeInclusive<Ipv4Addr>>([
            Ipv4Addr::new(10, 0, 0, 5)..=Ipv4Addr::new(10, 0, 0, 4)
        ]);
        assert!(elems.is_empty());
    }

    #[test]
    fn empty_fill_has_no_messages() {
        assert_eq!(
            fill_msgs::<Ipv4Addr, _>("t", "s", Vec::new().into_iter()).count(),
            0
        );
        assert_eq!(
            fill_msgs::<RangeInclusive<Ipv4Addr>, _>("t", "s", Vec::new().into_iter()).count(),
            0
        );
    }

    fn v4_keys(n: u32) -> Vec<Ipv4Addr> {
        (0..n).map(|i| Ipv4Addr::from(0x0a00_0000 + i)).collect()
    }

    #[test]
    fn fill_splits_at_16_bits() {
        // enough v4 elements that the `NFTA_SET_ELEM_LIST_ELEMENTS` nest must
        // be split across several messages
        let msgs: Vec<_> =
            fill_msgs::<Ipv4Addr, _>("t", "s", v4_keys(10_000).into_iter()).collect();
        assert!(msgs.len() >= 2, "expected multiple element messages");

        let total: usize = msgs
            .iter()
            .map(|msg| match &msg.payload {
                NetlinkPayload::InnerMessage(NetfilterMessage {
                    inner: NetfilterMessageInner::NfTables(NfTablesMessage::NewSetElement(m)),
                    ..
                }) => m
                    .attributes
                    .iter()
                    .find_map(|a| match a {
                        SetElementList::Elements(e) => Some(e.len()),
                        _ => None,
                    })
                    .unwrap_or(0),
                _ => 0,
            })
            .sum();
        assert_eq!(total, 10_000);
    }

    #[test]
    fn interval_pairs_are_not_split_across_messages() {
        // each range is two elements; force a split by using many ranges
        let ranges = (0..10_000u32).map(|i| {
            let base = i << 8;
            Ipv4Addr::from(base)..=Ipv4Addr::from(base | 0x7f)
        });
        let msgs: Vec<_> = fill_msgs::<RangeInclusive<Ipv4Addr>, _>("t", "s", ranges).collect();

        for msg in &msgs {
            let NetlinkPayload::InnerMessage(NetfilterMessage {
                inner: NetfilterMessageInner::NfTables(NfTablesMessage::NewSetElement(m)),
                ..
            }) = &msg.payload
            else {
                panic!("not a NewSetElement message");
            };

            let elems = m
                .attributes
                .iter()
                .find_map(|a| match a {
                    SetElementList::Elements(e) => Some(e),
                    _ => None,
                })
                .expect("elements");

            let mut pending_start = false;
            for item in elems {
                let ListAttribute::Element(attrs) = item else {
                    continue;
                };
                let is_end = attrs.iter().any(
                    |a| matches!(a, SetElementAttribute::Flags(f) if f.contains(SetElementFlags::IntervalEnd)),
                );
                if is_end {
                    assert!(pending_start, "interval end without its start");
                    pending_start = false;
                } else {
                    pending_start = true;
                }
            }
            assert!(!pending_start, "message ends on a dangling interval start");
        }
    }

    #[test]
    fn element_message_roundtrips() {
        let mut msg =
            fill_msgs::<Ipv4Addr, _>("tbl", "set", [Ipv4Addr::new(10, 0, 0, 1)].into_iter())
                .next()
                .expect("one message");
        msg.finalize();

        let mut buf = vec![0; msg.buffer_len()];
        msg.serialize(&mut buf);

        let parsed = NetlinkMessage::<NetfilterMessage>::deserialize(&buf).expect("parse back");
        assert_eq!(parsed.payload, msg.payload);
        assert_eq!(parsed.header.message_type, msg.header.message_type);
    }
}
