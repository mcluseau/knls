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
    collections::BTreeSet,
    marker::PhantomData,
    net::{Ipv4Addr, Ipv6Addr},
    ops::RangeInclusive,
};

use super::{Message, nft_header};

/// A named set of single keys.
pub type SimpleSet<'t, T> = Set<'t, T>;

/// A named set of intervals over keys of type `T`. `fill` takes inclusive
/// `RangeInclusive<T>`.
pub type IntervalSet<'t, T> = Set<'t, RangeInclusive<T>>;

/// A named map from key type `K` to data type `D`.
pub type MapSet<'t, K, D> = Set<'t, MapElem<K, D>>;

/// A named map from key type `K` to verdicts of value type `V`.
pub type VerdictMapSet<'t, K> = Set<'t, VerdictElem<K>>;

/// Maximum size of the `NFTA_SET_ELEM_LIST_ELEMENTS` attribute payload.
///
/// `nlattr.nla_len` is 16-bit and includes the 4-byte header, so the payload
/// itself must stay below `u16::MAX - 4`.
const MAX_ELEMS_BYTES: usize = u16::MAX as usize - 4;

/// `NFT_DATA_VERDICT`: data type of map values that are verdicts.
const NFT_DATA_VERDICT: u32 = 0xffffff00;

/// A verdict map value.
///
/// `Ord` is derived so a [`BTreeMap`] of raw keys can hold a verdict as its
/// value (see [`table_sync`](super::table_sync)).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
    use netlink_packet_core::DefaultNla;
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

    /// A concatenated-key interval (`KEY` start + `KEY_END` inclusive end), as
    /// nft emits it. The kernel rejects the `IntervalEnd` pair form for
    /// concatenations.
    pub(super) fn interval_range(
        start: Vec<u8>,
        end: Vec<u8>,
    ) -> ListAttribute<SetElementAttribute> {
        const NFTA_DATA_VALUE: u16 = 1;
        let mut attrs = elem_key(start, None);
        attrs.push(SetElementAttribute::KeyEnd(vec![DefaultNla::new(
            NFTA_DATA_VALUE,
            end,
        )]));
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

/// Builds the elements of an inclusive range key.
///
/// A scalar key uses the `start` + `IntervalEnd(start..=end+1)` pair, or an open
/// interval when the end is the field maximum. A concatenated key, which the
/// kernel requires in a different shape, uses a single element with an inclusive
/// `KEY_END`. Empty ranges yield nothing.
fn interval_elems(
    start: Vec<u8>,
    end: Vec<u8>,
    concat: bool,
) -> Vec<ListAttribute<SetElementAttribute>> {
    if start > end {
        return vec![];
    }

    if concat {
        // inclusive end, as nft stores concatenation ranges
        return vec![attr::interval_range(start, end)];
    }

    let is_open = end.iter().all(|b| *b == u8::MAX);
    if is_open {
        vec![attr::open_interval(start)]
    } else {
        let mut end = end;
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
    // intervals of concatenated keys keep the `Concat` flag of the key type
    const SET_FLAGS: SetFlags = T::SET_FLAGS.union(SetFlags::Interval);

    fn set_attributes() -> Vec<SetAttribute> {
        key_attributes::<T>()
    }

    fn attributes(&self) -> Vec<ListAttribute<SetElementAttribute>> {
        let concat = T::SET_FLAGS.contains(SetFlags::Concat);
        interval_elems(self.start().elem_data(), self.end().elem_data(), concat)
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

impl Data for u32 {
    const TYPE: u32 = 19; // TYPE_MARK
    const LEN: u32 = 4;

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

/// Builds [`Set`]s inside one table, handing out unique ids.
pub struct Builder<'t> {
    table: &'t str,
    id: u32,
}

impl<'t> Builder<'t> {
    /// A builder for sets of `table`, assigning each a unique id.
    pub fn new(table: &'t str) -> Self {
        Self { table, id: 0 }
    }

    /// Builds the `Set` named `name` with the next id.
    pub fn build<T: Elem>(&mut self, name: impl Into<String>) -> Set<'t, T> {
        self.id += 1;
        Set {
            table: self.table,
            name: name.into(),
            id: self.id,
            _marker: PhantomData,
        }
    }

    /// Builds a [`SimpleSet`] named `name`.
    pub fn build_simple<K: Data>(&mut self, name: impl Into<String>) -> SimpleSet<'t, K> {
        self.build(name)
    }

    /// Builds an [`IntervalSet`] named `name`.
    pub fn build_interval<K: Data>(&mut self, name: impl Into<String>) -> IntervalSet<'t, K> {
        self.build(name)
    }

    /// Builds a [`MapSet`] named `name`.
    pub fn build_map<K: Data, D: Data>(&mut self, name: impl Into<String>) -> MapSet<'t, K, D> {
        self.build(name)
    }

    /// Builds a [`VerdictMapSet`] named `name`.
    pub fn build_verdict_map<K: Data>(&mut self, name: impl Into<String>) -> VerdictMapSet<'t, K> {
        self.build(name)
    }
}

/// A named nftables set inside an `inet` table.
pub struct Set<'t, T> {
    table: &'t str,
    name: String,
    id: u32,
    _marker: PhantomData<T>,
}

impl<'t, T> Set<'t, T>
where
    T: Elem,
{
    pub fn new(table: &'t str, name: impl Into<String>, id: u32) -> Self {
        Self {
            table,
            name: name.into(),
            id,
            _marker: PhantomData,
        }
    }

    pub fn id(&self) -> u32 {
        self.id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Creates the set.
    ///
    /// `comment` is an optional free-form string, attached as nftables userdata
    /// so it shows up in `nft list`.
    pub fn create(&self, comment: Option<String>) -> Message {
        self.create_with(T::SET_FLAGS, comment)
    }

    /// Creates the set as **anonymous** (`NFT_SET_ANONYMOUS`).
    ///
    /// The kernel binds an anonymous set to a single rule and nft prints it
    /// inline (`{ tcp . 80, tcp . 443 }`) rather than as a named `@set`. The set
    /// must be created and filled before the rule referencing it.
    pub fn create_anonymous(&self) -> Message {
        self.create_with(T::SET_FLAGS | SetFlags::Anonymous, None)
    }

    fn create_with(&self, flags: SetFlags, comment: Option<String>) -> Message {
        Raw {
            table: self.table,
            name: self.name.clone(),
            id: self.id,
            flags,
            attributes: &T::set_attributes(),
            comment: comment.as_deref(),
        }
        .create()
    }

    pub fn flush(&self) -> Message {
        let mut header = NetlinkHeader::default();
        header.flags = NLM_F_REQUEST | NLM_F_ACK;

        // A `DeleteSetElement` without elements means "flush the whole set".
        let msg = NfTablesMessage::DeleteSetElement(SetElementMessage {
            attributes: vec![
                SetElementList::Table(self.table.to_string()),
                SetElementList::Set(self.name.clone()),
            ],
        });

        NetlinkMessage::new(header, NetfilterMessage::new(nft_header(), msg).into())
    }

    /// Add (or update) every given element.
    pub fn fill<I: Iterator<Item = T>>(
        &self,
        items: I,
    ) -> impl Iterator<Item = Message> + use<'_, 't, I, T> {
        fill_msgs(self.table, &self.name, items)
    }

    pub fn create_flush_fill<I: Iterator<Item = T>>(
        &self,
        comment: Option<String>,
        items: I,
    ) -> impl Iterator<Item = Message> + use<'_, 't, I, T> {
        std::iter::once(self.create(comment))
            .chain(std::iter::once(self.flush()))
            .chain(fill_msgs::<T, I>(self.table, &self.name, items))
    }
}

/// The `NFTA_SET_ELEM_*` attributes of one set element, already encoded in the
/// canonical kernel form.
///
/// An interval's start and end are one group, treated as an atomic block by the
/// fill/delete iterators so they never split across messages.
#[derive(Clone, Debug)]
pub struct Element(Vec<ListAttribute<SetElementAttribute>>);

impl Element {
    /// A simple-set key.
    pub fn key(key: Vec<u8>) -> Self {
        Self(vec![attr::key(key)])
    }

    /// A map entry: key → plain value.
    pub fn map_entry(key: Vec<u8>, value: Vec<u8>) -> Self {
        Self(vec![attr::key_with_data(key, DataAttr::Value(value))])
    }

    /// A verdict-map entry: key → verdict.
    pub fn verdict_entry(key: Vec<u8>, verdict: Verdict) -> Self {
        Self(vec![attr::key_with_data(key, DataAttr::Verdict(verdict))])
    }

    /// An inclusive `start..=end` interval (`concat` selects the concatenated
    /// `KEY_END` form). Empty ranges yield an empty group.
    pub fn interval(start: Vec<u8>, end: Vec<u8>, concat: bool) -> Self {
        Self(interval_elems(start, end, concat))
    }
}

/// A named set/map with pre-encoded metadata and element bytes, as stored in a
/// [`TableSync`](super::table_sync::TableSync).
///
/// Unlike [`Set`], the key/data type is erased to raw [`SetAttribute`]s, so the
/// same set can be created and diffed without knowing its nft type.
pub struct Raw<'t> {
    /// The table the set lives in.
    pub table: &'t str,
    /// The set's name.
    pub name: String,
    /// The set id, only meaningful within one netlink transaction.
    pub id: u32,
    /// The set-level flags.
    pub flags: SetFlags,
    /// The `NFTA_SET_*` attributes minus table/name/id and flags, as
    /// [`Elem::set_attributes`] returns them.
    pub attributes: &'t [SetAttribute],
    /// Optional `NFTA_SET_USERDATA` comment.
    pub comment: Option<&'t str>,
}

impl<'t> Raw<'t> {
    /// The `NewSet` message creating the set.
    ///
    /// Created with `NLM_F_CREATE` (no `EXCL`), so re-issuing it updates the
    /// metadata (e.g. the comment) in place without dropping its elements.
    pub fn create(&self) -> Message {
        let mut header = NetlinkHeader::default();
        header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE;

        let mut attrs = vec![
            SetAttribute::Table(self.table.to_string()),
            SetAttribute::Name(self.name.clone()),
            // the kernel requires an id even for named sets
            SetAttribute::Id(self.id),
        ];
        attrs.extend_from_slice(self.attributes);
        if !self.flags.is_empty() {
            attrs.push(SetAttribute::Flags(self.flags));
        }
        if let Some(comment) = self.comment {
            attrs.push(SetAttribute::UserData(set_comment(comment)));
        }

        let msg = NfTablesMessage::NewSet(SetMessage { attributes: attrs });

        NetlinkMessage::new(header, NetfilterMessage::new(nft_header(), msg).into())
    }

    /// The message deleting the set.
    pub fn delete(&self) -> Message {
        delete(self.table, &self.name)
    }

    /// The messages adding `items` to the set, batched.
    pub fn fill<I>(&self, items: I) -> impl Iterator<Item = Message> + use<'_, 't, I>
    where
        I: Iterator<Item = Element>,
    {
        raw_elems(self.table, &self.name, false, items)
    }

    /// The messages removing `items` from the set, batched.
    pub fn delete_elems<I>(&self, items: I) -> impl Iterator<Item = Message> + use<'_, 't, I>
    where
        I: Iterator<Item = Element>,
    {
        raw_elems(self.table, &self.name, true, items)
    }
}

/// Deletes the named set `name` in `table`.
pub fn delete(table: &str, name: &str) -> Message {
    let mut header = NetlinkHeader::default();
    header.flags = NLM_F_REQUEST | NLM_F_ACK;

    let msg = NfTablesMessage::DeleteSet(SetMessage {
        attributes: vec![
            SetAttribute::Table(table.to_string()),
            SetAttribute::Name(name.to_string()),
        ],
    });

    NetlinkMessage::new(header, NetfilterMessage::new(nft_header(), msg).into())
}

/// Batches `items` (each an atomic element group) into add/delete messages.
fn raw_elems<'a, I>(
    table: &'a str,
    name: &'a str,
    delete: bool,
    items: I,
) -> impl Iterator<Item = Message> + use<'a, I>
where
    I: Iterator<Item = Element>,
{
    ElemMsgs {
        table,
        name,
        delete,
        items: items.map(|element| element.0),
        buf: Vec::new(),
        bytes: 0,
    }
}

/// `NFTNL_UDATA_SET_COMMENT`: nft's userdata type for a set comment.
const UDATA_SET_COMMENT: u8 = 7;

/// Encodes `comment` as nft's userdata for `NFTA_SET_USERDATA`: a TLV of
/// `[type: u8][len: u8][string with trailing NUL]`, as `nftnl_udata_put_strz`
/// writes it.
fn set_comment(comment: &str) -> Vec<u8> {
    let bytes = comment.as_bytes();
    let mut udata = Vec::with_capacity(bytes.len() + 3);
    udata.push(UDATA_SET_COMMENT);
    udata.push((bytes.len() + 1) as u8);
    udata.extend_from_slice(bytes);
    udata.push(0); // strz
    udata
}

fn fill_msgs<'a, T, I>(
    table: &'a str,
    name: &'a str,
    items: I,
) -> impl Iterator<Item = Message> + use<'a, T, I>
where
    T: Elem,
    I: Iterator<Item = T>,
{
    ElemMsgs {
        table,
        name,
        delete: false,
        items: items.map(|item| item.attributes()),
        buf: Vec::new(),
        bytes: 0,
    }
}

/// The messages bringing the set from `orig` to `target`: every element of
/// `orig` that is missing from `target` is deleted first, then every element of
/// `target` that was missing from `orig` is added.
///
/// Each blob is a canonical element key (as produced by
/// [`Data::elem_data`], or read from the kernel), so a plain set is diffed with
/// [`BTreeSet`]s of those blobs. Creating the set itself is done separately by
/// [`Set::create`].
pub fn sync_raw_set<'a, T: Elem>(
    set: &'a Set<'a, T>,
    orig: &'a BTreeSet<Vec<u8>>,
    target: &'a BTreeSet<Vec<u8>>,
) -> impl Iterator<Item = Message> + use<'a, T> {
    let delete = ElemMsgs {
        table: set.table,
        name: &set.name,
        delete: true,
        items: orig
            .difference(target)
            .map(|key| vec![attr::key(key.clone())]),
        buf: Vec::new(),
        bytes: 0,
    };

    let add = ElemMsgs {
        table: set.table,
        name: &set.name,
        delete: false,
        items: target
            .difference(orig)
            .map(|key| vec![attr::key(key.clone())]),
        buf: Vec::new(),
        bytes: 0,
    };

    delete.chain(add)
}

/// Iterator over the `NEWSETELEM`/`DELSETELEM` messages for a batch of elements.
///
/// Only the message currently under construction is buffered in `buf`, with its
/// serialized size tracked in `bytes`; the allocation is recycled from one
/// message to the next. An item's elements (an interval's start and end) are
/// appended as a unit, so they never split across messages.
struct ElemMsgs<'t, I> {
    table: &'t str,
    name: &'t str,
    delete: bool,
    /// Per-element attributes (an interval yields two elements as a unit).
    items: I,
    buf: Vec<ListAttribute<SetElementAttribute>>,
    bytes: usize,
}

impl<'t, I> Iterator for ElemMsgs<'t, I>
where
    I: Iterator<Item = Vec<ListAttribute<SetElementAttribute>>>,
{
    type Item = Message;

    fn next(&mut self) -> Option<Self::Item> {
        for attrs in self.items.by_ref() {
            let before = self.buf.len();
            let mut added = 0;

            for attr in attrs {
                added += attr.buffer_len();
                self.buf.push(attr);
            }

            if before > 0 && self.bytes + added > MAX_ELEMS_BYTES {
                // the item that overflows starts the next message
                let overflow = self.buf.split_off(before);
                let elems = std::mem::replace(&mut self.buf, overflow);
                self.bytes = added;
                return Some(elem_msg(self.table, self.name, elems, self.delete));
            }

            self.bytes += added;
        }

        // items exhausted: emit the remaining message, if any
        if !self.buf.is_empty() {
            self.bytes = 0;
            return Some(elem_msg(
                self.table,
                self.name,
                std::mem::take(&mut self.buf),
                self.delete,
            ));
        }

        None
    }
}

fn elem_msg(
    table: &str,
    name: &str,
    elements: Vec<ListAttribute<SetElementAttribute>>,
    delete: bool,
) -> Message {
    let mut header = NetlinkHeader::default();
    // No NLM_F_EXCL: adding an existing element updates it.
    header.flags = if delete {
        NLM_F_REQUEST | NLM_F_ACK
    } else {
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE
    };

    let message = SetElementMessage {
        attributes: vec![
            SetElementList::Table(table.to_string()),
            SetElementList::Set(name.to_string()),
            SetElementList::Elements(elements),
        ],
    };

    let msg = if delete {
        NfTablesMessage::DeleteSetElement(message)
    } else {
        NfTablesMessage::NewSetElement(message)
    };

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

    /// A set for tests: table `t`, name `s`.
    fn test_set<T: Elem>() -> Set<'static, T> {
        Set::new("t", "s", 1)
    }

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
        let msg = test_set::<T>().create(None);
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

    /// A concatenated interval is a single element with an inclusive `KEY_END`,
    /// not the scalar start/end pair.
    fn concat_interval_keys(
        items: impl IntoIterator<Item = RangeInclusive<(u8, u16)>>,
    ) -> Vec<(Vec<u8>, Option<Vec<u8>>)> {
        let mut out = Vec::new();
        for msg in fill_msgs::<RangeInclusive<(u8, u16)>, _>("t", "s", items.into_iter()) {
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
                let mut end = None;
                for attr in attrs {
                    match attr {
                        SetElementAttribute::Key(DataAttribute::Value(v)) => key = Some(v.clone()),
                        SetElementAttribute::KeyEnd(nlas) => {
                            use netlink_packet_core::Nla;
                            let n = nlas.first().expect("data value");
                            let mut buf = vec![0u8; n.value_len()];
                            n.emit_value(&mut buf);
                            end = Some(buf);
                        }
                        _ => {}
                    }
                }
                out.push((key.expect("key"), end));
            }
        }
        out
    }

    #[test]
    fn concat_interval_uses_key_end() {
        // tcp . 80-90 : start (tcp,80), inclusive KEY_END (tcp,90)
        let elems = concat_interval_keys([(6u8, 80u16)..=(6, 90)]);
        assert_eq!(elems.len(), 1, "one element, not a start/end pair");
        let (key, end) = &elems[0];
        assert_eq!(key, &vec![6, 0, 0, 0, 0, 80, 0, 0]);
        assert_eq!(
            end.as_deref(),
            Some(&[6, 0, 0, 0, 0, 90, 0, 0][..]),
            "inclusive end"
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
        let mut msg = fill_msgs::<Ipv4Addr, _>("t", "s", [Ipv4Addr::new(10, 0, 0, 1)].into_iter())
            .next()
            .expect("one message");
        msg.finalize();

        let mut buf = vec![0; msg.buffer_len()];
        msg.serialize(&mut buf);

        let parsed = NetlinkMessage::<NetfilterMessage>::deserialize(&buf).expect("parse back");
        assert_eq!(parsed.payload, msg.payload);
        assert_eq!(parsed.header.message_type, msg.header.message_type);
    }

    /// `(is_delete, keys)` of a set element message.
    fn classify(msg: &Message) -> (bool, Vec<Vec<u8>>) {
        let (delete, m) = match &msg.payload {
            NetlinkPayload::InnerMessage(NetfilterMessage {
                inner: NetfilterMessageInner::NfTables(NfTablesMessage::DeleteSetElement(m)),
                ..
            }) => (true, m),
            NetlinkPayload::InnerMessage(NetfilterMessage {
                inner: NetfilterMessageInner::NfTables(NfTablesMessage::NewSetElement(m)),
                ..
            }) => (false, m),
            _ => panic!("not a set element message"),
        };

        let keys = m
            .attributes
            .iter()
            .find_map(|a| match a {
                SetElementList::Elements(e) => Some(e),
                _ => None,
            })
            .expect("elements")
            .iter()
            .filter_map(|item| match item {
                ListAttribute::Element(attrs) => attrs.iter().find_map(|a| match a {
                    SetElementAttribute::Key(DataAttribute::Value(v)) => Some(v.clone()),
                    _ => None,
                }),
                _ => None,
            })
            .collect();

        (delete, keys)
    }

    fn v4(n: u8) -> Vec<u8> {
        Ipv4Addr::new(10, 0, 0, n).elem_data()
    }

    #[test]
    fn sync_deletes_then_adds() {
        let orig: BTreeSet<_> = [v4(1), v4(2), v4(3)].into_iter().collect();
        let target: BTreeSet<_> = [v4(2), v4(3), v4(4)].into_iter().collect();

        let msgs: Vec<_> = sync_raw_set(&test_set::<Ipv4Addr>(), &orig, &target).collect();
        // one delete message (10.0.0.1) then one add message (10.0.0.4)
        assert_eq!(msgs.len(), 2);
        assert_eq!(classify(&msgs[0]), (true, vec![v4(1)]));
        assert_eq!(classify(&msgs[1]), (false, vec![v4(4)]));
    }

    #[test]
    fn sync_noop_when_equal() {
        let s: BTreeSet<_> = [v4(1), v4(2)].into_iter().collect();
        assert_eq!(sync_raw_set(&test_set::<Ipv4Addr>(), &s, &s).count(), 0);
    }

    #[test]
    fn sync_empty_orig_adds_all() {
        let orig = BTreeSet::new();
        let target: BTreeSet<_> = [v4(1), v4(2)].into_iter().collect();
        let msgs: Vec<_> = sync_raw_set(&test_set::<Ipv4Addr>(), &orig, &target).collect();
        assert_eq!(msgs.len(), 1); // batched into one add message
        let (delete, keys) = classify(&msgs[0]);
        assert!(!delete);
        assert_eq!(keys, vec![v4(1), v4(2)]);
    }

    #[test]
    fn sync_empty_target_deletes_all() {
        let orig: BTreeSet<_> = [v4(1), v4(2)].into_iter().collect();
        let target = BTreeSet::new();
        let msgs: Vec<_> = sync_raw_set(&test_set::<Ipv4Addr>(), &orig, &target).collect();
        assert_eq!(msgs.len(), 1); // batched into one delete message
        let (delete, keys) = classify(&msgs[0]);
        assert!(delete);
        assert_eq!(keys, vec![v4(1), v4(2)]);
    }

    #[test]
    fn sync_batches_and_keeps_order() {
        let orig = BTreeSet::new();
        let target: BTreeSet<_> = (0..20_000u32)
            .map(|i| Ipv4Addr::from(0x0a00_0000 + i).elem_data())
            .collect();
        let msgs: Vec<_> = sync_raw_set(&test_set::<Ipv4Addr>(), &orig, &target).collect();
        assert!(msgs.len() >= 2, "expected batching across messages");
        let total: usize = msgs.iter().map(|m| classify(m).1.len()).sum();
        assert_eq!(total, 20_000);
    }
}
