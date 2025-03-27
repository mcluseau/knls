use std::collections::BTreeMap as Map;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::packet;

#[derive(Clone)]
pub struct Domain {
    subs: Map<Label, Domain>,
    records: Vec<Record>,
}
impl Domain {
    pub fn new() -> Self {
        Self {
            subs: Map::new(),
            records: Vec::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.subs.is_empty() && self.records.is_empty()
    }

    pub fn records(&self) -> &[Record] {
        self.records.as_slice()
    }
    pub fn push_record(&mut self, record: Record) {
        self.records.push(record);
    }
    pub fn soa(&self) -> Option<&Record> {
        self.records.iter().find(|r| r.rtype == RecordType::SOA)
    }

    pub fn sub_or_create(&mut self, label: Label) -> &mut Domain {
        self.subs.entry(label).or_insert_with(Domain::new)
    }

    pub fn set(&mut self, dn: &DomainName, domain: Domain) {
        *self.resolve_or_create(dn) = domain;
    }

    pub fn resolve_or_create(&mut self, dn: &DomainName) -> &mut Domain {
        let mut domain = self;
        for label in dn.iter().rev() {
            domain = domain.sub_or_create(label.clone());
        }
        domain
    }

    pub fn resolve(&self, dn: &DomainName) -> Resolved {
        let mut r = Resolved {
            soa: self.soa().map(|soa| (DomainName::new(), soa)),
            domain: None,
        };

        let mut domain = self;
        for (i, label) in dn.iter().rev().enumerate() {
            domain = match domain.subs.get(label) {
                Some(v) => v,
                None => {
                    return r;
                }
            };
            if let Some(soa) = domain.soa() {
                r.soa = Some((DomainName(dn.0[dn.0.len() - 1 - i..].to_vec()), soa));
            }
        }

        r.domain = Some(domain);
        r
    }
}

pub struct Resolved<'t> {
    pub soa: Option<(DomainName, &'t Record)>,
    pub domain: Option<&'t Domain>,
}

macro_rules! def_record_types {
    ($($variant:ident => $val:expr),+ $(,)?) => {
        #[derive(Clone, Debug, PartialEq, Eq)]
        #[repr(u16)]
        pub enum RecordType {
            Unknown = 0,
            $(
                $variant = $val,
            )+
        }
        impl From<u16> for RecordType {
            fn from(rtype: u16) -> RecordType {
                use RecordType::*;
                match rtype {
                    $(
                        $val => $variant,
                    )+
                    _ => Unknown,
                }
            }
        }
        impl std::fmt::Display for RecordType {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
                use RecordType::*;
                f.write_str(match self {
                    $(
                        $variant => stringify!($variant),
                    )+
                    _ => "?",
                })
            }
        }
    };
}

def_record_types!(
    A => 1,
    NS => 2,
    CNAME => 5,
    SOA => 6,
    WKS => 11,
    PTR => 12,
    HINFO => 13,
    MINFO => 14,
    MX => 15,
    TXT => 16,
    AAAA => 28,
    OPT => 41,
);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    rtype: RecordType,
    class: u16,
    ttl: u32,
    rdata: Vec<u8>,
}
impl Record {
    pub fn alias(ttl: u32, ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(ip) => Self::alias4(ttl, ip),
            IpAddr::V6(ip) => Self::alias6(ttl, ip),
        }
    }

    pub fn alias4(ttl: u32, ip: Ipv4Addr) -> Self {
        Self {
            rtype: RecordType::A,
            class: 1,
            ttl,
            rdata: Vec::from(ip.octets()),
        }
    }

    pub fn alias6(ttl: u32, ip: Ipv6Addr) -> Self {
        Self {
            rtype: RecordType::AAAA,
            class: 1,
            ttl,
            rdata: Vec::from(ip.octets()),
        }
    }

    fn dn(ttl: u32, rtype: RecordType, dn: &DomainName) -> Self {
        Self {
            rtype,
            class: 1,
            ttl,
            rdata: dn.to_vec(),
        }
    }
    pub fn cname(ttl: u32, name: &DomainName) -> Self {
        Self::dn(ttl, RecordType::CNAME, name)
    }
    pub fn ns(ttl: u32, name: &DomainName) -> Self {
        Self::dn(ttl, RecordType::NS, name)
    }
    pub fn ptr(ttl: u32, name: &DomainName) -> Self {
        Self::dn(ttl, RecordType::PTR, name)
    }

    pub fn mx(ttl: u32, preference: u16, name: &DomainName) -> Self {
        let mut rdata = Vec::with_capacity(2 + name.raw_len());
        packet::push_u16(&mut rdata, preference);
        name.write_to(&mut rdata);
        Self {
            rtype: RecordType::MX,
            class: 1,
            ttl,
            rdata,
        }
    }

    pub fn opt(udp_size: u16, rcode_and_flags: u32, opts: &[Opt]) -> Self {
        let mut rdata =
            Vec::with_capacity(4 * opts.len() + opts.iter().map(|o| o.data.len()).sum::<usize>());
        for opt in opts {
            packet::push_u16(&mut rdata, opt.code);
            packet::push_u16(&mut rdata, opt.data.len() as u16);
            rdata.extend_from_slice(&opt.data);
        }
        Self {
            rtype: RecordType::OPT,
            class: udp_size,
            ttl: rcode_and_flags,
            rdata,
        }
    }

    pub fn new(rtype: RecordType, class: u16, ttl: u32, rdata: Vec<u8>) -> Self {
        Self {
            rtype,
            class,
            ttl,
            rdata,
        }
    }

    pub fn rtype(&self) -> &RecordType {
        &self.rtype
    }
    pub fn class(&self) -> u16 {
        self.class
    }
    pub fn ttl(&self) -> u32 {
        self.ttl
    }
    pub fn rdata(&self) -> &[u8] {
        self.rdata.as_slice()
    }

    pub fn push_to(&self, w: &mut packet::Writer) {
        w.push_u16(self.rtype.clone() as u16);
        w.push_u16(self.class);
        w.push_u32(self.ttl);
        w.push_u16(self.rdata.len() as u16);
        w.push_n(&self.rdata);
    }
}

pub struct Soa {
    pub mname: DomainName,
    pub rname: DomainName,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32,
}
impl Soa {
    pub fn into_record(self, ttl: u32) -> Record {
        let mut rdata = Vec::with_capacity(self.mname.raw_len() + self.rname.raw_len() + 4 * 4);

        self.mname.write_to(&mut rdata);
        self.rname.write_to(&mut rdata);

        use packet::push_u32;
        push_u32(&mut rdata, self.serial);
        push_u32(&mut rdata, self.refresh);
        push_u32(&mut rdata, self.retry);
        push_u32(&mut rdata, self.expire);
        push_u32(&mut rdata, self.minimum);

        Record {
            rtype: RecordType::SOA,
            class: 1,
            ttl,
            rdata,
        }
    }
}

pub struct Opt {
    pub code: u16,
    pub data: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct DomainName(Vec<Label>);

impl DomainName {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn push(&mut self, label: Label) {
        self.0.push(label);
    }
    pub fn extend(&mut self, suffix: DomainName) {
        self.0.extend(suffix.0);
    }

    pub fn iter(&self) -> impl DoubleEndedIterator<Item = &Label> {
        self.0.iter()
    }

    pub fn raw_len(&self) -> usize {
        self.0.len() // 1 byte per label
            + self.iter().map(|s| s.0.as_bytes().len()).sum::<usize>()
            + 1 // ROOT terminator
    }

    /// Writes the domain name to the given buffer, returning label start offsets.
    /// Most notably, the label start offsets allow to compute jumps in the response packet.
    pub fn write_to(&self, buf: &mut Vec<u8>) -> Vec<usize> {
        let mut offsets = Vec::with_capacity(self.0.len());
        let mut offset = buf.len();
        for label in &self.0 {
            offsets.push(offset);

            let len = label.0.len();
            offset += len;

            buf.push(len as u8);
            buf.extend_from_slice(label.0.as_bytes());
        }
        buf.push(0); // terminate with ROOT
        offsets
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(self.raw_len());
        self.write_to(&mut v);
        v
    }
}

impl std::cmp::Ord for DomainName {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        use std::cmp::Ordering::*;

        // compare from TLD to host name; ie we want b.a < a.b
        let mut labels_a = self.iter().rev();
        let mut labels_b = other.iter().rev();
        loop {
            let a = labels_a.next();
            let b = labels_b.next();

            break match (a, b) {
                (None, None) => Equal,
                (None, Some(_)) => Less,
                (Some(_), None) => Greater,
                (Some(a), Some(b)) => match a.cmp(&b) {
                    Equal => {
                        continue;
                    }
                    v => v,
                },
            };
        }
    }
}
impl std::cmp::PartialOrd for DomainName {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl FromIterator<Label> for DomainName {
    fn from_iter<T>(iter: T) -> Self
    where
        T: IntoIterator<Item = Label>,
    {
        Self(iter.into_iter().collect())
    }
}

impl From<Label> for DomainName {
    fn from(v: Label) -> Self {
        Self(Vec::from([v]))
    }
}

impl TryFrom<&str> for DomainName {
    type Error = Error;
    fn try_from(v: &str) -> Result<Self, Self::Error> {
        if v.as_bytes().len() > 255 {
            return Err(Error::DomainNameTooLong);
        }

        let mut dn = Self::new();
        for label in v.split('.').filter(|v| !v.is_empty()) {
            dn.push(Label::try_from(label)?);
        }
        Ok(dn)
    }
}

impl std::fmt::Display for DomainName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        for label in self.iter() {
            label.fmt(f)?;
            f.write_str(".")?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum Error {
    LabelTooLong,
    DomainNameTooLong,
}

#[derive(Clone, PartialOrd, Ord, PartialEq, Eq)]
pub struct Label(String);
impl Label {
    pub fn from_str(v: &str) -> Self {
        // downcase name so the comparisons are case insensitive (including sort, otherwise we
        // could use eq_ignore_ascii_case).
        let v = v.to_lowercase();
        Self(v)
    }

    pub fn raw_len(&self) -> usize {
        self.0.as_bytes().len() + 1
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl TryFrom<&str> for Label {
    type Error = Error;
    fn try_from(v: &str) -> Result<Self, Self::Error> {
        if v.as_bytes().len() > 63 {
            return Err(Error::LabelTooLong);
        }
        Ok(Self::from_str(v))
    }
}

impl<'t> TryFrom<&[u8]> for Label {
    type Error = Error;
    fn try_from(v: &[u8]) -> Result<Self, Self::Error> {
        Self::try_from(String::from_utf8_lossy(v).as_ref())
    }
}

impl<'t> std::fmt::Display for Label {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        f.write_str(&self.0)
    }
}
