use super::data::{self, DomainName};

mod header {
    pub const ID_IDX: usize = 0;
    pub const OPCODE_IDX: usize = 2;
    pub const QR_BIT: u8 = 0b1_0000_0_0_0;
    pub const AA_BIT: u8 = 0b0_0000_1_0_0;
    pub const TC_BIT: u8 = 0b0_0000_0_1_0;
    pub const RD_BIT: u8 = 0b0_0000_0_0_1;
    pub const RCODE_IDX: usize = OPCODE_IDX + 1;
    pub const RA_BIT: u8 = 0b1_000_0000;
    pub const QDCOUNT_IDX: usize = RCODE_IDX + 1;
    pub const ANCOUNT_IDX: usize = QDCOUNT_IDX + 2;
    pub const NSCOUNT_IDX: usize = ANCOUNT_IDX + 2;
    pub const ARCOUNT_IDX: usize = NSCOUNT_IDX + 2;
}

pub enum Label<'t> {
    Root,
    Jump { offset: u16 },
    Name(&'t [u8]),
}
impl<'t> Label<'t> {
    pub fn push_to(&self, buf: &mut Vec<u8>) {
        match self {
            Label::Root => buf.push(0),
            Label::Jump { offset } => push_u16(buf, offset | ((JUMP_BITS as u16) << 8)),
            Label::Name(n) => {
                buf.push(n.len() as u8);
                buf.extend_from_slice(n)
            }
        }
    }
}

pub const JUMP_BITS: u8 = 0b1100_0000;

// RFC1035 status codes
#[derive(Debug)]
pub enum ResponseCode {
    NoError = 0,
    FormatError = 1,
    ServerFailure = 2,
    NameError = 3,
    NotImplemented = 4,
    Refused = 5,
}

pub type Result<T> = std::result::Result<T, ResponseCode>;

pub struct Reader<'t> {
    pkt: &'t [u8],
    pos: usize,
}
impl<'t> Reader<'t> {
    pub fn new(pkt: &'t [u8]) -> Self {
        Self { pkt, pos: 0 }
    }

    pub fn with_header(pkt: &'t [u8]) -> Self {
        Self {
            pkt,
            pos: 12, // start reading after the header
        }
    }

    pub fn id(&self) -> Result<u16> {
        self.get_u16(0)
    }
    pub fn qr(&mut self) -> Result<bool> {
        self.get_bit(header::OPCODE_IDX, header::QR_BIT)
    }
    pub fn opcode(&mut self) -> Result<u8> {
        Ok(self.get(header::OPCODE_IDX)? >> 3 & 0b111)
    }
    pub fn aa(&mut self) -> Result<bool> {
        self.get_bit(header::OPCODE_IDX, header::AA_BIT)
    }
    pub fn tc(&mut self) -> Result<bool> {
        self.get_bit(header::OPCODE_IDX, header::TC_BIT)
    }
    pub fn rd(&mut self) -> Result<bool> {
        self.get_bit(header::OPCODE_IDX, header::RD_BIT)
    }
    pub fn ra(&mut self) -> Result<bool> {
        self.get_bit(header::RCODE_IDX, header::RA_BIT)
    }
    pub fn z(&mut self) -> Result<u8> {
        Ok(self.get(header::RCODE_IDX)? >> 4 & 0b111)
    }
    pub fn rcode(&mut self) -> Result<u8> {
        Ok(self.get(header::RCODE_IDX)? & 0b1111)
    }
    pub fn qd_count(&self) -> Result<u16> {
        self.get_u16(header::QDCOUNT_IDX)
    }
    pub fn an_count(&self) -> Result<u16> {
        self.get_u16(header::ANCOUNT_IDX)
    }
    pub fn ns_count(&self) -> Result<u16> {
        self.get_u16(header::NSCOUNT_IDX)
    }
    pub fn ar_count(&self) -> Result<u16> {
        self.get_u16(header::ARCOUNT_IDX)
    }

    pub fn remainer(&self) -> &[u8] {
        &self.pkt.get(self.pos..).unwrap_or_default()
    }

    fn get(&self, pos: usize) -> Result<u8> {
        self.pkt.get(pos).ok_or(ResponseCode::FormatError).copied()
    }
    fn get_n(&self, pos: usize, n: usize) -> Result<&'t [u8]> {
        self.pkt.get(pos..pos + n).ok_or(ResponseCode::FormatError)
    }
    fn get_bit(&self, pos: usize, mask: u8) -> Result<bool> {
        Ok(self.get(pos)? & mask != 0)
    }
    fn get_u16(&self, pos: usize) -> Result<u16> {
        Ok((self.get(pos)? as u16) << 8 | (self.get(pos + 1)? as u16))
    }
    fn get_u32(&self, pos: usize) -> Result<u32> {
        Ok((self.get(pos)? as u32) << 24
            | (self.get(pos + 1)? as u32) << 16
            | (self.get(pos + 2)? as u32) << 8
            | (self.get(pos + 3)? as u32))
    }

    /// get the label at the given position, return the label and the length it takes in the packet
    fn get_label(&self, mut pos: usize) -> Result<(Label<'t>, usize)> {
        let b = self.get(pos)?;
        pos += 1;

        let (label, len) = if b == 0 {
            (Label::Root, 1)
        } else if b & JUMP_BITS == JUMP_BITS {
            let offset = ((b ^ JUMP_BITS) as u16) << 8 | (self.get(pos)? as u16);
            (Label::Jump { offset }, 2)
        } else {
            let len = b as usize;
            (Label::Name(self.get_n(pos, len)?), 1 + len)
        };

        Ok((label, len))
    }

    pub fn next(&mut self) -> Result<u8> {
        self.get(self.pos).inspect(|_| self.pos += 1)
    }
    pub fn next_n(&mut self, n: usize) -> Result<&'t [u8]> {
        self.get_n(self.pos, n).inspect(|_| self.pos += n)
    }
    pub fn next_u16(&mut self) -> Result<u16> {
        self.get_u16(self.pos).inspect(|_| self.pos += 2)
    }
    pub fn next_u32(&mut self) -> Result<u32> {
        self.get_u32(self.pos).inspect(|_| self.pos += 4)
    }

    fn next_label(&mut self) -> Result<Label<'t>> {
        let (label, len) = self.get_label(self.pos)?;
        self.pos += len;
        Ok(label)
    }

    pub fn next_domain_name(&mut self) -> Result<DomainName> {
        let mut len = 0;
        let mut dn = DomainName::new();
        loop {
            match self.next_label()? {
                Label::Root => {
                    break;
                }
                Label::Jump { offset } => {
                    self.read_labels(&mut dn, offset, len)?;
                    break;
                }
                Label::Name(n) => {
                    let Ok(label) = data::Label::try_from(n) else {
                        return Err(ResponseCode::Refused);
                    };

                    // domain names are limited to 255 bytes (rfc1034#section-3.1)
                    len += label.raw_len();
                    if len > 255 {
                        return Err(ResponseCode::Refused);
                    }

                    dn.push(label);
                }
            }
        }
        Ok(dn)
    }

    fn read_labels(&self, dn: &mut DomainName, offset: u16, mut len: usize) -> Result<()> {
        let mut pos = offset as usize;
        let mut just_jumped = true;

        loop {
            let (label, label_len) = self.get_label(pos)?;

            match label {
                Label::Root => {
                    break;
                }
                Label::Jump { offset } => {
                    // refuse jump loops
                    if just_jumped {
                        return Err(ResponseCode::Refused);
                    }
                    pos = offset as usize;
                    just_jumped = true;
                }
                Label::Name(n) => {
                    just_jumped = false;

                    let Ok(label) = data::Label::try_from(n) else {
                        return Err(ResponseCode::Refused);
                    };

                    len += label.raw_len();
                    if len > 255 {
                        return Err(ResponseCode::Refused);
                    }
                    dn.push(label);

                    pos += label_len;
                }
            }
        }
        Ok(())
    }

    pub fn next_rr(&mut self) -> Result<(DomainName, data::Record)> {
        let dn = self.next_domain_name()?;
        let rtype = self.next_u16()?;
        let class = self.next_u16()?;
        let ttl = self.next_u32()?;
        let rdlen = self.next_u16()?;
        let rdata = self.next_n(rdlen as usize)?;

        let rtype = data::RecordType::from(rtype);
        Ok((dn, data::Record::new(rtype, class, ttl, rdata.into())))
    }
}

pub struct Writer {
    pkt: Vec<u8>,
    // TODO size limit & truncation support
}
impl Writer {
    pub fn new() -> Self {
        Self::with_capacity(512)
    }
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            pkt: Vec::with_capacity(capacity),
        }
    }

    pub fn pos(&self) -> usize {
        self.pkt.len()
    }

    pub fn set_id(&mut self, v: u16) {
        self.set_u16(header::ID_IDX, v);
    }
    pub fn set_qr(&mut self, v: bool) {
        self.set_bit(header::OPCODE_IDX, header::QR_BIT, v);
    }
    pub fn set_opcode(&mut self, v: u8) {
        self.set_bits(header::OPCODE_IDX, 0b1_0000_1_1_1, (v & 0b1111) << 3);
    }
    pub fn set_aa(&mut self, v: bool) {
        self.set_bit(header::OPCODE_IDX, header::AA_BIT, v);
    }
    pub fn set_tc(&mut self, v: bool) {
        self.set_bit(header::OPCODE_IDX, header::TC_BIT, v);
    }
    pub fn set_rd(&mut self, v: bool) {
        self.set_bit(header::OPCODE_IDX, header::RD_BIT, v);
    }
    pub fn set_ra(&mut self, v: bool) {
        self.set_bit(header::RCODE_IDX, header::RA_BIT, v);
    }
    pub fn set_rcode(&mut self, v: ResponseCode) {
        self.set_bits(header::RCODE_IDX, 0b11110000, v as u8);
    }
    pub fn set_qd_count(&mut self, v: u16) {
        self.set_u16(header::QDCOUNT_IDX, v);
    }
    pub fn set_an_count(&mut self, v: u16) {
        self.set_u16(header::ANCOUNT_IDX, v);
    }
    pub fn set_ns_count(&mut self, v: u16) {
        self.set_u16(header::NSCOUNT_IDX, v);
    }
    pub fn set_ar_count(&mut self, v: u16) {
        self.set_u16(header::ARCOUNT_IDX, v);
    }

    fn set_bit(&mut self, pos: usize, bit: u8, v: bool) {
        self.set_bits(pos, !bit, if v { bit } else { 0 });
    }
    fn set_bits(&mut self, pos: usize, mask: u8, v: u8) {
        self.pkt[pos] = self.pkt[pos] & mask | v;
    }
    fn set_u16(&mut self, pos: usize, v: u16) {
        self.pkt[pos] = (v >> 8) as u8;
        self.pkt[pos + 1] = v as u8;
    }

    pub fn push(&mut self, b: u8) {
        self.pkt.push(b)
    }
    pub fn push_n(&mut self, slice: &[u8]) {
        self.pkt.extend_from_slice(slice)
    }
    pub fn push_u16(&mut self, v: u16) {
        self.pkt.extend([(v >> 8) as u8, v as u8])
    }
    pub fn push_u32(&mut self, v: u32) {
        self.pkt
            .extend([(v >> 24) as u8, (v >> 16) as u8, (v >> 8) as u8, v as u8])
    }

    pub fn push_label(&mut self, label: &Label) {
        label.push_to(&mut self.pkt)
    }
    pub fn push_dn(&mut self, dn: &DomainName) {
        let v = dn.to_vec();
        if let Some(offset) = self.offset_of(&v) {
            self.push_label(&Label::Jump { offset });
        } else {
            self.push_n(&v);
        }
        // TODO use label offsets to implement DNS packet compression
        // let start =self.pos();
        // dn.write_to(&mut self.pkt);
        // ...
    }

    pub fn push_record(&mut self, record: &data::Record) {
        record.push_to(self)
    }

    pub fn offset_of(&self, v: &[u8]) -> Option<u16> {
        self.pkt
            .windows(v.len())
            .position(|w| v == w)
            .map(|pos| pos as u16)
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.pkt
    }
}

pub fn push_u16(buf: &mut Vec<u8>, v: u16) {
    buf.extend([(v >> 8) as u8, v as u8])
}
pub fn push_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend([(v >> 24) as u8, (v >> 16) as u8, (v >> 8) as u8, v as u8])
}
