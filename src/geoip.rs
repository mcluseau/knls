use cidr::{IpCidr, Ipv4Cidr, Ipv6Cidr};
use std::{
    io::{Error, Result, SeekFrom},
    net::{Ipv4Addr, Ipv6Addr},
    path::Path,
};
use tokio::{
    fs,
    io::{AsyncRead, AsyncReadExt, AsyncSeekExt},
};

pub fn serialize_db<'t>(vec: &mut Vec<u8>, db: &[(&'t [u8; 2], &'t IpSet)]) {
    let mut offset = DbHeader::size(db.len());

    let mut sets = Vec::with_capacity(db.len());
    for (c, set) in db {
        sets.push(SetHeader {
            country: **c,
            offset,
        });
        offset += set.serialized_size();
    }

    DbHeader { sets }.append_to(vec);

    for (_, set) in db {
        set.append_to(vec);
    }
}

pub struct Db {
    db: fs::File,
    hdr: DbHeader,
}

impl Db {
    pub async fn open(path: impl AsRef<Path>) -> Result<Self> {
        let mut db = fs::File::open(path).await?;
        let mut rd = &mut tokio::io::BufReader::new(&mut db);
        let hdr = DbHeader::from_reader(&mut rd).await?;

        Ok(Self { db, hdr })
    }

    pub fn has_country(&self, country: &[u8]) -> bool {
        self.hdr.sets.iter().any(|set| set.country == country)
    }

    pub async fn lookup(&mut self, country: &[u8]) -> Result<Option<IpSet>> {
        let Some(hdr) = self.hdr.sets.iter().find(|set| set.country == country) else {
            return Ok(None);
        };

        self.db.seek(SeekFrom::Start(hdr.offset as u64)).await?;
        let rd = &mut tokio::io::BufReader::new(&mut self.db);
        let set = IpSet::from_reader(rd).await?;

        Ok(Some(set))
    }
}

#[derive(Clone, Default, PartialEq, Eq)]
pub struct IpSet {
    pub ipv4: Vec<Ipv4Cidr>,
    pub ipv6: Vec<Ipv6Cidr>,
}

impl IpSet {
    pub fn push(&mut self, cidr: IpCidr) {
        match cidr {
            IpCidr::V4(cidr) => self.ipv4.push(cidr),
            IpCidr::V6(cidr) => self.ipv6.push(cidr),
        }
    }

    fn serialized_size(&self) -> u32 {
        let mut sz = 4 + 4;
        for cidr in &self.ipv4 {
            sz += 1 + bits_bytes(cidr.network_length()) as u32;
        }
        for cidr in &self.ipv6 {
            sz += 1 + bits_bytes(cidr.network_length()) as u32;
        }
        sz
    }

    fn append_to(&self, vec: &mut Vec<u8>) {
        vec.reserve(self.serialized_size() as usize);

        vec.extend_from_slice(&(self.ipv4.len() as u32).to_le_bytes());
        vec.extend_from_slice(&(self.ipv6.len() as u32).to_le_bytes());

        for cidr in &self.ipv4 {
            serialize_cidr4(vec, *cidr);
        }
        for cidr in &self.ipv6 {
            serialize_cidr6(vec, *cidr);
        }
    }

    async fn from_reader<R>(rd: &mut R) -> Result<Self>
    where
        R: AsyncRead + Unpin,
    {
        const MAX_SIZE: usize = 2 << 20; // ~4x more than currently observed

        let mut n = [0u8; 4];
        rd.read_exact(&mut n).await?;
        let n_ipv4 = u32::from_le_bytes(n) as usize;
        rd.read_exact(&mut n).await?;
        let n_ipv6 = u32::from_le_bytes(n) as usize;

        let mut ipv4 = Vec::with_capacity(n_ipv6.min(MAX_SIZE));
        for _ in 0..n_ipv4 {
            let ip = deserialize_cidr4(rd).await?;
            ipv4.push(ip);
        }

        let mut ipv6 = Vec::with_capacity(n_ipv6.min(MAX_SIZE));
        for _ in 0..n_ipv6 {
            let ip = deserialize_cidr6(rd).await?;
            ipv6.push(ip);
        }

        Ok(Self { ipv4, ipv6 })
    }
}

#[inline]
fn bits_bytes(bits: u8) -> usize {
    let mut sz = (bits / 8) as usize;
    if !bits.is_multiple_of(8) {
        sz += 1
    };
    sz
}

#[inline]
fn serialize_cidr4(vec: &mut Vec<u8>, c: Ipv4Cidr) -> usize {
    serialize_cidr(vec, c.first_address().octets(), c.network_length())
}
#[inline]
fn serialize_cidr6(vec: &mut Vec<u8>, c: Ipv6Cidr) -> usize {
    serialize_cidr(vec, c.first_address().octets(), c.network_length())
}
#[inline]
fn serialize_cidr<const N: usize>(vec: &mut Vec<u8>, octets: [u8; N], bits: u8) -> usize {
    let sz = bits_bytes(bits);
    vec.reserve(1 + sz);
    vec.push(bits.to_le());
    vec.extend_from_slice(&octets[0..sz]);
    1 + sz
}

#[inline]
async fn deserialize_cidr4<R: AsyncRead + Unpin>(rd: &mut R) -> Result<Ipv4Cidr> {
    let (ip, bits) = deserialize_cidr(rd).await?;
    Ipv4Cidr::new(Ipv4Addr::from_octets(ip), bits).map_err(Error::other)
}
#[inline]
async fn deserialize_cidr6<R: AsyncRead + Unpin>(rd: &mut R) -> Result<Ipv6Cidr> {
    let (ip, bits) = deserialize_cidr(rd).await?;
    Ipv6Cidr::new(Ipv6Addr::from_octets(ip), bits).map_err(Error::other)
}
#[inline]
async fn deserialize_cidr<const N: usize>(mut rd: impl AsyncRead + Unpin) -> Result<([u8; N], u8)> {
    let bits = u8::from_le(rd.read_u8().await?);
    let sz = bits_bytes(bits);

    let mut octets = [0u8; N];
    rd.read_exact(&mut octets[0..sz]).await?;

    Ok((octets, bits))
}

struct DbHeader {
    sets: Vec<SetHeader>,
}

impl DbHeader {
    fn size(n_sets: usize) -> u32 {
        2 + (n_sets as u32) * SetHeader::SIZE
    }
    fn serialized_size(&self) -> u32 {
        Self::size(self.sets.len())
    }

    fn append_to(&self, vec: &mut Vec<u8>) {
        vec.reserve(self.serialized_size() as usize);

        let n = self.sets.len() as u16;
        vec.extend_from_slice(&n.to_le_bytes());

        for set in &self.sets {
            set.append_to(vec);
        }
    }

    async fn from_reader<R>(rd: &mut R) -> Result<Self>
    where
        R: AsyncRead + Unpin,
    {
        let n = u16::from_le_bytes(read_n(rd).await?);

        let mut sets = Vec::with_capacity(n.min(256) as usize);

        for _ in 0..n {
            sets.push(SetHeader::from_reader(rd).await?);
        }

        Ok(Self { sets })
    }
}

struct SetHeader {
    country: [u8; 2],
    offset: u32,
}

impl SetHeader {
    const SIZE: u32 = 2 + 4;

    fn append_to(&self, vec: &mut Vec<u8>) {
        vec.reserve(Self::SIZE as usize);
        vec.extend_from_slice(&self.country);
        vec.extend_from_slice(&self.offset.to_le_bytes());
    }

    async fn from_reader<R>(rd: &mut R) -> Result<Self>
    where
        R: AsyncRead + Unpin,
    {
        let mut country = [0u8; 2];
        rd.read_exact(&mut country).await?;

        let mut offset = [0u8; 4];
        rd.read_exact(&mut offset).await?;
        let offset = u32::from_le_bytes(offset);

        Ok(Self { country, offset })
    }
}

#[inline]
async fn read_n<const N: usize, R>(rd: &mut R) -> Result<[u8; N]>
where
    R: AsyncRead + Unpin,
{
    let mut b = [0u8; N];
    rd.read_exact(&mut b).await?;
    Ok(b)
}
