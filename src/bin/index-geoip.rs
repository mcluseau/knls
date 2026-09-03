use eyre::Result;
use serde::{Deserialize, Deserializer};
use std::{collections::BTreeMap as Map, fmt, fs, io::Cursor, str::FromStr};

use knls::geoip;

#[derive(Clone, Copy, Deserialize)]
pub struct GeoipRecord {
    #[serde(deserialize_with = "asn::deserialize")]
    pub asn: u32,
    pub country: CountryCode,
}

/// 2-letters country code
#[derive(Clone, Copy, PartialOrd, Ord, PartialEq, Eq)]
pub struct CountryCode([u8; 2]);

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0} is not a valid country code")]
    InvalidCountryCode(String),
}

#[tokio::main]
pub async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let output = args.next().unwrap_or("country_ips.db".into());

    let test = args.next().as_deref() == Some("test");

    eprintln!("loading DB");
    let db = {
        let db = fs::File::open("geoip.mmdb.zst")?;
        let db = zstd::decode_all(db)?;
        maxminddb::Reader::from_source(db)?
    };

    eprintln!("reading records");
    let mut country_ips = Map::new();

    for net in db.networks(Default::default())? {
        let net = net?;

        let Ok(Some(record)) = net
            .decode::<GeoipRecord>()
            .inspect_err(|e| println!("err: {e}"))
        else {
            continue;
        };

        let ip_net = net.network()?;
        let cidr = cidr::IpCidr::new(ip_net.ip(), ip_net.prefix())?;

        let ipset: &mut geoip::IpSet = country_ips.entry(record.country).or_default();
        ipset.push(cidr);
    }

    for set in country_ips.values_mut() {
        set.ipv4.sort();
        set.ipv6.sort();

        if test {
            set.ipv4.truncate(3);
            set.ipv6.truncate(3);
        }
    }

    eprintln!("writing DB ({} countries)", country_ips.len());

    let mut ser_db = Vec::new();
    geoip::serialize_db(
        &mut ser_db,
        &country_ips
            .iter()
            .map(|(c, s)| (&c.0, s))
            .collect::<Vec<_>>(),
    );

    fs::write(&output, &ser_db)?;

    // read again
    eprintln!("reading & validating result");
    let mut db = geoip::Db::open(&output).await?;

    for (country, set) in &country_ips {
        eprint!("{country}\r");
        let read_set = db.lookup(&country.0).await?;
        if read_set.as_ref() != Some(set) {
            eprintln!("{country}: set mismatch");
        }
    }

    drop(db);

    eprintln!("compressing");
    let comp_db = zstd::encode_all(Cursor::new(ser_db), 16)?;
    fs::write(format!("{output}.zst"), comp_db)?;

    eprintln!("done");
    Ok(())
}

impl CountryCode {
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 2 || !bytes.iter().all(|byte| byte.is_ascii_uppercase()) {
            return Err(Error::InvalidCountryCode(
                String::from_utf8_lossy(bytes).to_string(),
            ));
        }

        let mut arr = [0u8; 2];
        arr.copy_from_slice(bytes);
        Ok(CountryCode(arr))
    }

    pub fn as_str(&self) -> &str {
        // safe because we only allow ASCII uppercase letters
        // which are valid UTF-8 single-byte characters
        unsafe { str::from_utf8_unchecked(&self.0) }
    }
}

impl<'de> serde::Deserialize<'de> for CountryCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error as _;
        let s = String::deserialize(deserializer)?;
        CountryCode::from_str(&s).map_err(|e| D::Error::custom(e.to_string()))
    }
}

impl fmt::Display for CountryCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for CountryCode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = s.as_bytes();
        Self::from_bytes(bytes)
    }
}

pub mod asn {
    use serde::{Deserialize, Deserializer};

    #[inline]
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u32, D::Error> {
        let asn_str = String::deserialize(deserializer)?;
        Ok(asn_str.trim_start_matches("AS").parse::<u32>().unwrap_or(0))
    }
}
