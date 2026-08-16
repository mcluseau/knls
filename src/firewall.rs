use cidr::{IpCidr, Ipv4Cidr, Ipv6Cidr};
use eyre::{bail, eyre, Result};
use log::error;
use std::{collections::BTreeMap as Map, fmt::Display, path::PathBuf};
use tokio::sync::mpsc;

use crate::geoip;

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct Firewall {
    table: String,
    country_ips: PathBuf,
    ipsets: Map<String, IpSet>,
    chains: Map<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IpSet {
    Country(String),
    Ips(Vec<IpCidr>),
}

impl Default for Firewall {
    fn default() -> Self {
        Self {
            table: "knls-firewall".into(),
            country_ips: "/assets/country_ips.db".into(),
            ipsets: Map::new(),
            chains: Map::new(),
        }
    }
}

impl Firewall {
    pub fn is_empty(&self) -> bool {
        self.ipsets.is_empty() && self.chains.is_empty()
    }

    pub async fn to_nft(&self) -> Result<String> {
        let mut out = String::new();

        let mut rx = self.nft_steps().await?;
        while let Some(part) = rx.recv().await {
            out.push_str(&part);
        }

        Ok(out) // we could _unchecked
    }

    pub async fn nft_steps(&self) -> Result<mpsc::Receiver<String>> {
        let (tx, rx) = mpsc::channel(1);

        // step 1: rebuild the table without country sets (they can be big)
        // non-country sets are better in the atomic part, they cna be critical for access

        let mut out = String::new();

        macro_rules! w {
            ($s:expr) => {
                out.push_str($s)
            };
        }

        let table = format!("inet {}", self.table);
        w!(&format!(
            "table {table} {{}}\ndelete table {table}\ntable {table} {{}}\n"
        ));

        let mut country_ips = None;

        for (name, ipset) in &self.ipsets {
            match ipset {
                IpSet::Ips(ips) => {
                    nft_ipset(
                        &mut out,
                        &table,
                        name,
                        ips.iter().filter_map(|c| match c {
                            IpCidr::V4(c) => Some(*c),
                            _ => None,
                        }),
                        ips.iter().filter_map(|c| match c {
                            IpCidr::V6(c) => Some(*c),
                            _ => None,
                        }),
                    );
                }
                IpSet::Country(code) => {
                    if country_ips.is_none() {
                        let path = self.country_ips.clone();
                        let db = (geoip::Db::open(&path).await)
                            .map_err(|e| eyre!("geoip DB open failed: {}: {e}", path.display()))?;
                        country_ips = Some(db);
                    }
                    // safe because of 2 lines up
                    let db = unsafe { country_ips.as_mut().unwrap_unchecked() };

                    if !db.has_country(code.as_bytes()) {
                        bail!("no country with code {code}");
                    }

                    nft_ipset(
                        &mut out,
                        &table,
                        name,
                        std::iter::empty(),
                        std::iter::empty(),
                    );
                }
            }
        }

        w!(&format!("table {table} {{\n"));
        for (name, rules) in &self.chains {
            w!(&format!("  chain {name} {{\n"));
            w!(rules);
            w!("  }\n");
        }

        w!("}\n");

        tx.try_send(out).expect("shouldn't block");

        let ipsets = self.ipsets.clone();

        // step 2: async generate country ipsets chunks
        tokio::spawn(async move {
            let mut out = String::new();
            for (name, ipset) in ipsets {
                let IpSet::Country(code) = ipset else {
                    continue;
                };

                let db = country_ips.as_mut().expect("DB should be open");

                let Ok(Some(ipset)) = db
                    .lookup(code.as_bytes())
                    .await
                    .inspect_err(|e| error!("failed to read country ipset for {code}: {e}"))
                else {
                    continue;
                };

                for chunk in ipset.ipv4.chunks(500) {
                    nft_set_ipv4(&mut out, &table, &name, chunk.iter().copied());
                    if tx.send(out.clone()).await.is_err() {
                        return; // discarded
                    }
                    out.clear();
                }

                for chunk in ipset.ipv6.chunks(500) {
                    nft_set_ipv6(&mut out, &table, &name, chunk.iter().copied());
                    if tx.send(out.clone()).await.is_err() {
                        return; // discarded
                    }
                    out.clear();
                }
            }
        });

        Ok(rx)
    }
}

fn nft_ipset(
    out: &mut String,
    table: &str,
    name: impl Display,
    ipsv4: impl Iterator<Item = Ipv4Cidr>,
    ipsv6: impl Iterator<Item = Ipv6Cidr>,
) {
    nft_set(out, table, format!("{name}_ipv4"), "ipv4_addr", ipsv4);
    nft_set(out, table, format!("{name}_ipv6"), "ipv6_addr", ipsv6);
}

fn nft_set_ipv4(
    out: &mut String,
    table: &str,
    name: impl Display,
    ips: impl Iterator<Item = Ipv4Cidr>,
) {
    nft_set(out, table, format!("{name}_ipv4"), "ipv4_addr", ips);
}

fn nft_set_ipv6(
    out: &mut String,
    table: &str,
    name: impl Display,
    ips: impl Iterator<Item = Ipv6Cidr>,
) {
    nft_set(out, table, format!("{name}_ipv6"), "ipv6_addr", ips);
}

fn nft_set(
    out: &mut String,
    table: &str,
    name: impl Display,
    type_: impl Display,
    elements: impl Iterator<Item = impl Display>,
) {
    macro_rules! w {
        ($s:expr) => {
            out.push_str($s)
        };
    }

    w!(&format!(
        "set {table} {name} {{\n  type {type_}; flags interval"
    ));
    let mut open = false;
    for (i, e) in elements.enumerate() {
        let prefix = if i == 0 {
            open = true;
            "; elements = {\n"
        } else if i % 10 == 0 {
            ",\n"
        } else {
            ", "
        };
        w!(&format!("{prefix}{e}"));
    }
    if open {
        w!("\n  }")
    };
    w!("\n}\n");
}

#[cfg(test)]
mod test {
    use super::*;

    #[tokio::test]
    async fn tests_from_yaml() {
        #[derive(serde::Deserialize)]
        struct Test {
            name: String,
            cfg: Firewall,
            expect: String,
        }

        let tests: Vec<Test> = serde_yaml::from_str(include_str!("firewall/tests.yaml")) //
            .expect("bad tests file");

        for mut test in tests {
            test.cfg.country_ips = "test_assets/country_ips.db".into();

            let nft_script = test.cfg.to_nft().await.expect("to_nft failed");

            if test.expect != nft_script {
                use diff::Result::*;
                println!("diff on test {}", test.name);
                for diff in diff::lines(&test.expect, &nft_script) {
                    match diff {
                        Left(l) => println!("-{l}"),
                        Both(l, _) => println!(" {l}"),
                        Right(r) => println!("+{r}"),
                    }
                }
                panic!("assertion failed");
            }
        }
    }
}
