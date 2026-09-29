use cidr::IpCidr;
use eyre::{Result, bail, eyre};
use std::{
    collections::BTreeMap as Map,
    net::{Ipv4Addr, Ipv6Addr},
    path::PathBuf,
};

use crate::{
    geoip,
    netlink::netfilter::{self, NetlinkExt as _},
    nftables::{self, set, table},
};

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

    async fn open_db(&self) -> Result<geoip::Db> {
        geoip::Db::open(&self.country_ips)
            .await
            .map_err(|e| eyre!("geoip DB open failed: {}: {e}", self.country_ips.display()))
    }

    pub async fn apply(&self) -> Result<()> {
        let nl = netfilter::new_link()?;

        let mut id_seq = 0u32;
        let mut next_id = || {
            id_seq += 1;
            id_seq
        };

        // step 1: recreate the table and define/fill the regular sets in one
        // atomic batch. Country sets are only created here (empty); their
        // elements can be huge and are filled in step 3.

        let mut msgs = vec![];
        msgs.extend(table::recreate(&self.table));

        let mut deferred = vec![];

        for (name, ipset) in &self.ipsets {
            let v4 = set::IntervalSet::<Ipv4Addr>::new(
                self.table.clone(),
                format!("{name}_ipv4"),
                next_id(),
            );
            let v6 = set::IntervalSet::<Ipv6Addr>::new(
                self.table.clone(),
                format!("{name}_ipv6"),
                next_id(),
            );

            msgs.extend([v4.create(), v4.flush()]);
            msgs.extend([v6.create(), v6.flush()]);

            match ipset {
                IpSet::Ips(ips) => {
                    msgs.extend(v4.fill(ips.iter().filter_map(|c| match c {
                        IpCidr::V4(c) => Some(c.first_address()..=c.last_address()),
                        _ => None,
                    })));
                    msgs.extend(v6.fill(ips.iter().filter_map(|c| match c {
                        IpCidr::V6(c) => Some(c.first_address()..=c.last_address()),
                        _ => None,
                    })));
                }
                IpSet::Country(code) => {
                    deferred.push((code, v4, v6));
                }
            }
        }

        nl.send_as_transactions(msgs.into_iter()).await?;

        // step 2: create the user chains. The sets referenced by `@name` were
        // created in step 1.

        let mut script = String::new();
        script.push_str(&format!("table inet {} {{\n", self.table));
        for (name, rules) in &self.chains {
            script.push_str(&format!("  chain {name} {{\n"));
            script.push_str(rules);
            script.push_str("  }\n");
        }
        script.push_str("}\n");

        nftables::apply_script(script)
            .await
            .map_err(|e| eyre!("applying chains failed: {e}"))?;

        // step 3: fill the country sets, chunked by the fill iterator.

        if deferred.is_empty() {
            return Ok(());
        }

        let mut db = self.open_db().await?;

        for (code, v4, v6) in deferred {
            let Some(ipset) = db.lookup(code.as_bytes()).await? else {
                bail!("no country with code {code}");
            };

            let msgs = v4
                .fill((ipset.ipv4.iter()).map(|c| c.first_address()..=c.last_address()))
                .chain(v6.fill((ipset.ipv6.iter()).map(|c| c.first_address()..=c.last_address())));

            nl.send_as_transactions(msgs).await?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::process::Command;

    /// Source of the expected post-apply state, as dumped by `nft list table`.
    #[derive(serde::Deserialize)]
    struct Test {
        name: String,
        cfg: Firewall,
        expect: String,
    }

    fn tests() -> Vec<Test> {
        serde_yaml::from_str(include_str!("firewall/tests.yaml")).expect("bad tests file")
    }

    /// The kernel state of `table`, as text.
    fn dump(table: &str) -> String {
        let out = Command::new("nft")
            .args(["list", "table", "inet", table])
            .output()
            .expect("nft should run");
        assert!(
            out.status.success(),
            "nft list failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).expect("nft output should be UTF-8")
    }

    /// Collapse all whitespace, so line wrapping and indentation don't matter.
    fn normalize(s: &str) -> String {
        s.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// End-to-end test: applies each case to the real kernel and compares the
    /// resulting table (sets, elements and chains) against the expected dump.
    ///
    /// Requires `CAP_NET_ADMIN`; run with `sudo -E cargo test -- --ignored`.
    #[ignore = "requires CAP_NET_ADMIN and a real kernel"]
    #[tokio::test]
    async fn tests_from_yaml() {
        for mut test in tests() {
            test.cfg.country_ips = "test_assets/country_ips.db".into();

            test.cfg.apply().await.expect("apply failed");

            let actual = normalize(&dump(&test.cfg.table));
            let expect = normalize(&test.expect);
            if actual != expect {
                use diff::Result::*;
                println!("diff on test {}", test.name);
                for diff in diff::lines(&expect, &actual) {
                    match diff {
                        Left(l) => println!("-{l}"),
                        Both(l, _) => println!(" {l}"),
                        Right(r) => println!("+{r}"),
                    }
                }
                panic!("assertion failed for test {}", test.name);
            }
        }
    }

    #[test]
    fn tests_file_is_valid() {
        // ensure the yaml parses and every case has an expectation, without
        // needing a kernel
        for test in tests() {
            assert!(!test.name.is_empty());
            assert!(!test.expect.trim().is_empty());
        }
    }
}
