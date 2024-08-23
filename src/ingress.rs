use std::collections::{BTreeMap as Map, BTreeSet as Set};

pub type Config = Map<String, HostConfig>;

#[derive(Debug, PartialEq, Eq, serde::Serialize)]
struct HostConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    tls_secret: Option<keys::Object>,
    #[serde(skip_serializing_if = "Map::is_empty")]
    exact_matches: Map<String, Set<Endpoint>>,
    #[serde(skip_serializing_if = "Map::is_empty")]
    prefix_matches: Map<String, Set<Endpoint>>,
    #[serde(skip_serializing_if = "Set::is_empty")]
    any_match: Set<Endpoint>,
}
impl Default for HostConfig {
    fn default() -> Self {
        Self {
            tls_secret: None,
            exact_matches: Map::new(),
            prefix_matches: Map::new(),
            any_match: Set::new(),
        }
    }
}
