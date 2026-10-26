//! A pre-parsed [`LabelSelector`], for matching k8s objects by their labels.

use eyre::{Result, eyre};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, LabelSelectorRequirement};
use std::collections::{BTreeMap as Map, BTreeSet as Set};

/// A pre-parsed [`LabelSelector`], so matching objects needs no re-interpretation
/// of the raw object.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Selector {
    match_labels: Map<String, String>,
    match_expressions: Vec<SelectorExpr>,
}

impl Selector {
    /// Whether `labels` satisfy every label and expression constraint.
    ///
    /// An absent or empty constraint matches everything.
    pub fn matches(&self, labels: &Map<String, String>) -> bool {
        self.match_labels
            .iter()
            .all(|(k, v)| labels.get(k) == Some(v))
            && self
                .match_expressions
                .iter()
                .all(|expr| expr.matches(labels))
    }

    /// Canonical, length-prefixed encoding, used to derive shared set names.
    ///
    /// `matchLabels` are already sorted; `matchExpressions` are sorted here, so
    /// semantically identical selectors encode identically regardless of the
    /// order they were written in.
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        fn put_u32(out: &mut Vec<u8>, value: u32) {
            out.extend_from_slice(&value.to_be_bytes());
        }
        fn put_bytes(out: &mut Vec<u8>, value: impl AsRef<[u8]>) {
            let value = value.as_ref();
            put_u32(out, value.len() as u32);
            out.extend_from_slice(value);
        }

        put_u32(out, self.match_labels.len() as u32);
        for (key, value) in &self.match_labels {
            put_bytes(out, key);
            put_bytes(out, value);
        }

        let mut exprs: Vec<_> = self.match_expressions.iter().collect();
        exprs.sort();
        put_u32(out, exprs.len() as u32);
        for expr in exprs {
            put_bytes(out, &expr.key);
            out.push(expr.operator.code());
            match &expr.values {
                Some(values) => {
                    out.push(1);
                    put_u32(out, values.len() as u32);
                    for value in values {
                        put_bytes(out, value);
                    }
                }
                None => out.push(0),
            }
        }
    }

    /// A k8s-ish human form, for set comments: `app=a,env in (prod)`.
    ///
    /// An empty selector is rendered `*` (matches everything).
    pub fn describe(&self) -> String {
        let mut parts: Vec<String> = self
            .match_labels
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect();

        let mut exprs: Vec<_> = self.match_expressions.iter().collect();
        exprs.sort();
        for expr in exprs {
            let key = &expr.key;
            let values = || {
                expr.values
                    .iter()
                    .flatten()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(",")
            };
            parts.push(match expr.operator {
                SelectorOp::In => format!("{key} in ({})", values()),
                SelectorOp::NotIn => format!("{key} notin ({})", values()),
                SelectorOp::Exists => key.clone(),
                SelectorOp::DoesNotExist => format!("!{key}"),
            });
        }

        if parts.is_empty() {
            "*".into()
        } else {
            parts.join(",")
        }
    }
}

impl TryFrom<&LabelSelector> for Selector {
    type Error = eyre::Error;

    fn try_from(selector: &LabelSelector) -> Result<Self> {
        Ok(Self {
            match_labels: selector.match_labels.clone().unwrap_or_default(),
            match_expressions: (selector.match_expressions.as_deref().unwrap_or_default())
                .iter()
                .map(SelectorExpr::try_from)
                .collect::<Result<_>>()?,
        })
    }
}

/// A pre-parsed [`LabelSelectorRequirement`].
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct SelectorExpr {
    key: String,
    operator: SelectorOp,
    values: Option<Set<String>>,
}

impl SelectorExpr {
    fn matches(&self, labels: &Map<String, String>) -> bool {
        let value = labels.get(&self.key);
        match self.operator {
            SelectorOp::Exists => value.is_some(),
            SelectorOp::DoesNotExist => value.is_none(),
            SelectorOp::In => {
                value.is_some_and(|value| self.values.as_ref().is_some_and(|v| v.contains(value)))
            }
            SelectorOp::NotIn => {
                value.is_none_or(|value| self.values.as_ref().is_some_and(|v| !v.contains(value)))
            }
        }
    }
}

impl TryFrom<&LabelSelectorRequirement> for SelectorExpr {
    type Error = eyre::Error;

    fn try_from(req: &LabelSelectorRequirement) -> Result<Self> {
        Ok(Self {
            key: req.key.clone(),
            operator: req.operator.as_str().try_into()?,
            values: req
                .values
                .as_ref()
                .map(|values| values.iter().cloned().collect()),
        })
    }
}

/// The operator of a [`SelectorExpr`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SelectorOp {
    In,
    NotIn,
    Exists,
    DoesNotExist,
}

impl SelectorOp {
    /// A stable discriminant for [`Selector::encode_into`].
    fn code(self) -> u8 {
        match self {
            Self::In => 0,
            Self::NotIn => 1,
            Self::Exists => 2,
            Self::DoesNotExist => 3,
        }
    }
}

impl TryFrom<&str> for SelectorOp {
    type Error = eyre::Error;

    fn try_from(operator: &str) -> Result<Self> {
        match operator {
            "In" => Ok(Self::In),
            "NotIn" => Ok(Self::NotIn),
            "Exists" => Ok(Self::Exists),
            "DoesNotExist" => Ok(Self::DoesNotExist),
            other => Err(eyre!("unknown selector operator {other:?}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn selector(json: serde_json::Value) -> Selector {
        Selector::try_from(&serde_json::from_value(json).expect("selector")).expect("parse")
    }

    fn labels(pairs: &[(&str, &str)]) -> Map<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn empty_matches_everything() {
        assert!(selector(serde_json::json!({})).matches(&labels(&[("app", "a")])));
        assert!(selector(serde_json::json!({})).matches(&Map::new()));
    }

    #[test]
    fn match_labels_are_anded() {
        let s = selector(serde_json::json!({ "matchLabels": { "app": "a", "tier": "web" } }));
        assert!(s.matches(&labels(&[("app", "a"), ("tier", "web")])));
        assert!(!s.matches(&labels(&[("app", "a")])));
        assert!(!s.matches(&labels(&[("app", "b"), ("tier", "web")])));
    }

    #[test]
    fn match_expressions_operators() {
        let s = selector(serde_json::json!({
            "matchExpressions": [
                { "key": "env", "operator": "In", "values": ["prod", "staging"] },
                { "key": "team", "operator": "NotIn", "values": ["other"] },
                { "key": "app", "operator": "Exists" },
                { "key": "deprecated", "operator": "DoesNotExist" },
            ]
        }));

        assert!(s.matches(&labels(&[("env", "prod"), ("app", "a")])));
        assert!(!s.matches(&labels(&[("env", "dev"), ("app", "a")])));
        assert!(!s.matches(&labels(&[("env", "prod"), ("team", "other"), ("app", "a")])));
        assert!(!s.matches(&labels(&[("env", "prod")])));
        assert!(!s.matches(&labels(&[
            ("env", "prod"),
            ("app", "a"),
            ("deprecated", "yes")
        ])));
    }

    /// Expressions are hashed and described in a canonical (sorted) order, so
    /// the same selector written differently names the same set.
    #[test]
    fn encoding_and_description_are_canonical() {
        let a = selector(serde_json::json!({
            "matchExpressions": [
                { "key": "env", "operator": "In", "values": ["prod", "staging"] },
                { "key": "app", "operator": "Exists" },
            ]
        }));
        let b = selector(serde_json::json!({
            "matchExpressions": [
                { "key": "app", "operator": "Exists" },
                { "key": "env", "operator": "In", "values": ["staging", "prod"] },
            ]
        }));

        let (mut ea, mut eb) = (Vec::new(), Vec::new());
        a.encode_into(&mut ea);
        b.encode_into(&mut eb);
        assert_eq!(ea, eb);
        assert_eq!(a.describe(), b.describe());
    }

    #[test]
    fn describe_is_k8s_ish() {
        let s = selector(serde_json::json!({
            "matchLabels": { "app": "a" },
            "matchExpressions": [
                { "key": "env", "operator": "In", "values": ["prod", "staging"] },
                { "key": "team", "operator": "NotIn", "values": ["other"] },
                { "key": "tracked", "operator": "Exists" },
                { "key": "deprecated", "operator": "DoesNotExist" },
            ]
        }));
        assert_eq!(
            s.describe(),
            "app=a,!deprecated,env in (prod,staging),team notin (other),tracked"
        );
        assert_eq!(selector(serde_json::json!({})).describe(), "*");
    }

    #[test]
    fn unknown_operator_is_an_error() {
        let selector: LabelSelector = serde_json::from_value(serde_json::json!({
            "matchExpressions": [{ "key": "app", "operator": "Bogus", "values": ["a"] }]
        }))
        .expect("selector");
        assert!(Selector::try_from(&selector).is_err());
    }

    #[test]
    fn labels_and_expressions_are_combined() {
        let s = selector(serde_json::json!({
            "matchLabels": { "app": "a" },
            "matchExpressions": [{ "key": "env", "operator": "In", "values": ["prod"] }],
        }));
        assert!(s.matches(&labels(&[("app", "a"), ("env", "prod")])));
        assert!(!s.matches(&labels(&[("app", "a"), ("env", "dev")])));
    }
}
