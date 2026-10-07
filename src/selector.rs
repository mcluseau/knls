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
#[derive(Clone, Debug, PartialEq, Eq)]
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SelectorOp {
    In,
    NotIn,
    Exists,
    DoesNotExist,
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
