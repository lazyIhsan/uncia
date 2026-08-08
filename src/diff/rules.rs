//! Canonicalization of security-group rule lists.
//!
//! Lives here rather than in either consumer because both the behavioral and
//! the semantic pass reduce rules to atoms, and they must agree on how. The
//! normalizations are small but easy to get subtly wrong twice: an all-traffic
//! permission omits the ports on the wire and Terraform stores them as `0`, and
//! an absent protocol means "all", which Terraform stores as the literal
//! `"-1"`. A second copy of that logic that drifted would make the two passes
//! disagree about whether two rules are the same rule.

use std::collections::BTreeSet;

use serde_json::Value;

/// The canonical `"{protocol}/{from}-{to}"` prefix shared by every atom
/// derived from one rule.
///
/// Absent ports normalize to `0` and an absent protocol to `"-1"`, matching how
/// Terraform records an all-traffic rule.
pub(crate) fn rule_base(rule: &Value) -> String {
    let from = rule.get("from_port").and_then(Value::as_i64).unwrap_or(0);
    let to = rule.get("to_port").and_then(Value::as_i64).unwrap_or(0);
    let protocol = rule.get("protocol").and_then(Value::as_str).unwrap_or("-1");
    format!("{protocol}/{from}-{to}")
}

/// Explode a rule list into a canonical set of atoms, one per
/// (port-range, protocol, source). Insensitive to rule order *and* to how
/// sources are grouped into rules — AWS and Terraform group differently, and
/// neither grouping is meaningful.
///
/// Rule descriptions are deliberately not part of the atom (see module docs
/// in `collector::aws::security_group`).
pub(crate) fn explode_rules(rules: &Value) -> BTreeSet<String> {
    let mut atoms = BTreeSet::new();
    let Some(list) = rules.as_array() else {
        return atoms;
    };
    for rule in list {
        let base = rule_base(rule);

        for (key, tag) in [
            ("cidr_blocks", "cidr"),
            ("ipv6_cidr_blocks", "cidr6"),
            ("prefix_list_ids", "pl"),
            ("security_groups", "sg"),
        ] {
            if let Some(sources) = rule.get(key).and_then(Value::as_array) {
                for source in sources {
                    if let Some(source) = source.as_str() {
                        atoms.insert(format!("{base}/{tag}:{source}"));
                    }
                }
            }
        }
        if rule.get("self").and_then(Value::as_bool).unwrap_or(false) {
            atoms.insert(format!("{base}/self"));
        }
    }
    atoms
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn all_traffic_rule_normalizes_absent_ports_and_protocol() {
        // An all-traffic permission arrives with no ports and no protocol;
        // both passes must read it as Terraform's "-1/0-0".
        assert_eq!(rule_base(&json!({})), "-1/0-0");
        assert_eq!(
            rule_base(&json!({"protocol": "tcp", "from_port": 443, "to_port": 443})),
            "tcp/443-443"
        );
    }

    #[test]
    fn grouping_of_sources_into_rules_is_not_meaningful() {
        let split = json!([
            {"protocol": "tcp", "from_port": 443, "to_port": 443, "cidr_blocks": ["10.0.0.0/8"]},
            {"protocol": "tcp", "from_port": 443, "to_port": 443, "cidr_blocks": ["192.168.0.0/16"]},
        ]);
        let grouped = json!([
            {"protocol": "tcp", "from_port": 443, "to_port": 443,
             "cidr_blocks": ["192.168.0.0/16", "10.0.0.0/8"]},
        ]);
        assert_eq!(explode_rules(&split), explode_rules(&grouped));
    }

    #[test]
    fn self_reference_and_group_sources_are_distinct_atoms() {
        let atoms = explode_rules(&json!([{
            "protocol": "tcp", "from_port": 443, "to_port": 443,
            "security_groups": ["sg-app"], "self": true,
        }]));
        assert!(atoms.contains("tcp/443-443/sg:sg-app"), "{atoms:?}");
        assert!(atoms.contains("tcp/443-443/self"), "{atoms:?}");
    }

    #[test]
    fn a_non_array_rule_list_explodes_to_nothing() {
        assert!(explode_rules(&Value::Null).is_empty());
    }
}
