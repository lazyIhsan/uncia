//! Canonicalization of security-group rules, in every shape they arrive in.
//!
//! Lives here rather than in either consumer because both the behavioral and
//! the semantic pass reduce rules to atoms, and they must agree on how. The
//! normalizations are small but easy to get subtly wrong twice: an all-traffic
//! permission omits the ports on the wire and Terraform stores them as `0`, and
//! an absent protocol means "all", which Terraform stores as the literal
//! `"-1"`. A second copy of that logic that drifted would make the two passes
//! disagree about whether two rules are the same rule.
//!
//! # Three shapes, one vocabulary
//!
//! A group's rules can be declared three ways, and the field names differ more
//! than one would guess:
//!
//! | | inline block | `aws_security_group_rule` | `aws_vpc_security_group_*_rule` |
//! |---|---|---|---|
//! | direction | which block | `type` | the resource type |
//! | protocol | `protocol` | `protocol` | `ip_protocol` |
//! | IPv4 | `cidr_blocks` (list) | `cidr_blocks` (list) | `cidr_ipv4` (single) |
//! | other group | `security_groups` (list) | `source_security_group_id` | `referenced_security_group_id` |
//! | self | `self` (bool) | `self` (bool) | *no field* |
//!
//! All three reduce to the **same atom vocabulary** here, so comparison stays
//! in one place and a new rule form is a new arm of [`sibling_rule_atoms`] and
//! nothing else.
//!
//! The last column is the trap. The modern resources have no `self` field: a
//! self-reference is `referenced_security_group_id` pointing at the group's own
//! id. But `collector::aws::security_group` folds AWS's equivalent into
//! `self: true` and drops it from `security_groups`, so the live side emits a
//! `/self` atom. Without folding these together, every self-referencing rule
//! declared the modern way would read as drift.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

use crate::types::resource::{Resource, ResourceKind};

/// The canonical `"{protocol}/{from}-{to}"` prefix shared by every atom
/// derived from one rule.
///
/// Absent ports normalize to `0` and an absent protocol to `"-1"`, matching how
/// Terraform records an all-traffic rule.
pub(crate) fn rule_base(rule: &Value) -> String {
    base_from(rule, "protocol")
}

/// [`rule_base`] with the protocol read from a caller-chosen key, because the
/// modern rule resources spell it `ip_protocol`. Reading the wrong key would
/// silently yield the `"-1"` default and match nothing.
fn base_from(rule: &Value, protocol_key: &str) -> String {
    let from = rule.get("from_port").and_then(Value::as_i64).unwrap_or(0);
    let to = rule.get("to_port").and_then(Value::as_i64).unwrap_or(0);
    let protocol = protocol_of(rule, protocol_key);
    format!("{protocol}/{from}-{to}")
}

/// The protocol a rule specifies, normalized the way the live side reports it.
///
/// Terraform accepts `protocol = "all"`; AWS always answers `"-1"`.
fn protocol_of(rule: &Value, protocol_key: &str) -> String {
    match rule.get(protocol_key).and_then(Value::as_str) {
        Some("all") | None => "-1".to_string(),
        Some(other) => other.to_string(),
    }
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

/// Which of a group's rule lists a separately-declared rule contributes to.
fn direction_of(kind: &ResourceKind, attrs: &Map<String, Value>) -> Option<&'static str> {
    match kind {
        ResourceKind::AwsVpcSecurityGroupIngressRule => Some("ingress"),
        ResourceKind::AwsVpcSecurityGroupEgressRule => Some("egress"),
        // The legacy resource carries direction in a field rather than in its
        // type, so an egress rule must not be counted toward ingress.
        ResourceKind::AwsSecurityGroupRule => match attrs.get("type").and_then(Value::as_str) {
            Some("ingress") => Some("ingress"),
            Some("egress") => Some("egress"),
            _ => None,
        },
        _ => None,
    }
}

/// Rewrite one separately-declared rule into the shape an inline
/// `ingress`/`egress` block has, along with the list it belongs to.
///
/// Normalizing to the *inline shape* rather than straight to atoms is what
/// keeps this to one code path: atoms then come from [`explode_rules`] exactly
/// as they do for a real inline block, and the semantic pass — which reasons
/// over rule objects, not atoms — can consume the same output.
///
/// `own_group_id` is the group the rule targets: needed to fold a
/// self-reference into the `self` flag, which is how the live side reports it.
fn sibling_rule_block(
    kind: &ResourceKind,
    attrs: &Map<String, Value>,
    own_group_id: &str,
) -> Option<(&'static str, Value)> {
    let direction = direction_of(kind, attrs)?;
    let value = Value::Object(attrs.clone());

    let (protocol_key, sources): (&str, Vec<(&str, Vec<String>)>) = match kind {
        ResourceKind::AwsSecurityGroupRule => (
            "protocol",
            ["cidr_blocks", "ipv6_cidr_blocks", "prefix_list_ids"]
                .iter()
                .map(|key| {
                    let list = attrs
                        .get(*key)
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect();
                    (*key, list)
                })
                .collect(),
        ),
        ResourceKind::AwsVpcSecurityGroupIngressRule
        | ResourceKind::AwsVpcSecurityGroupEgressRule => (
            // Singular fields throughout: one rule resource carries exactly one
            // source, and reading `protocol` here instead of `ip_protocol`
            // would silently yield the "-1" default and match nothing.
            "ip_protocol",
            [
                ("cidr_ipv4", "cidr_blocks"),
                ("cidr_ipv6", "ipv6_cidr_blocks"),
                ("prefix_list_id", "prefix_list_ids"),
            ]
            .iter()
            .map(|(from, to)| {
                let list = attrs
                    .get(*from)
                    .and_then(Value::as_str)
                    .map(|v| vec![v.to_string()])
                    .unwrap_or_default();
                (*to, list)
            })
            .collect(),
        ),
        _ => return None,
    };

    let referenced = match kind {
        ResourceKind::AwsSecurityGroupRule => attrs.get("source_security_group_id"),
        _ => attrs.get("referenced_security_group_id"),
    }
    .and_then(Value::as_str);

    // A group reference naming the rule's own group is what the live side
    // reports as `self`, so the two must not be told apart here.
    let is_self = attrs.get("self").and_then(Value::as_bool).unwrap_or(false)
        || referenced == Some(own_group_id);
    let security_groups: Vec<String> = referenced
        .filter(|id| *id != own_group_id)
        .map(|id| vec![id.to_string()])
        .unwrap_or_default();

    let mut block = Map::new();
    block.insert("from_port".into(), json_i64(attrs.get("from_port")));
    block.insert("to_port".into(), json_i64(attrs.get("to_port")));
    block.insert(
        "protocol".into(),
        Value::String(protocol_of(&value, protocol_key)),
    );
    for (key, list) in sources {
        block.insert(
            key.into(),
            Value::Array(list.into_iter().map(Value::String).collect()),
        );
    }
    block.insert(
        "security_groups".into(),
        Value::Array(security_groups.into_iter().map(Value::String).collect()),
    );
    block.insert("self".into(), Value::Bool(is_self));

    Some((direction, Value::Object(block)))
}

fn json_i64(v: Option<&Value>) -> Value {
    Value::from(v.and_then(Value::as_i64).unwrap_or(0))
}

/// Atoms contributed by one separately-declared rule resource.
///
/// Production code goes through [`SiblingRules`], which keeps the blocks so the
/// semantic pass can reason over rule objects. This spells out the block-to-atom
/// step on its own so the tests can assert the three shapes agree.
#[cfg(test)]
fn sibling_rule_atoms(
    kind: &ResourceKind,
    attrs: &Map<String, Value>,
    own_group_id: &str,
) -> BTreeSet<String> {
    match sibling_rule_block(kind, attrs, own_group_id) {
        Some((_, block)) => explode_rules(&Value::Array(vec![block])),
        None => BTreeSet::new(),
    }
}

/// Rules declared as separate resources, indexed by the group they target.
///
/// Only the *declared* side needs this. AWS reports a group's rules on the
/// group whatever Terraform did, so the live side is already complete.
#[derive(Debug, Default)]
pub(crate) struct SiblingRules {
    by_group: BTreeMap<(String, &'static str), Vec<Value>>,
}

impl SiblingRules {
    /// Index every separately-declared rule in a set of declared resources.
    ///
    /// A rule contributes whether or not it has a cloud id: unlike a
    /// comparison subject it is read as declared *intent*, and intent counts
    /// before it has been applied.
    pub(crate) fn index(declared: &[Resource]) -> Self {
        let mut by_group: BTreeMap<(String, &'static str), Vec<Value>> = BTreeMap::new();

        for resource in declared {
            let Some(group) = resource
                .attributes
                .get("security_group_id")
                .and_then(Value::as_str)
            else {
                continue;
            };
            let Some((direction, block)) =
                sibling_rule_block(&resource.kind, &resource.attributes, group)
            else {
                continue;
            };
            by_group
                .entry((group.to_string(), direction))
                .or_default()
                .push(block);
        }

        Self { by_group }
    }

    /// Atoms contributed to one group's `ingress` or `egress` by sibling rules.
    pub(crate) fn atoms(&self, group_cloud_id: &str, direction: &str) -> BTreeSet<String> {
        explode_rules(&Value::Array(self.blocks(group_cloud_id, direction)))
    }

    /// Sibling rules as inline-shaped blocks, for callers that reason over rule
    /// objects rather than atoms (the semantic pass).
    pub(crate) fn blocks(&self, group_cloud_id: &str, direction: &str) -> Vec<Value> {
        self.by_group
            .get(&(group_cloud_id.to_string(), normalize_direction(direction)))
            .cloned()
            .unwrap_or_default()
    }
}

fn normalize_direction(direction: &str) -> &'static str {
    if direction == "egress" {
        "egress"
    } else {
        "ingress"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn attrs(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

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
    fn protocol_all_and_minus_one_are_the_same_rule() {
        assert_eq!(
            rule_base(&json!({"protocol": "all"})),
            rule_base(&json!({}))
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

    // --- The three shapes agree ---

    /// The property the whole design rests on: one logical rule reduces to the
    /// same atoms however it was declared.
    #[test]
    fn all_three_shapes_reduce_to_the_same_atom() {
        let inline = explode_rules(&json!([{
            "protocol": "tcp", "from_port": 443, "to_port": 443,
            "cidr_blocks": ["10.0.0.0/8"],
        }]));
        let legacy = sibling_rule_atoms(
            &ResourceKind::AwsSecurityGroupRule,
            &attrs(
                json!({"type": "ingress", "protocol": "tcp", "from_port": 443,
                          "to_port": 443, "cidr_blocks": ["10.0.0.0/8"]}),
            ),
            "sg-web",
        );
        let modern = sibling_rule_atoms(
            &ResourceKind::AwsVpcSecurityGroupIngressRule,
            &attrs(
                json!({"ip_protocol": "tcp", "from_port": 443, "to_port": 443,
                          "cidr_ipv4": "10.0.0.0/8"}),
            ),
            "sg-web",
        );

        assert_eq!(inline, legacy);
        assert_eq!(inline, modern);
        assert_eq!(
            inline,
            BTreeSet::from(["tcp/443-443/cidr:10.0.0.0/8".to_string()])
        );
    }

    #[test]
    fn the_modern_form_reads_ip_protocol_not_protocol() {
        // Reading "protocol" here would fall back to the "-1" default and
        // silently match nothing.
        let atoms = sibling_rule_atoms(
            &ResourceKind::AwsVpcSecurityGroupIngressRule,
            &attrs(
                json!({"ip_protocol": "tcp", "from_port": 443, "to_port": 443,
                          "cidr_ipv4": "10.0.0.0/8"}),
            ),
            "sg-web",
        );
        assert!(atoms.contains("tcp/443-443/cidr:10.0.0.0/8"), "{atoms:?}");
    }

    #[test]
    fn a_modern_reference_to_the_own_group_becomes_the_self_atom() {
        let atoms = sibling_rule_atoms(
            &ResourceKind::AwsVpcSecurityGroupIngressRule,
            &attrs(json!({"ip_protocol": "-1", "referenced_security_group_id": "sg-web"})),
            "sg-web",
        );
        assert_eq!(atoms, BTreeSet::from(["-1/0-0/self".to_string()]));
    }

    #[test]
    fn a_legacy_source_of_the_own_group_becomes_the_self_atom() {
        let atoms = sibling_rule_atoms(
            &ResourceKind::AwsSecurityGroupRule,
            &attrs(json!({"type": "ingress", "protocol": "-1",
                          "source_security_group_id": "sg-web"})),
            "sg-web",
        );
        assert_eq!(atoms, BTreeSet::from(["-1/0-0/self".to_string()]));
    }

    #[test]
    fn a_reference_to_another_group_stays_a_group_atom() {
        let atoms = sibling_rule_atoms(
            &ResourceKind::AwsVpcSecurityGroupIngressRule,
            &attrs(
                json!({"ip_protocol": "tcp", "from_port": 443, "to_port": 443,
                          "referenced_security_group_id": "sg-app"}),
            ),
            "sg-web",
        );
        assert_eq!(atoms, BTreeSet::from(["tcp/443-443/sg:sg-app".to_string()]));
    }

    #[test]
    fn ipv6_and_prefix_lists_survive_the_singular_to_plural_difference() {
        let modern = sibling_rule_atoms(
            &ResourceKind::AwsVpcSecurityGroupIngressRule,
            &attrs(
                json!({"ip_protocol": "tcp", "from_port": 443, "to_port": 443,
                          "cidr_ipv6": "::/0", "prefix_list_id": "pl-1"}),
            ),
            "sg-web",
        );
        let inline = explode_rules(&json!([{
            "protocol": "tcp", "from_port": 443, "to_port": 443,
            "ipv6_cidr_blocks": ["::/0"], "prefix_list_ids": ["pl-1"],
        }]));
        assert_eq!(modern, inline);
    }

    // --- Indexing ---

    fn rule_resource(address: &str, kind: ResourceKind, values: Value) -> Resource {
        Resource {
            id: crate::types::resource::ResourceId(address.to_string()),
            kind,
            attributes: attrs(values),
        }
    }

    #[test]
    fn the_index_separates_directions_and_groups() {
        let declared = [
            rule_resource(
                "aws_vpc_security_group_ingress_rule.a",
                ResourceKind::AwsVpcSecurityGroupIngressRule,
                json!({"security_group_id": "sg-web", "ip_protocol": "tcp",
                       "from_port": 443, "to_port": 443, "cidr_ipv4": "0.0.0.0/0"}),
            ),
            rule_resource(
                "aws_vpc_security_group_egress_rule.b",
                ResourceKind::AwsVpcSecurityGroupEgressRule,
                json!({"security_group_id": "sg-web", "ip_protocol": "-1",
                       "cidr_ipv4": "0.0.0.0/0"}),
            ),
            rule_resource(
                "aws_vpc_security_group_ingress_rule.other",
                ResourceKind::AwsVpcSecurityGroupIngressRule,
                json!({"security_group_id": "sg-other", "ip_protocol": "tcp",
                       "from_port": 22, "to_port": 22, "cidr_ipv4": "0.0.0.0/0"}),
            ),
        ];
        let index = SiblingRules::index(&declared);

        assert_eq!(
            index.atoms("sg-web", "ingress"),
            BTreeSet::from(["tcp/443-443/cidr:0.0.0.0/0".to_string()])
        );
        assert_eq!(
            index.atoms("sg-web", "egress"),
            BTreeSet::from(["-1/0-0/cidr:0.0.0.0/0".to_string()])
        );
        assert_eq!(
            index.atoms("sg-other", "ingress"),
            BTreeSet::from(["tcp/22-22/cidr:0.0.0.0/0".to_string()])
        );
        assert!(index.atoms("sg-nothing", "ingress").is_empty());
    }

    #[test]
    fn a_legacy_rule_with_no_type_contributes_nothing() {
        // Direction is required to know which list it belongs to; guessing
        // would put an egress rule in ingress.
        let declared = [rule_resource(
            "aws_security_group_rule.broken",
            ResourceKind::AwsSecurityGroupRule,
            json!({"security_group_id": "sg-web", "protocol": "tcp"}),
        )];
        let index = SiblingRules::index(&declared);
        assert!(index.atoms("sg-web", "ingress").is_empty());
        assert!(index.atoms("sg-web", "egress").is_empty());
    }

    #[test]
    fn a_rule_naming_no_group_contributes_nothing() {
        let declared = [rule_resource(
            "aws_vpc_security_group_ingress_rule.orphan",
            ResourceKind::AwsVpcSecurityGroupIngressRule,
            json!({"ip_protocol": "tcp", "cidr_ipv4": "0.0.0.0/0"}),
        )];
        assert!(
            SiblingRules::index(&declared)
                .atoms("sg-web", "ingress")
                .is_empty()
        );
    }
}
