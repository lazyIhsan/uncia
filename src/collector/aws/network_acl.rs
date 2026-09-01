//! AWS network ACL collection.
//!
//! Fetches network ACLs via `DescribeNetworkAcls` and normalizes each into
//! the attribute names and shapes Terraform state uses for
//! `aws_network_acl`, so the diff compares like against like.
//!
//! Normalization pitfalls handled here, verified against
//! `terraform-provider-aws`'s `internal/service/ec2/vpc_network_acl.go` and
//! `vpc_default_network_acl.go`, not assumed:
//! - AWS auto-creates an implicit "deny all" rule on every NACL, ingress and
//!   egress, at rule number 32767 (IPv4) / 32768 (IPv6). These can be
//!   neither configured nor deleted by users, and Terraform's own read skips
//!   them for exactly that reason — collecting them here would report
//!   permanent phantom drift on every account, so [`fetch`] filters them the
//!   same way.
//! - `protocol` is already a protocol-*number* string on the wire (the SDK's
//!   own doc: `"-1"` means all protocols) and Terraform records exactly that
//!   number, not a name — unlike `aws_security_group`'s `ingress`/`egress`,
//!   which speaks protocol names. No name-to-number translation needed here.
//! - `action` is `RuleAction::Allow`/`Deny`; `.as_str()` gives the lowercase
//!   `"allow"`/`"deny"` Terraform's schema stores.
//! - `subnet_ids` isn't inferred the way security-group membership is
//!   elsewhere in uncia — a NACL declares its subnet associations directly
//!   (`aws_network_acl.subnet_ids`), so this is a flat, directly-comparable
//!   field, built from `associations[].subnet_id`.
//! - `from_port`/`to_port` absent (protocol `-1`, or an ICMP rule) normalize
//!   to `0`, and `icmp_type`/`icmp_code` absent (a non-ICMP rule) normalize
//!   to `0` too — the same convention `security_group.rs` uses for its own
//!   absent-port case.
//!
//! Not yet handled: `aws_network_acl_rule` (a NACL's entries declared as
//! their own resource, mirroring `aws_security_group_rule`) has no
//! reconciliation into the owning NACL's `ingress`/`egress` here — only
//! inline-declared rules are compared correctly today.

use aws_sdk_ec2::error::DisplayErrorContext;
use aws_sdk_ec2::types::{NetworkAcl, NetworkAclEntry};
use serde_json::{Map, Value, json};

use crate::collector::LiveResource;
use crate::error::UnciaError;
use crate::types::resource::ResourceKind;

/// AWS auto-creates these two rules (implicit IPv4/IPv6 deny-all) on every
/// network ACL. They can be neither configured nor deleted, and Terraform's
/// own read skips them — see the module docs.
const IMPLICIT_DENY_ALL_RULE_NUMBERS: [i32; 2] = [32767, 32768];

/// Fetch and normalize all network ACLs visible to the client.
pub async fn fetch(client: &aws_sdk_ec2::Client) -> crate::Result<Vec<LiveResource>> {
    let mut out = Vec::new();
    let mut pages = client.describe_network_acls().into_paginator().send();
    while let Some(page) = pages.next().await {
        let page = page.map_err(|e| {
            UnciaError::Collector(format!("DescribeNetworkAcls: {}", DisplayErrorContext(&e)))
        })?;
        for nacl in page.network_acls() {
            if let Some(live) = normalize(nacl) {
                out.push(live);
            }
        }
    }
    Ok(out)
}

/// Normalize one API-shaped network ACL into Terraform-state-shaped
/// attributes. Returns `None` for a NACL with no id (never observed in
/// practice, but the API models it as optional).
fn normalize(nacl: &NetworkAcl) -> Option<LiveResource> {
    let id = nacl.network_acl_id()?.to_string();

    let tags: Map<String, Value> = nacl
        .tags()
        .iter()
        .filter_map(|t| Some((t.key()?.to_string(), json!(t.value().unwrap_or_default()))))
        .collect();

    let mut subnet_ids: Vec<&str> = nacl
        .associations()
        .iter()
        .filter_map(|a| a.subnet_id())
        .collect();
    subnet_ids.sort_unstable();

    let configured = nacl
        .entries()
        .iter()
        .filter(|e| !IMPLICIT_DENY_ALL_RULE_NUMBERS.contains(&e.rule_number().unwrap_or_default()));
    let (egress, ingress): (Vec<&NetworkAclEntry>, Vec<&NetworkAclEntry>) =
        configured.partition(|e| e.egress().unwrap_or(false));

    let mut attributes = Map::new();
    attributes.insert("id".into(), json!(id));
    attributes.insert("vpc_id".into(), json!(nacl.vpc_id().unwrap_or_default()));
    attributes.insert(
        "owner_id".into(),
        json!(nacl.owner_id().unwrap_or_default()),
    );
    attributes.insert("subnet_ids".into(), json!(subnet_ids));
    attributes.insert("tags".into(), Value::Object(tags));
    attributes.insert("ingress".into(), entries_to_value(&ingress));
    attributes.insert("egress".into(), entries_to_value(&egress));

    Some(LiveResource {
        cloud_id: id,
        kind: ResourceKind::AwsNetworkAcl,
        attributes,
    })
}

fn entries_to_value(entries: &[&NetworkAclEntry]) -> Value {
    Value::Array(
        entries
            .iter()
            .map(|e| {
                let (from_port, to_port) = e
                    .port_range()
                    .map(|p| (p.from().unwrap_or(0), p.to().unwrap_or(0)))
                    .unwrap_or((0, 0));
                let (icmp_type, icmp_code) = e
                    .icmp_type_code()
                    .map(|c| (c.r#type().unwrap_or(0), c.code().unwrap_or(0)))
                    .unwrap_or((0, 0));
                json!({
                    "rule_no": e.rule_number().unwrap_or_default(),
                    "action": e.rule_action().map(|a| a.as_str()).unwrap_or_default(),
                    "protocol": e.protocol().unwrap_or_default(),
                    "cidr_block": e.cidr_block().unwrap_or_default(),
                    "ipv6_cidr_block": e.ipv6_cidr_block().unwrap_or_default(),
                    "from_port": from_port,
                    "to_port": to_port,
                    "icmp_type": icmp_type,
                    "icmp_code": icmp_code,
                })
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_sdk_ec2::types::{IcmpTypeCode, NetworkAclAssociation, PortRange, RuleAction, Tag};

    fn entry(
        rule_no: i32,
        egress: bool,
        action: RuleAction,
        protocol: &str,
        cidr: &str,
    ) -> NetworkAclEntry {
        NetworkAclEntry::builder()
            .rule_number(rule_no)
            .egress(egress)
            .rule_action(action)
            .protocol(protocol)
            .cidr_block(cidr)
            .build()
    }

    fn sample_nacl() -> NetworkAcl {
        NetworkAcl::builder()
            .network_acl_id("acl-0123456789abcdef0")
            .vpc_id("vpc-0aa11bb22cc33dd44")
            .owner_id("123456789012")
            .is_default(false)
            .tags(Tag::builder().key("Name").value("web").build())
            .associations(
                NetworkAclAssociation::builder()
                    .network_acl_association_id("aclassoc-1")
                    .network_acl_id("acl-0123456789abcdef0")
                    .subnet_id("subnet-b")
                    .build(),
            )
            .associations(
                NetworkAclAssociation::builder()
                    .network_acl_association_id("aclassoc-2")
                    .network_acl_id("acl-0123456789abcdef0")
                    .subnet_id("subnet-a")
                    .build(),
            )
            .entries(
                NetworkAclEntry::builder()
                    .rule_number(100)
                    .egress(false)
                    .rule_action(RuleAction::Allow)
                    .protocol("6")
                    .cidr_block("0.0.0.0/0")
                    .port_range(PortRange::builder().from(443).to(443).build())
                    .build(),
            )
            .entries(entry(200, false, RuleAction::Deny, "-1", "10.0.0.0/8"))
            .entries(entry(100, true, RuleAction::Allow, "-1", "0.0.0.0/0"))
            // The implicit deny-all rules AWS always adds — must be filtered.
            .entries(entry(32767, false, RuleAction::Deny, "-1", "0.0.0.0/0"))
            .entries(entry(32768, false, RuleAction::Deny, "-1", "::/0"))
            .entries(entry(32767, true, RuleAction::Deny, "-1", "0.0.0.0/0"))
            .entries(entry(32768, true, RuleAction::Deny, "-1", "::/0"))
            .build()
    }

    #[test]
    fn normalizes_to_terraform_shape() {
        let live = normalize(&sample_nacl()).unwrap();

        assert_eq!(live.cloud_id, "acl-0123456789abcdef0");
        assert_eq!(live.kind, ResourceKind::AwsNetworkAcl);
        assert_eq!(live.attributes["id"], "acl-0123456789abcdef0");
        assert_eq!(live.attributes["vpc_id"], "vpc-0aa11bb22cc33dd44");
        assert_eq!(live.attributes["owner_id"], "123456789012");
        assert_eq!(live.attributes["tags"]["Name"], "web");
        // Sorted, not discovery order.
        assert_eq!(
            live.attributes["subnet_ids"],
            json!(["subnet-a", "subnet-b"])
        );

        let ingress = live.attributes["ingress"].as_array().unwrap();
        assert_eq!(
            ingress.len(),
            2,
            "the two implicit deny-all rules are excluded"
        );
        let allow_443 = ingress.iter().find(|r| r["rule_no"] == 100).unwrap();
        assert_eq!(allow_443["action"], "allow");
        assert_eq!(allow_443["protocol"], "6");
        assert_eq!(allow_443["cidr_block"], "0.0.0.0/0");
        assert_eq!(allow_443["from_port"], 443);
        assert_eq!(allow_443["to_port"], 443);
        assert_eq!(allow_443["icmp_type"], 0);
        assert_eq!(allow_443["icmp_code"], 0);

        let deny_all = ingress.iter().find(|r| r["rule_no"] == 200).unwrap();
        assert_eq!(deny_all["action"], "deny");
        assert_eq!(deny_all["protocol"], "-1");
        assert_eq!(deny_all["cidr_block"], "10.0.0.0/8");
        // Protocol -1 carries no port range: normalizes to 0, not absent.
        assert_eq!(deny_all["from_port"], 0);
        assert_eq!(deny_all["to_port"], 0);

        let egress = live.attributes["egress"].as_array().unwrap();
        assert_eq!(
            egress.len(),
            1,
            "the two implicit deny-all rules are excluded"
        );
        assert_eq!(egress[0]["rule_no"], 100);
        assert_eq!(egress[0]["action"], "allow");
    }

    #[test]
    fn an_icmp_rule_normalizes_type_and_code() {
        let nacl = NetworkAcl::builder()
            .network_acl_id("acl-icmp")
            .vpc_id("vpc-1")
            .entries(
                NetworkAclEntry::builder()
                    .rule_number(50)
                    .egress(false)
                    .rule_action(RuleAction::Allow)
                    .protocol("1")
                    .cidr_block("0.0.0.0/0")
                    .icmp_type_code(IcmpTypeCode::builder().r#type(8).code(0).build())
                    .build(),
            )
            .build();

        let live = normalize(&nacl).unwrap();
        let rule = &live.attributes["ingress"][0];
        assert_eq!(rule["protocol"], "1");
        assert_eq!(rule["icmp_type"], 8);
        assert_eq!(rule["icmp_code"], 0);
        // ICMP rules carry no port range: normalizes to 0, not absent.
        assert_eq!(rule["from_port"], 0);
        assert_eq!(rule["to_port"], 0);
    }

    #[test]
    fn a_nacl_with_no_associated_subnets_normalizes_to_an_empty_list() {
        let nacl = NetworkAcl::builder()
            .network_acl_id("acl-unattached")
            .vpc_id("vpc-1")
            .build();

        let live = normalize(&nacl).unwrap();
        assert_eq!(live.attributes["subnet_ids"], json!([]));
        assert_eq!(live.attributes["ingress"], json!([]));
        assert_eq!(live.attributes["egress"], json!([]));
    }

    #[test]
    fn a_nacl_with_no_id_is_not_collected() {
        let nacl = NetworkAcl::builder().vpc_id("vpc-1").build();
        assert!(normalize(&nacl).is_none());
    }
}
