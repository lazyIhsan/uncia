//! Reconciliation of `aws_lb_target_group_attachment` resources into their
//! owning target group's declared `targets`.
//!
//! The same "sibling resource" shape [`crate::diff::rules::SiblingRules`]
//! already solves for security-group rules, just simpler: no directions, no
//! rule-shape normalization, one attribute pair per attachment. Terraform has
//! no inline `targets` argument on `aws_lb_target_group` — registration is
//! this separate resource — while AWS reports a target group's registrations
//! on the group itself (`collector::aws::target_group`), so only the
//! *declared* side needs this.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::types::resource::{Resource, ResourceKind};

/// Declared target-group-attachment resources, indexed by the target group
/// they register a target with.
#[derive(Debug, Default)]
pub(crate) struct TargetAttachments {
    by_target_group: BTreeMap<String, Vec<String>>,
}

impl TargetAttachments {
    /// Index every declared `aws_lb_target_group_attachment` resource.
    ///
    /// An attachment contributes whether or not it has its own cloud id:
    /// unlike a comparison subject it is read as declared *intent*, the same
    /// reasoning [`SiblingRules::index`](super::rules::SiblingRules::index)
    /// already documents.
    pub(crate) fn index(declared: &[Resource]) -> Self {
        let mut by_target_group: BTreeMap<String, Vec<String>> = BTreeMap::new();

        for resource in declared {
            if resource.kind != ResourceKind::AwsLbTargetGroupAttachment {
                continue;
            }
            let Some(target_group_arn) = resource
                .attributes
                .get("target_group_arn")
                .and_then(Value::as_str)
            else {
                continue;
            };
            let Some(target_id) = resource.attributes.get("target_id").and_then(Value::as_str)
            else {
                continue;
            };
            by_target_group
                .entry(target_group_arn.to_string())
                .or_default()
                .push(target_id.to_string());
        }

        Self { by_target_group }
    }

    /// The target ids declared as registered to one target group.
    pub(crate) fn targets(&self, target_group_arn: &str) -> Vec<String> {
        self.by_target_group
            .get(target_group_arn)
            .cloned()
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn attachment(target_group_arn: &str, target_id: &str) -> Resource {
        Resource {
            id: crate::types::resource::ResourceId("aws_lb_target_group_attachment.x".to_string()),
            kind: ResourceKind::AwsLbTargetGroupAttachment,
            attributes: json!({
                "target_group_arn": target_group_arn,
                "target_id": target_id,
            })
            .as_object()
            .unwrap()
            .clone(),
        }
    }

    #[test]
    fn multiple_attachments_to_the_same_group_accumulate() {
        let declared = [attachment("arn:tg/1", "i-a"), attachment("arn:tg/1", "i-b")];
        let index = TargetAttachments::index(&declared);
        assert_eq!(index.targets("arn:tg/1"), vec!["i-a", "i-b"]);
    }

    #[test]
    fn attachments_to_different_groups_stay_separate() {
        let declared = [attachment("arn:tg/1", "i-a"), attachment("arn:tg/2", "i-b")];
        let index = TargetAttachments::index(&declared);
        assert_eq!(index.targets("arn:tg/1"), vec!["i-a"]);
        assert_eq!(index.targets("arn:tg/2"), vec!["i-b"]);
    }

    #[test]
    fn an_attachment_naming_no_target_group_contributes_nothing() {
        let declared = [Resource {
            id: crate::types::resource::ResourceId(
                "aws_lb_target_group_attachment.orphan".to_string(),
            ),
            kind: ResourceKind::AwsLbTargetGroupAttachment,
            attributes: json!({"target_id": "i-a"}).as_object().unwrap().clone(),
        }];
        assert!(
            TargetAttachments::index(&declared)
                .targets("arn:tg/1")
                .is_empty()
        );
    }

    #[test]
    fn an_attachment_naming_no_target_id_contributes_nothing() {
        let declared = [Resource {
            id: crate::types::resource::ResourceId(
                "aws_lb_target_group_attachment.no_target".to_string(),
            ),
            kind: ResourceKind::AwsLbTargetGroupAttachment,
            attributes: json!({"target_group_arn": "arn:tg/1"})
                .as_object()
                .unwrap()
                .clone(),
        }];
        assert!(
            TargetAttachments::index(&declared)
                .targets("arn:tg/1")
                .is_empty()
        );
    }

    #[test]
    fn an_unindexed_group_returns_empty() {
        let index = TargetAttachments::index(&[]);
        assert!(index.targets("arn:tg/unknown").is_empty());
    }

    #[test]
    fn a_resource_of_a_different_kind_is_ignored() {
        let declared = [Resource {
            id: crate::types::resource::ResourceId("aws_instance.web".to_string()),
            kind: ResourceKind::AwsInstance,
            attributes: json!({"target_group_arn": "arn:tg/1", "target_id": "i-a"})
                .as_object()
                .unwrap()
                .clone(),
        }];
        assert!(
            TargetAttachments::index(&declared)
                .targets("arn:tg/1")
                .is_empty()
        );
    }
}
