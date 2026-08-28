//! Resource model: the unit of infrastructure uncia tracks.

use serde_json::{Map, Value};

/// Stable identifier for a resource: the **Terraform address**
/// (e.g. `aws_instance.web`, `module.network.aws_security_group.internal`).
///
/// Invariant (`docs/ARCHITECTURE.md`): this is *not* the cloud-assigned ID.
/// The cloud ID lives in `attributes["id"]` and is read via
/// [`Resource::cloud_id`]. The Terraform address is stable across replaces;
/// the cloud ID is not.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ResourceId(pub String);

/// The kind of infrastructure resource (e.g. EC2 instance, security group).
///
/// Kinds uncia knows how to collect get their own variant; everything else
/// is carried through as [`ResourceKind::Other`] so unknown resources are
/// still parsed and reportable, just not collectable.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ResourceKind {
    AwsSecurityGroup,
    AwsInstance,
    /// A rule declared as its own resource rather than inline on the group.
    ///
    /// These are never compared against live observations — no collector
    /// returns them, because AWS reports a group's rules on the group. They
    /// are read only as *declared intent*, and reconciled into the owning
    /// group's rule set before comparison. See `crate::diff::rules`.
    AwsSecurityGroupRule,
    AwsVpcSecurityGroupIngressRule,
    AwsVpcSecurityGroupEgressRule,
    Other(String),
}

impl ResourceKind {
    /// Map a Terraform resource type (e.g. `"aws_security_group"`) to a kind.
    pub fn from_terraform_type(terraform_type: &str) -> Self {
        match terraform_type {
            "aws_security_group" => Self::AwsSecurityGroup,
            "aws_instance" => Self::AwsInstance,
            "aws_security_group_rule" => Self::AwsSecurityGroupRule,
            "aws_vpc_security_group_ingress_rule" => Self::AwsVpcSecurityGroupIngressRule,
            "aws_vpc_security_group_egress_rule" => Self::AwsVpcSecurityGroupEgressRule,
            other => Self::Other(other.to_string()),
        }
    }

    /// The Terraform resource type string for this kind.
    pub fn as_str(&self) -> &str {
        match self {
            Self::AwsSecurityGroup => "aws_security_group",
            Self::AwsInstance => "aws_instance",
            Self::AwsSecurityGroupRule => "aws_security_group_rule",
            Self::AwsVpcSecurityGroupIngressRule => "aws_vpc_security_group_ingress_rule",
            Self::AwsVpcSecurityGroupEgressRule => "aws_vpc_security_group_egress_rule",
            Self::Other(s) => s,
        }
    }
}

/// A single tracked infrastructure resource, as declared in state.
#[derive(Debug, Clone)]
pub struct Resource {
    pub id: ResourceId,
    pub kind: ResourceKind,
    /// The resource's attribute values as recorded in Terraform state.
    pub attributes: Map<String, Value>,
}

impl Resource {
    /// The cloud-assigned identifier (e.g. `i-0abc123`, `sg-0def456`), if the
    /// state recorded one.
    ///
    /// This is the one place the `attributes["id"]` convention is encoded;
    /// joining declared resources to live observations must go through here,
    /// never through [`ResourceId`].
    pub fn cloud_id(&self) -> Option<&str> {
        self.attributes.get("id").and_then(Value::as_str)
    }
}
