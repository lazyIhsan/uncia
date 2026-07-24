//! Resource model: the unit of infrastructure uncia tracks.

/// Stable identifier for a resource.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ResourceId(pub String);

/// The kind of infrastructure resource (e.g. EC2 instance, security group).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ResourceKind {
    // TODO: enumerate supported resource kinds.
}

/// A single tracked infrastructure resource.
#[derive(Debug, Clone)]
pub struct Resource {
    pub id: ResourceId,
    pub kind: ResourceKind,
    // TODO: attributes / provider-specific payload.
}
