//! Explicit consent persistence context, shared by authorization and token services.
//!
//! A grant binds one identity to one client, application, and owning organization.
//! Composite foreign keys constrain grant scopes to that client's configured scopes
//! in the same application. A database trigger verifies the organization against
//! application ancestry and share-locks the client, ancestors, and membership to serialize
//! consent with lifecycle/configuration changes. Revocation is permanent and still works
//! after context becomes inactive; membership is not inferred from identity.
//! Authorization and code redemption recheck active membership, resource authority, client/ancestry
//! lifecycle, consent, and protocol-specific conditions; future refresh must do the same.
//! Membership existence or a saved grant alone never authorizes a resource.

use uuid::Uuid;

/// Explicit tenant/resource binding for consent services; not a token claim set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrantContext {
    pub user_id: Uuid,
    pub client_id: Uuid,
    pub application_id: Uuid,
    pub organization_id: Uuid,
}
