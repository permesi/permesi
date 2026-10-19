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

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

/// Maximum saved-consent records returned on one self-service page.
pub(crate) const GRANT_PAGE_SIZE: usize = 50;

/// User-visible consent metadata; internal tenant and principal permissions stay private.
#[derive(Debug)]
pub(crate) struct SavedGrant {
    pub id: Uuid,
    pub client_id: Uuid,
    pub client_name: String,
    pub application_name: String,
    pub organization_slug: String,
    pub organization_name: String,
    pub scopes: Vec<String>,
    pub created_at: DateTime<Utc>,
}

/// Lists only the authenticated user's active grants under current tenant ancestry.
/// A cursor is resolved within the same user, and an extra row signals another page.
pub(crate) async fn list_user_grants(
    pool: &PgPool,
    user_id: Uuid,
    after: Option<Uuid>,
) -> Result<Vec<SavedGrant>, sqlx::Error> {
    let query_limit = i64::try_from(GRANT_PAGE_SIZE + 1)
        .map_err(|_| sqlx::Error::Protocol("Invalid saved-grant page size.".to_string()))?;
    let rows = sqlx::query_as::<
        _,
        (
            Uuid,
            Uuid,
            String,
            String,
            String,
            String,
            DateTime<Utc>,
            Vec<String>,
        ),
    >(
        "SELECT g.id,c.client_id,c.name AS client_name,a.name AS application_name,
                o.slug AS organization_slug,o.name AS organization_name,g.created_at,
                ARRAY(SELECT s.name FROM oauth_grant_scopes gs
                      JOIN oauth_scopes s ON s.id=gs.scope_id AND s.application_id=g.application_id
                      WHERE gs.grant_id=g.id ORDER BY s.name) AS scopes
         FROM oauth_grants g
         JOIN oauth_clients c ON c.id=g.client_id AND c.application_id=g.application_id
         JOIN applications a ON a.id=g.application_id
         JOIN environments e ON e.id=a.environment_id
         JOIN projects p ON p.id=e.project_id
         JOIN organizations o ON o.id=g.organization_id AND o.id=p.org_id
         JOIN org_memberships m ON m.user_id=g.user_id AND m.org_id=g.organization_id
         LEFT JOIN oauth_grants cursor ON cursor.id=$2 AND cursor.user_id=g.user_id
         WHERE g.user_id=$1 AND g.revoked_at IS NULL AND c.deleted_at IS NULL
           AND c.disabled_at IS NULL AND a.deleted_at IS NULL AND e.deleted_at IS NULL
           AND p.deleted_at IS NULL AND o.deleted_at IS NULL AND m.status='active'
           AND ($2::uuid IS NULL OR (cursor.id IS NOT NULL AND
                (g.created_at,g.id)<(cursor.created_at,cursor.id)))
         ORDER BY g.created_at DESC,g.id DESC LIMIT $3",
    )
    .bind(user_id)
    .bind(after)
    .bind(query_limit)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(
                id,
                client_id,
                client_name,
                application_name,
                organization_slug,
                organization_name,
                created_at,
                scopes,
            )| SavedGrant {
                id,
                client_id,
                client_name,
                application_name,
                organization_slug,
                organization_name,
                scopes,
                created_at,
            },
        )
        .collect())
}

/// Permanently revokes only the current user's grant. Redemption and refresh
/// recheck this row under a PostgreSQL share lock, so no later transaction can
/// mint new authority from it after this update commits.
pub(crate) async fn revoke_user_grant(
    pool: &PgPool,
    user_id: Uuid,
    grant_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE oauth_grants SET revoked_at=clock_timestamp()
         WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL",
    )
    .bind(grant_id)
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Explicit tenant/resource binding for consent services; not a token claim set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrantContext {
    pub user_id: Uuid,
    pub client_id: Uuid,
    pub application_id: Uuid,
    pub organization_id: Uuid,
}
