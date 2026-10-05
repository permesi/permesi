//! Bottom-up tenant lifecycle transactions, shared by creation and deletion.
//!
//! Flow Overview: lock active ancestry from organization to leaf, verify current
//! membership/roles for deletion, exclusively lock the target, check its immediate
//! active children, and soft-delete. Creators hold SHARE on the same parents until
//! commit, so no successful creation can outlive a concurrent parent deletion.
//! Application deletion requires explicit OAuth client deletion first; that existing
//! lifecycle revokes credentials and grants. Registry metadata does not block deletion.

use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

use super::{OrgContext, OrgError, resolve_org_context};

#[cfg(test)]
mod tests;

/// Trusted database IDs used only after the caller's tenant authorization checks.
pub(super) enum Parent {
    Organization(Uuid),
    Project(Uuid),
    Environment(Uuid),
}

/// Path-bound target; each variant deletes only one resource, never its children.
pub(in super::super) enum Deletion<'a> {
    Organization,
    Project(&'a str),
    Environment(&'a str, &'a str),
    Application(&'a str, &'a str, Uuid),
}

/// Locks every active ancestor in root-to-leaf order until creation commits.
/// IDs grant no authority; HTTP callers must separately enforce owner/admin membership.
pub(super) async fn lock_parent(
    tx: &mut Transaction<'_, Postgres>,
    parent: Parent,
) -> Result<(), OrgError> {
    let (org, project, environment) = match parent {
        Parent::Organization(id) => (id, None, None),
        Parent::Project(id) => {
            let org = sqlx::query_scalar("SELECT org_id FROM projects WHERE id=$1")
                .bind(id)
                .fetch_optional(&mut **tx)
                .await
                .map_err(OrgError::Database)?
                .ok_or(OrgError::NotFound)?;
            (org, Some(id), None)
        }
        Parent::Environment(id) => {
            let row = sqlx::query("SELECT p.org_id,p.id FROM environments e JOIN projects p ON p.id=e.project_id WHERE e.id=$1")
                .bind(id).fetch_optional(&mut **tx).await.map_err(OrgError::Database)?
                .ok_or(OrgError::NotFound)?;
            (row.get("org_id"), Some(row.get("id")), Some(id))
        }
    };
    lock_id(
        tx,
        "SELECT id FROM organizations WHERE id=$1 AND deleted_at IS NULL FOR SHARE",
        org,
    )
    .await?;
    if let Some(project) = project {
        lock_id(
            tx,
            "SELECT id FROM projects WHERE id=$1 AND deleted_at IS NULL FOR SHARE",
            project,
        )
        .await?;
    }
    if let Some(environment) = environment {
        lock_id(
            tx,
            "SELECT id FROM environments WHERE id=$1 AND deleted_at IS NULL FOR SHARE",
            environment,
        )
        .await?;
    }
    Ok(())
}

/// Executes only fixed SQL chosen by the lifecycle; deleted/missing parents fail closed.
async fn lock_id(
    tx: &mut Transaction<'_, Postgres>,
    sql: &'static str,
    id: Uuid,
) -> Result<Uuid, OrgError> {
    sqlx::query_scalar(sql)
        .bind(id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(OrgError::Database)?
        .ok_or(OrgError::NotFound)
}

/// Resolves current owner/admin authority under active user, membership and role locks.
/// The organization lock is exclusive only when deleting the organization itself.
async fn lock_org(
    tx: &mut Transaction<'_, Postgres>,
    user: Uuid,
    slug: &str,
    org_id: Uuid,
    owner_only: bool,
) -> Result<OrgContext, OrgError> {
    let query = if owner_only {
        "SELECT id,slug,name,created_at::text FROM organizations WHERE slug=$1 AND id=$2 AND deleted_at IS NULL FOR UPDATE"
    } else {
        "SELECT id,slug,name,created_at::text FROM organizations WHERE slug=$1 AND id=$2 AND deleted_at IS NULL FOR SHARE"
    };
    let row = sqlx::query(query)
        .bind(slug)
        .bind(org_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(OrgError::Database)?
        .ok_or(OrgError::NotFound)?;
    let org: Uuid = row.get("id");
    let status = sqlx::query_scalar::<_, String>(
        "SELECT m.status::text FROM org_memberships m JOIN users u ON u.id=m.user_id WHERE m.org_id=$1 AND m.user_id=$2 AND u.status='active' FOR SHARE OF m,u",
    )
    .bind(org)
    .bind(user)
    .fetch_optional(&mut **tx)
    .await
    .map_err(OrgError::Database)?;
    if status.as_deref() != Some("active") {
        return Err(OrgError::NotFound);
    }
    let roles = sqlx::query_scalar("SELECT role_name FROM org_member_roles WHERE org_id=$1 AND user_id=$2 ORDER BY role_name FOR SHARE")
        .bind(org).bind(user).fetch_all(&mut **tx).await.map_err(OrgError::Database)?;
    let context = OrgContext {
        id: org,
        slug: row.get("slug"),
        name: row.get("name"),
        created_at: row.get("created_at"),
        roles,
    };
    if (owner_only && !context.is_owner()) || (!owner_only && !context.can_manage()) {
        return Err(OrgError::NotFound);
    }
    Ok(context)
}

/// Locks the exact child of the already-locked parent, without cross-tenant lookups.
async fn lock_child(
    tx: &mut Transaction<'_, Postgres>,
    sql: &'static str,
    parent: Uuid,
    slug: &str,
) -> Result<Uuid, OrgError> {
    sqlx::query_scalar(sql)
        .bind(parent)
        .bind(slug)
        .fetch_optional(&mut **tx)
        .await
        .map_err(OrgError::Database)?
        .ok_or(OrgError::NotFound)
}

/// Fixed queries for a locked target; SQL cannot come from a request.
struct LockedDeletion {
    id: Uuid,
    children: &'static str,
    update: &'static str,
    message: &'static str,
}

/// Resolves the exact active target and prepares its immediate-child check under lock.
async fn lock_target(
    tx: &mut Transaction<'_, Postgres>,
    org: &OrgContext,
    target: Deletion<'_>,
) -> Result<LockedDeletion, OrgError> {
    let row = match target {
        Deletion::Organization => LockedDeletion {
            id: org.id(),
            children: "SELECT EXISTS(SELECT 1 FROM projects WHERE org_id=$1 AND deleted_at IS NULL)",
            update: "UPDATE organizations SET deleted_at=NOW() WHERE id=$1",
            message: "Organization contains active projects.",
        },
        Deletion::Project(slug) => {
            let id = lock_child(tx, "SELECT id FROM projects WHERE org_id=$1 AND slug=$2 AND deleted_at IS NULL FOR UPDATE", org.id(), slug).await?;
            LockedDeletion {
                id,
                children: "SELECT EXISTS(SELECT 1 FROM environments WHERE project_id=$1 AND deleted_at IS NULL)",
                update: "UPDATE projects SET deleted_at=NOW() WHERE id=$1",
                message: "Project contains active environments.",
            }
        }
        Deletion::Environment(project, environment)
        | Deletion::Application(project, environment, _) => {
            let project = lock_child(tx, "SELECT id FROM projects WHERE org_id=$1 AND slug=$2 AND deleted_at IS NULL FOR SHARE", org.id(), project).await?;
            let sql = if matches!(target, Deletion::Environment(..)) {
                "SELECT id FROM environments WHERE project_id=$1 AND slug=$2 AND deleted_at IS NULL FOR UPDATE"
            } else {
                "SELECT id FROM environments WHERE project_id=$1 AND slug=$2 AND deleted_at IS NULL FOR SHARE"
            };
            let environment = lock_child(tx, sql, project, environment).await?;
            if let Deletion::Application(_, _, application) = target {
                let id = sqlx::query_scalar("SELECT id FROM applications WHERE environment_id=$1 AND id=$2 AND deleted_at IS NULL FOR UPDATE")
                    .bind(environment).bind(application).fetch_optional(&mut **tx).await.map_err(OrgError::Database)?.ok_or(OrgError::NotFound)?;
                LockedDeletion {
                    id,
                    children: "SELECT EXISTS(SELECT 1 FROM oauth_clients WHERE application_id=$1 AND deleted_at IS NULL)",
                    update: "UPDATE applications SET deleted_at=NOW() WHERE id=$1",
                    message: "Application contains undeleted OAuth clients.",
                }
            } else {
                LockedDeletion {
                    id: environment,
                    children: "SELECT EXISTS(SELECT 1 FROM applications WHERE environment_id=$1 AND deleted_at IS NULL)",
                    update: "UPDATE environments SET deleted_at=NOW() WHERE id=$1",
                    message: "Environment contains active applications.",
                }
            }
        }
    };
    Ok(row)
}

/// Deletes one authorized resource after atomically establishing an empty immediate child set.
/// SHARE locks used by all child creators conflict with the target's UPDATE lock.
/// Repeated/foreign/inaccessible targets return 404; protocol scope rows never count as children.
pub(in super::super) async fn delete_resource(
    pool: &sqlx::PgPool,
    user: Uuid,
    org_slug: &str,
    target: Deletion<'_>,
) -> Result<(), OrgError> {
    // Reject foreign tenants before joining their lifecycle lock queue. Recheck
    // authority under locks below, pinned to this organization rather than a reused slug.
    let context = resolve_org_context(pool, user, org_slug)
        .await
        .map_err(OrgError::Database)?
        .ok_or(OrgError::NotFound)?;
    let owner_only = matches!(target, Deletion::Organization);
    if (owner_only && !context.is_owner()) || (!owner_only && !context.can_manage()) {
        return Err(OrgError::NotFound);
    }
    let mut tx = pool.begin().await.map_err(OrgError::Database)?;
    let org = lock_org(&mut tx, user, org_slug, context.id(), owner_only).await?;
    let row = lock_target(&mut tx, &org, target).await?;
    let nonempty: bool = sqlx::query_scalar(row.children)
        .bind(row.id)
        .fetch_one(&mut *tx)
        .await
        .map_err(OrgError::Database)?;
    if nonempty {
        return Err(OrgError::Conflict(row.message));
    }
    sqlx::query(row.update)
        .bind(row.id)
        .execute(&mut *tx)
        .await
        .map_err(OrgError::Database)?;
    tx.commit().await.map_err(OrgError::Database)?;
    Ok(())
}
