//! Shared SQL storage helpers for organization and project entities.
//!
//! This module provides functions for CRUD operations on organizations,
//! projects, environments, and applications, ensuring proper scoping
//! and constraint handling.

use axum::{http::StatusCode, response::IntoResponse};
use sqlx::{PgPool, Row};
use tracing::error;
use uuid::Uuid;

use super::{
    ORG_ROLE_ADMIN, ORG_ROLE_OWNER, ORG_SLUG_MAX,
    slug::with_suffix,
    types::{
        ApplicationResponse, EnvironmentResponse, EnvironmentTier, OrgResponse, ProjectResponse,
    },
};

#[derive(Debug)]
pub(super) struct OrgContext {
    id: Uuid,
    slug: String,
    name: String,
    created_at: String,
    roles: Vec<String>,
}

impl OrgContext {
    /// Returns the organization id this context was resolved for.
    /// This id is tenant-scoped and safe to use for scoped lookups within the same request.
    pub(super) fn id(&self) -> Uuid {
        self.id
    }

    /// Returns `true` when the member holds an elevated org role (owner/admin).
    /// Use this ACL helper to guard privileged org writes (projects, envs, apps, settings).
    pub(super) fn can_manage(&self) -> bool {
        self.roles
            .iter()
            .any(|role| role == ORG_ROLE_OWNER || role == ORG_ROLE_ADMIN)
    }

    /// Converts this internal org context into an `OrgResponse` DTO for API responses.
    /// It intentionally excludes membership status and roles to avoid leaking authorization state.
    pub(super) fn to_response(&self) -> OrgResponse {
        OrgResponse {
            id: self.id.to_string(),
            slug: self.slug.clone(),
            name: self.name.clone(),
            created_at: self.created_at.clone(),
        }
    }
}

#[derive(Debug)]
pub(super) struct ProjectRow {
    id: Uuid,
}

impl ProjectRow {
    /// Returns the resolved project id for downstream scoped queries.
    /// Callers should only use this id after passing org membership checks.
    pub(super) fn id(&self) -> Uuid {
        self.id
    }
}

#[derive(Debug)]
pub(super) struct EnvironmentRow {
    id: Uuid,
}

impl EnvironmentRow {
    /// Returns the resolved environment id for downstream scoped queries.
    /// Callers should only use this id after passing org/project resolution.
    pub(super) fn id(&self) -> Uuid {
        self.id
    }
}

#[derive(Debug)]
pub(super) enum OrgError {
    BadRequest(&'static str),
    Conflict(&'static str),
    Database(sqlx::Error),
}

impl IntoResponse for OrgError {
    /// Maps storage-layer failures into stable HTTP responses for handlers.
    /// Database errors are logged server-side and surfaced as `500` without leaking details.
    fn into_response(self) -> axum::response::Response {
        match self {
            Self::BadRequest(message) => (StatusCode::BAD_REQUEST, message).into_response(),
            Self::Conflict(message) => (StatusCode::CONFLICT, message).into_response(),
            Self::Database(err) => {
                error!("Database error: {err}");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    }
}

/// Inserts a new organization and bootstraps default roles and creator membership.
/// Runs as a transaction, granting the creator the `owner` role on success.
/// Slug collisions are resolved by suffixing within `ORG_SLUG_MAX`; creator name conflicts map to `409`.
/// Returns an `OrgResponse` without membership/role fields.
pub(super) async fn create_org_with_roles(
    pool: &PgPool,
    user_id: Uuid,
    name: &str,
    base_slug: &str,
) -> Result<OrgResponse, OrgError> {
    let mut attempt = 0;
    loop {
        let slug = if attempt == 0 {
            base_slug.to_string()
        } else {
            let suffix = attempt + 1;
            let Some(slug) = with_suffix(base_slug, suffix, ORG_SLUG_MAX) else {
                return Err(OrgError::Conflict("Organization slug is unavailable."));
            };
            slug
        };

        let mut tx = pool.begin().await.map_err(OrgError::Database)?;
        let insert = sqlx::query(
            r#"
            INSERT INTO organizations (slug, name, created_by)
            VALUES ($1, $2, $3)
            RETURNING id, slug, name,
                to_char(created_at AT TIME ZONE 'utc', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS created_at
            "#,
        )
        .bind(&slug)
        .bind(name)
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await;

        let row = match insert {
            Ok(row) => row,
            Err(err) => {
                if is_name_unique_violation(&err) {
                    let _ = tx.rollback().await;
                    return Err(OrgError::Conflict(
                        "You already have an organization with this name.",
                    ));
                }
                if is_unique_violation(&err) {
                    let _ = tx.rollback().await;
                    attempt += 1;
                    continue;
                }
                return Err(OrgError::Database(err));
            }
        };

        let org_id: Uuid = row.get("id");
        let created_at: String = row.get("created_at");

        insert_default_org_roles(&mut tx, org_id).await?;
        sqlx::query(
            r"
            INSERT INTO org_memberships (org_id, user_id, status)
            VALUES ($1, $2, 'active')
            ",
        )
        .bind(org_id)
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(OrgError::Database)?;
        sqlx::query(
            r"
            INSERT INTO org_member_roles (org_id, user_id, role_name, assigned_by)
            VALUES ($1, $2, $3, $2)
            ",
        )
        .bind(org_id)
        .bind(user_id)
        .bind(ORG_ROLE_OWNER)
        .execute(&mut *tx)
        .await
        .map_err(OrgError::Database)?;

        tx.commit().await.map_err(OrgError::Database)?;

        return Ok(OrgResponse {
            id: org_id.to_string(),
            slug,
            name: name.to_string(),
            created_at,
        });
    }
}

/// Seeds the standard org role set for a freshly created organization.
/// It should be called inside the same transaction as org creation so partial setup cannot persist.
async fn insert_default_org_roles(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    org_id: Uuid,
) -> Result<(), OrgError> {
    let roles = [ORG_ROLE_OWNER, ORG_ROLE_ADMIN, "member", "readonly"];
    for role in roles {
        sqlx::query(
            r"
            INSERT INTO org_roles (org_id, name)
            VALUES ($1, $2)
            ",
        )
        .bind(org_id)
        .bind(role)
        .execute(&mut **tx)
        .await
        .map_err(OrgError::Database)?;
    }
    Ok(())
}

/// Fetches organizations where `user_id` has an active membership, excluding soft-deleted rows.
/// Returns `OrgResponse` DTOs only (no roles or membership metadata).
pub(super) async fn fetch_orgs_for_user(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Vec<OrgResponse>, sqlx::Error> {
    // Default to active-only orgs.
    let query = r#"
        SELECT
            o.id::text AS id,
            o.slug,
            o.name,
            to_char(o.created_at AT TIME ZONE 'utc', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS created_at
        FROM organizations o
        JOIN org_memberships m ON m.org_id = o.id
        WHERE m.user_id = $1 AND m.status = 'active' AND o.deleted_at IS NULL
        ORDER BY o.created_at DESC
    "#;
    let rows = sqlx::query(query).bind(user_id).fetch_all(pool).await?;
    Ok(rows
        .into_iter()
        .map(|row| OrgResponse {
            id: row.get("id"),
            slug: row.get("slug"),
            name: row.get("name"),
            created_at: row.get("created_at"),
        })
        .collect())
}

/// Resolves an org by slug for `user_id` and returns role-bearing `OrgContext` when membership is active.
/// Returns `None` for non-members, inactive memberships, or soft-deleted orgs to support `404`.
pub(super) async fn resolve_org_context(
    pool: &PgPool,
    user_id: Uuid,
    slug: &str,
) -> Result<Option<OrgContext>, sqlx::Error> {
    // Default to active-only orgs.
    let query = r#"
        SELECT
            o.id,
            o.slug,
            o.name,
            to_char(o.created_at AT TIME ZONE 'utc', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS created_at,
            m.status,
            COALESCE(
                array_agg(r.role_name) FILTER (WHERE r.role_name IS NOT NULL),
                '{}'
            ) AS roles
        FROM organizations o
        JOIN org_memberships m ON m.org_id = o.id AND m.user_id = $1
        LEFT JOIN org_member_roles r ON r.org_id = o.id AND r.user_id = m.user_id
        WHERE o.slug = $2 AND o.deleted_at IS NULL
        GROUP BY o.id, o.slug, o.name, o.created_at, m.status
        LIMIT 1
    "#;
    let row = sqlx::query(query)
        .bind(user_id)
        .bind(slug)
        .fetch_optional(pool)
        .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let status: String = row.get("status");
    if status != "active" {
        return Ok(None);
    }
    let roles: Vec<String> = row.get("roles");
    Ok(Some(OrgContext {
        id: row.get("id"),
        slug: row.get("slug"),
        name: row.get("name"),
        created_at: row.get("created_at"),
        roles,
    }))
}

/// Updates an organization's name and/or slug and returns the latest `OrgResponse`.
/// Assumes the caller already verified `context.can_manage()`; this function does no ACL checks.
/// Slug collisions are resolved by suffixing within `ORG_SLUG_MAX`, mapping uniqueness failures to `409`.
pub(super) async fn update_org_record(
    pool: &PgPool,
    context: &OrgContext,
    name: Option<&str>,
    slug: Option<&str>,
) -> Result<OrgResponse, OrgError> {
    let mut attempt = 0;
    let base_slug = slug.unwrap_or(&context.slug);

    loop {
        let candidate = if attempt == 0 {
            base_slug.to_string()
        } else {
            let suffix = attempt + 1;
            let Some(slug) = with_suffix(base_slug, suffix, ORG_SLUG_MAX) else {
                return Err(OrgError::Conflict("Organization slug is unavailable."));
            };
            slug
        };

        let update = sqlx::query(
            r#"
            UPDATE organizations
            SET
                name = COALESCE($1, name),
                slug = $2
            WHERE id = $3
            RETURNING
                id::text AS id,
                slug,
                name,
                to_char(created_at AT TIME ZONE 'utc', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS created_at
            "#,
        )
        .bind(name)
        .bind(&candidate)
        .bind(context.id)
        .fetch_one(pool)
        .await;

        match update {
            Ok(row) => {
                return Ok(OrgResponse {
                    id: row.get("id"),
                    slug: row.get("slug"),
                    name: row.get("name"),
                    created_at: row.get("created_at"),
                });
            }
            Err(err) => {
                if is_unique_violation(&err) {
                    attempt += 1;
                    continue;
                }
                return Err(OrgError::Database(err));
            }
        }
    }
}

/// Inserts a project under the given org id and returns a `ProjectResponse`.
/// Caller must ensure the org id is authorized (typically via `OrgContext::can_manage`).
/// Uniqueness violations on slug are mapped to `409` without exposing database details.
pub(super) async fn insert_project(
    pool: &PgPool,
    org_id: Uuid,
    name: &str,
    slug: &str,
) -> Result<ProjectResponse, OrgError> {
    let insert = sqlx::query(
        r#"
        INSERT INTO projects (org_id, slug, name)
        VALUES ($1, $2, $3)
        RETURNING
            id::text AS id,
            slug,
            name,
            to_char(created_at AT TIME ZONE 'utc', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS created_at
        "#,
    )
    .bind(org_id)
    .bind(slug)
    .bind(name)
    .fetch_one(pool)
    .await;

    match insert {
        Ok(row) => Ok(ProjectResponse {
            id: row.get("id"),
            slug: row.get("slug"),
            name: row.get("name"),
            created_at: row.get("created_at"),
        }),
        Err(err) => {
            if is_unique_violation(&err) {
                Err(OrgError::Conflict("Project slug already exists."))
            } else {
                Err(OrgError::Database(err))
            }
        }
    }
}

/// Lists active (non-deleted) projects for an org as `ProjectResponse` DTOs.
/// It returns only id/slug/name/timestamps, not environments or org membership data.
pub(super) async fn fetch_projects(
    pool: &PgPool,
    org_id: Uuid,
) -> Result<Vec<ProjectResponse>, sqlx::Error> {
    // Default to active-only projects.
    let query = r#"
        SELECT
            id::text AS id,
            slug,
            name,
            to_char(created_at AT TIME ZONE 'utc', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS created_at
        FROM projects
        WHERE org_id = $1 AND deleted_at IS NULL
        ORDER BY created_at DESC
    "#;
    let rows = sqlx::query(query).bind(org_id).fetch_all(pool).await?;
    Ok(rows
        .into_iter()
        .map(|row| ProjectResponse {
            id: row.get("id"),
            slug: row.get("slug"),
            name: row.get("name"),
            created_at: row.get("created_at"),
        })
        .collect())
}

/// Resolves a project's id by slug under an org, returning `None` when missing or soft-deleted.
/// It is used as a scoping guard so downstream queries cannot cross tenant boundaries.
pub(super) async fn resolve_project(
    pool: &PgPool,
    org_id: Uuid,
    slug: &str,
) -> Result<Option<ProjectRow>, sqlx::Error> {
    // Default to active-only projects.
    let row = sqlx::query(
        r"
        SELECT id
        FROM projects
        WHERE org_id = $1 AND slug = $2 AND deleted_at IS NULL
        LIMIT 1
        ",
    )
    .bind(org_id)
    .bind(slug)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|row| ProjectRow { id: row.get("id") }))
}

/// Inserts an environment for a project and returns an `EnvironmentResponse`.
/// Enforces a single `production` tier per project and requires production before `non_production`.
/// Caller must have already enforced org/project access; this function is scoped by ids only.
/// Uniqueness violations on slug are mapped to `409`.
pub(super) async fn insert_environment(
    pool: &PgPool,
    project_id: Uuid,
    name: &str,
    slug: &str,
    tier: EnvironmentTier,
) -> Result<EnvironmentResponse, OrgError> {
    let production_exists = sqlx::query(
        "SELECT EXISTS(SELECT 1 FROM environments WHERE project_id = $1 AND tier = 'production' AND deleted_at IS NULL) AS exists",
    )
    .bind(project_id)
    .fetch_one(pool)
    .await
    .map_err(OrgError::Database)?
    .get::<bool, _>("exists");

    match tier {
        EnvironmentTier::Production => {
            if production_exists {
                return Err(OrgError::Conflict(
                    "A production environment already exists for this project.",
                ));
            }
        }
        EnvironmentTier::NonProduction => {
            if !production_exists {
                return Err(OrgError::BadRequest(
                    "Create a production environment before adding non-production environments.",
                ));
            }
        }
    }

    let insert = sqlx::query(
        r#"
        INSERT INTO environments (project_id, slug, name, tier)
        VALUES ($1, $2, $3, $4::environment_tier)
        RETURNING
            id::text AS id,
            slug,
            name,
            tier::text AS tier,
            to_char(created_at AT TIME ZONE 'utc', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS created_at
        "#,
    )
    .bind(project_id)
    .bind(slug)
    .bind(name)
    .bind(tier.as_str())
    .fetch_one(pool)
    .await;

    match insert {
        Ok(row) => Ok(EnvironmentResponse {
            id: row.get("id"),
            slug: row.get("slug"),
            name: row.get("name"),
            tier: row.get("tier"),
            created_at: row.get("created_at"),
        }),
        Err(err) => {
            if is_unique_violation(&err) {
                Err(OrgError::Conflict("Environment slug already exists."))
            } else {
                Err(OrgError::Database(err))
            }
        }
    }
}

/// Lists active (non-deleted) environments for a project as `EnvironmentResponse` DTOs.
/// Returns only environment fields; callers decide what additional joins are safe/needed.
pub(super) async fn fetch_environments(
    pool: &PgPool,
    project_id: Uuid,
) -> Result<Vec<EnvironmentResponse>, sqlx::Error> {
    // Default to active-only envs.
    let query = r#"
        SELECT
            id::text AS id,
            slug,
            name,
            tier::text AS tier,
            to_char(created_at AT TIME ZONE 'utc', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS created_at
        FROM environments
        WHERE project_id = $1 AND deleted_at IS NULL
        ORDER BY created_at DESC
    "#;
    let rows = sqlx::query(query).bind(project_id).fetch_all(pool).await?;
    Ok(rows
        .into_iter()
        .map(|row| EnvironmentResponse {
            id: row.get("id"),
            slug: row.get("slug"),
            name: row.get("name"),
            tier: row.get("tier"),
            created_at: row.get("created_at"),
        })
        .collect())
}

/// Resolves an environment id by slug under a project, returning `None` when missing or soft-deleted.
/// Use this to scope application queries and preserve the project boundary.
pub(super) async fn resolve_environment(
    pool: &PgPool,
    project_id: Uuid,
    slug: &str,
) -> Result<Option<EnvironmentRow>, sqlx::Error> {
    // Default to active-only envs.
    let row = sqlx::query(
        r"
        SELECT id
        FROM environments
        WHERE project_id = $1 AND slug = $2 AND deleted_at IS NULL
        LIMIT 1
        ",
    )
    .bind(project_id)
    .bind(slug)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|row| EnvironmentRow { id: row.get("id") }))
}

/// Inserts an application within an environment and returns an `ApplicationResponse`.
/// Caller must have already verified org/project/environment access; this function trusts `environment_id`.
/// Uniqueness violations are mapped to `409` without surfacing database details.
pub(super) async fn insert_application(
    pool: &PgPool,
    environment_id: Uuid,
    name: &str,
) -> Result<ApplicationResponse, OrgError> {
    let insert = sqlx::query(
        r#"
        INSERT INTO applications (environment_id, name)
        VALUES ($1, $2)
        RETURNING
            id::text AS id,
            name,
            to_char(created_at AT TIME ZONE 'utc', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS created_at
        "#,
    )
    .bind(environment_id)
    .bind(name)
    .fetch_one(pool)
    .await;

    match insert {
        Ok(row) => Ok(ApplicationResponse {
            id: row.get("id"),
            name: row.get("name"),
            created_at: row.get("created_at"),
        }),
        Err(err) => {
            if is_unique_violation(&err) {
                Err(OrgError::Conflict("Application already exists."))
            } else {
                Err(OrgError::Database(err))
            }
        }
    }
}

/// Lists active (non-deleted) applications for an environment as `ApplicationResponse` DTOs.
/// Returns only id/name/timestamps, not environment or org context.
pub(super) async fn fetch_applications(
    pool: &PgPool,
    environment_id: Uuid,
) -> Result<Vec<ApplicationResponse>, sqlx::Error> {
    // Default to active-only apps.
    let query = r#"
        SELECT
            id::text AS id,
            name,
            to_char(created_at AT TIME ZONE 'utc', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS created_at
        FROM applications
        WHERE environment_id = $1 AND deleted_at IS NULL
        ORDER BY created_at DESC
    "#;
    let rows = sqlx::query(query)
        .bind(environment_id)
        .fetch_all(pool)
        .await?;
    Ok(rows
        .into_iter()
        .map(|row| ApplicationResponse {
            id: row.get("id"),
            name: row.get("name"),
            created_at: row.get("created_at"),
        })
        .collect())
}

/// Returns `true` when `err` is a database unique-violation (SQLSTATE `23505`).
/// This is used to translate constraint errors into stable API `409` responses.
fn is_unique_violation(err: &sqlx::Error) -> bool {
    match err {
        sqlx::Error::Database(db_err) => db_err.code().as_deref() == Some("23505"),
        _ => false,
    }
}

/// Returns `true` when `err` matches the organization-name uniqueness constraint for a creator.
/// Used to provide a specific `409` message when a user already owns an active org with the same name.
fn is_name_unique_violation(err: &sqlx::Error) -> bool {
    match err {
        sqlx::Error::Database(db_err) => {
            db_err.code().as_deref() == Some("23505")
                && db_err
                    .constraint()
                    .is_some_and(|c| c == "organizations_creator_name_active_idx")
        }
        _ => false,
    }
}
