//! Fixed-query metadata reads with active ancestry enforced in every SQL statement.
//!
//! Scope is server-selected by the route; all path/cursor values are bound parameters.
//! Parent validation distinguishes an empty collection from missing ancestry, while
//! the page query rechecks that ancestry rather than trusting the earlier lookup.

use axum::http::StatusCode;
use chrono::{DateTime, SecondsFormat, Utc};
use sqlx::{PgPool, Postgres, QueryBuilder, Row, postgres::PgRow};
use uuid::Uuid;

use super::{AdminMetadata, PAGE_SIZE};

pub(super) enum Scope {
    Organizations,
    Projects(String),
    Environments(String, String),
    Applications(String, String, String),
}

pub(super) enum Selector {
    Slug(String),
    Id(Uuid),
}

pub(super) struct Record {
    pub(super) id: Uuid,
    created_at: DateTime<Utc>,
    name: String,
    slug: Option<String>,
    tier: Option<String>,
}

impl Record {
    /// Selects only the public metadata allowlist; authentication and tenant roles stay private.
    pub(super) fn metadata(self) -> AdminMetadata {
        AdminMetadata {
            id: self.id.to_string(),
            name: self.name,
            created_at: self.created_at.to_rfc3339_opts(SecondsFormat::Secs, true),
            slug: self.slug,
            tier: self.tier,
        }
    }

    /// Decodes typed database columns without assuming that nullable metadata is populated.
    fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            created_at: row.try_get("created_at")?,
            name: row.try_get("name")?,
            slug: row.try_get("slug")?,
            tier: row.try_get("tier")?,
        })
    }
}

/// Constructs fixed ancestry joins; user data is never concatenated into SQL identifiers.
fn base(scope: &Scope) -> QueryBuilder<Postgres> {
    let mut query = QueryBuilder::new("SELECT r.id,r.name,r.created_at,");
    query.push(match scope {
        Scope::Organizations => "r.slug,NULL::text AS tier FROM organizations r WHERE r.deleted_at IS NULL",
        Scope::Projects(_) => "r.slug,NULL::text AS tier FROM projects r JOIN organizations o ON o.id=r.org_id WHERE r.deleted_at IS NULL AND o.deleted_at IS NULL",
        Scope::Environments(_, _) => "r.slug,r.tier::text AS tier FROM environments r JOIN projects p ON p.id=r.project_id JOIN organizations o ON o.id=p.org_id WHERE r.deleted_at IS NULL AND p.deleted_at IS NULL AND o.deleted_at IS NULL",
        Scope::Applications(_, _, _) => "NULL::text AS slug,NULL::text AS tier FROM applications r JOIN environments e ON e.id=r.environment_id JOIN projects p ON p.id=e.project_id JOIN organizations o ON o.id=p.org_id WHERE r.deleted_at IS NULL AND e.deleted_at IS NULL AND p.deleted_at IS NULL AND o.deleted_at IS NULL",
    });
    match scope {
        Scope::Organizations => {}
        Scope::Projects(org) => {
            query.push(" AND o.slug=").push_bind(org.clone());
        }
        Scope::Environments(org, project) => {
            query
                .push(" AND o.slug=")
                .push_bind(org.clone())
                .push(" AND p.slug=")
                .push_bind(project.clone());
        }
        Scope::Applications(org, project, environment) => {
            query
                .push(" AND o.slug=")
                .push_bind(org.clone())
                .push(" AND p.slug=")
                .push_bind(project.clone())
                .push(" AND e.slug=")
                .push_bind(environment.clone());
        }
    }
    query
}

/// Maps dependency failures without logging resource paths, SQL values or credential data.
fn database_error(error: &sqlx::Error) -> StatusCode {
    tracing::error!(code = ?error.as_database_error().and_then(sqlx::error::DatabaseError::code), "Admin inspection storage failed");
    StatusCode::SERVICE_UNAVAILABLE
}

/// Finds one resource inside the selected active collection, including cursor anchors.
pub(super) async fn find(
    pool: &PgPool,
    scope: &Scope,
    selector: &Selector,
) -> Result<Option<Record>, StatusCode> {
    let mut query = base(scope);
    match selector {
        Selector::Slug(slug) => {
            query.push(" AND r.slug=").push_bind(slug.clone());
        }
        Selector::Id(id) => {
            query.push(" AND r.id=").push_bind(*id);
        }
    }
    query.push(" LIMIT 1");
    query
        .build()
        .fetch_optional(pool)
        .await
        .map_err(|error| database_error(&error))?
        .as_ref()
        .map(Record::from_row)
        .transpose()
        .map_err(|error| database_error(&error))
}

/// Rejects absent/deleted parents rather than presenting their child list as empty.
pub(super) async fn require_parent(pool: &PgPool, scope: &Scope) -> Result<(), StatusCode> {
    let parent = match scope {
        Scope::Organizations => return Ok(()),
        Scope::Projects(org) => (Scope::Organizations, org),
        Scope::Environments(org, project) => (Scope::Projects(org.clone()), project),
        Scope::Applications(org, project, environment) => (
            Scope::Environments(org.clone(), project.clone()),
            environment,
        ),
    };
    find(pool, &parent.0, &Selector::Slug(parent.1.clone()))
        .await?
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(())
}

/// Reads at most one page plus a sentinel, ordered deterministically across equal timestamps.
pub(super) async fn page(
    pool: &PgPool,
    scope: &Scope,
    cursor: Option<Record>,
) -> Result<Vec<Record>, StatusCode> {
    let mut query = base(scope);
    if let Some(cursor) = cursor {
        query
            .push(" AND (r.created_at,r.id)<(")
            .push_bind(cursor.created_at)
            .push(",")
            .push_bind(cursor.id)
            .push(")");
    }
    query
        .push(" ORDER BY r.created_at DESC,r.id DESC LIMIT ")
        .push_bind(i64::try_from(PAGE_SIZE + 1).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?);
    query
        .build()
        .fetch_all(pool)
        .await
        .map_err(|error| database_error(&error))?
        .iter()
        .map(Record::from_row)
        .collect::<Result<_, _>>()
        .map_err(|error| database_error(&error))
}
