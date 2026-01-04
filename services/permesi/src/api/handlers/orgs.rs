//! Organization, project, environment, and application endpoints.
//!
//! Organizations are the tenant boundary, so every handler scopes by org slug
//! and derives authorization from org membership roles. We return 404 for
//! unauthorized access (including inactive memberships) to avoid exposing
//! resource existence, and we normalize slugs to stable URL-safe identifiers.
//! Environment creation enforces a single production tier per project, with
//! non-production environments gated until a production environment exists.
//!
//! Flow Overview:
//! 1) Authenticate via session cookie.
//! 2) Resolve the organization by slug and verify active membership.
//! 3) Enforce org-scoped roles for write operations.
//! 4) Perform scoped CRUD for projects, environments, and applications.

use axum::{
    Json,
    extract::{Extension, Path},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use tracing::error;
use utoipa::ToSchema;
use uuid::Uuid;

use super::auth::principal::require_auth;

const ORG_SLUG_MIN: usize = 3;
const ORG_SLUG_MAX: usize = 63;
const PROJECT_SLUG_MIN: usize = 3;
const PROJECT_SLUG_MAX: usize = 63;
const ENV_SLUG_MIN: usize = 2;
const ENV_SLUG_MAX: usize = 32;

const ORG_ROLE_OWNER: &str = "owner";
const ORG_ROLE_ADMIN: &str = "admin";

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateOrgRequest {
    pub name: String,
    pub slug: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateOrgRequest {
    pub name: Option<String>,
    pub slug: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateProjectRequest {
    pub name: String,
    pub slug: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateEnvironmentRequest {
    pub name: String,
    pub slug: String,
    #[serde(default)]
    pub tier: EnvironmentTier,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateApplicationRequest {
    pub name: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct OrgResponse {
    pub id: String,
    pub slug: String,
    pub name: String,
    pub created_at: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ProjectResponse {
    pub id: String,
    pub slug: String,
    pub name: String,
    pub created_at: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct EnvironmentResponse {
    pub id: String,
    pub slug: String,
    pub name: String,
    pub tier: String,
    pub created_at: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ApplicationResponse {
    pub id: String,
    pub name: String,
    pub created_at: String,
}

#[derive(Debug, Deserialize, Serialize, ToSchema, Clone, Copy, Default)]
#[serde(rename_all = "snake_case")]
pub enum EnvironmentTier {
    Production,
    #[default]
    NonProduction,
}

impl EnvironmentTier {
    fn as_str(self) -> &'static str {
        match self {
            Self::Production => "production",
            Self::NonProduction => "non_production",
        }
    }
}

#[utoipa::path(
    post,
    path = "/v1/orgs",
    request_body = CreateOrgRequest,
    responses(
        (status = 201, description = "Organization created.", body = OrgResponse),
        (status = 400, description = "Invalid input.", body = String),
        (status = 401, description = "Missing or invalid session cookie."),
    ),
    tag = "orgs"
)]
pub async fn create_org(
    headers: HeaderMap,
    pool: Extension<PgPool>,
    Json(payload): Json<CreateOrgRequest>,
) -> impl IntoResponse {
    let principal = match require_auth(&headers, &pool).await {
        Ok(principal) => principal,
        Err(status) => return status.into_response(),
    };

    let name = payload.name.trim();
    if name.is_empty() {
        return (StatusCode::BAD_REQUEST, "Organization name is required.").into_response();
    }

    let base_slug = match payload.slug.as_deref() {
        Some(slug) => normalize_slug(slug, ORG_SLUG_MIN, ORG_SLUG_MAX),
        None => normalize_slug(name, ORG_SLUG_MIN, ORG_SLUG_MAX),
    };

    let Some(base_slug) = base_slug else {
        return (StatusCode::BAD_REQUEST, "Invalid organization slug.").into_response();
    };

    match create_org_with_roles(&pool, principal.user_id, name, &base_slug).await {
        Ok(response) => (StatusCode::CREATED, Json(response)).into_response(),
        Err(err) => err.into_response(),
    }
}

#[utoipa::path(
    get,
    path = "/v1/orgs",
    responses(
        (status = 200, description = "List organizations.", body = [OrgResponse]),
        (status = 401, description = "Missing or invalid session cookie."),
    ),
    tag = "orgs"
)]
pub async fn list_orgs(headers: HeaderMap, pool: Extension<PgPool>) -> impl IntoResponse {
    let principal = match require_auth(&headers, &pool).await {
        Ok(principal) => principal,
        Err(status) => return status.into_response(),
    };

    match fetch_orgs_for_user(&pool, principal.user_id).await {
        Ok(rows) => (StatusCode::OK, Json(rows)).into_response(),
        Err(err) => {
            error!("Failed to list orgs: {err}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[utoipa::path(
    get,
    path = "/v1/orgs/{org_slug}",
    params(("org_slug" = String, Path, description = "Organization slug")),
    responses(
        (status = 200, description = "Organization detail.", body = OrgResponse),
        (status = 401, description = "Missing or invalid session cookie."),
        (status = 404, description = "Organization not found."),
    ),
    tag = "orgs"
)]
pub async fn get_org(
    Path(org_slug): Path<String>,
    headers: HeaderMap,
    pool: Extension<PgPool>,
) -> impl IntoResponse {
    let principal = match require_auth(&headers, &pool).await {
        Ok(principal) => principal,
        Err(status) => return status.into_response(),
    };

    match resolve_org_context(&pool, principal.user_id, &org_slug).await {
        Ok(Some(context)) => (StatusCode::OK, Json(context.to_response())).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(err) => {
            error!("Failed to get org: {err}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[utoipa::path(
    patch,
    path = "/v1/orgs/{org_slug}",
    request_body = UpdateOrgRequest,
    params(("org_slug" = String, Path, description = "Organization slug")),
    responses(
        (status = 200, description = "Organization updated.", body = OrgResponse),
        (status = 400, description = "Invalid input.", body = String),
        (status = 401, description = "Missing or invalid session cookie."),
        (status = 404, description = "Organization not found."),
    ),
    tag = "orgs"
)]
pub async fn patch_org(
    Path(org_slug): Path<String>,
    headers: HeaderMap,
    pool: Extension<PgPool>,
    Json(payload): Json<UpdateOrgRequest>,
) -> impl IntoResponse {
    let principal = match require_auth(&headers, &pool).await {
        Ok(principal) => principal,
        Err(status) => return status.into_response(),
    };

    let context = match resolve_org_context(&pool, principal.user_id, &org_slug).await {
        Ok(Some(context)) => context,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(err) => {
            error!("Failed to resolve org for patch: {err}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    if !context.can_manage() {
        return StatusCode::NOT_FOUND.into_response();
    }

    let name = payload
        .name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let slug = match payload.slug.as_deref() {
        Some(value) => normalize_slug(value, ORG_SLUG_MIN, ORG_SLUG_MAX),
        None => None,
    };

    if payload.slug.is_some() && slug.is_none() {
        return (StatusCode::BAD_REQUEST, "Invalid organization slug.").into_response();
    }

    if name.is_none() && slug.is_none() {
        return (StatusCode::BAD_REQUEST, "No updates provided.").into_response();
    }

    match update_org_record(&pool, &context, name, slug.as_deref()).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(err) => err.into_response(),
    }
}

#[utoipa::path(
    post,
    path = "/v1/orgs/{org_slug}/projects",
    request_body = CreateProjectRequest,
    params(("org_slug" = String, Path, description = "Organization slug")),
    responses(
        (status = 201, description = "Project created.", body = ProjectResponse),
        (status = 400, description = "Invalid input.", body = String),
        (status = 401, description = "Missing or invalid session cookie."),
        (status = 404, description = "Organization not found."),
        (status = 409, description = "Project slug already exists.", body = String),
    ),
    tag = "projects"
)]
pub async fn create_project(
    Path(org_slug): Path<String>,
    headers: HeaderMap,
    pool: Extension<PgPool>,
    Json(payload): Json<CreateProjectRequest>,
) -> impl IntoResponse {
    let principal = match require_auth(&headers, &pool).await {
        Ok(principal) => principal,
        Err(status) => return status.into_response(),
    };

    let name = payload.name.trim();
    if name.is_empty() {
        return (StatusCode::BAD_REQUEST, "Project name is required.").into_response();
    }

    let slug = match payload.slug.as_deref() {
        Some(slug) => normalize_slug(slug, PROJECT_SLUG_MIN, PROJECT_SLUG_MAX),
        None => normalize_slug(name, PROJECT_SLUG_MIN, PROJECT_SLUG_MAX),
    };
    let Some(slug) = slug else {
        return (StatusCode::BAD_REQUEST, "Invalid project slug.").into_response();
    };

    let context = match resolve_org_context(&pool, principal.user_id, &org_slug).await {
        Ok(Some(context)) => context,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(err) => {
            error!("Failed to resolve org for project: {err}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    if !context.can_manage() {
        return StatusCode::NOT_FOUND.into_response();
    }

    match insert_project(&pool, context.id, name, &slug).await {
        Ok(response) => (StatusCode::CREATED, Json(response)).into_response(),
        Err(err) => err.into_response(),
    }
}

#[utoipa::path(
    get,
    path = "/v1/orgs/{org_slug}/projects",
    params(("org_slug" = String, Path, description = "Organization slug")),
    responses(
        (status = 200, description = "List projects.", body = [ProjectResponse]),
        (status = 401, description = "Missing or invalid session cookie."),
        (status = 404, description = "Organization not found."),
    ),
    tag = "projects"
)]
pub async fn list_projects(
    Path(org_slug): Path<String>,
    headers: HeaderMap,
    pool: Extension<PgPool>,
) -> impl IntoResponse {
    let principal = match require_auth(&headers, &pool).await {
        Ok(principal) => principal,
        Err(status) => return status.into_response(),
    };

    let context = match resolve_org_context(&pool, principal.user_id, &org_slug).await {
        Ok(Some(context)) => context,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(err) => {
            error!("Failed to resolve org for list projects: {err}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    match fetch_projects(&pool, context.id).await {
        Ok(rows) => (StatusCode::OK, Json(rows)).into_response(),
        Err(err) => {
            error!("Failed to list projects: {err}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[utoipa::path(
    post,
    path = "/v1/orgs/{org_slug}/projects/{project_slug}/envs",
    request_body = CreateEnvironmentRequest,
    params(
        ("org_slug" = String, Path, description = "Organization slug"),
        ("project_slug" = String, Path, description = "Project slug")
    ),
    responses(
        (status = 201, description = "Environment created.", body = EnvironmentResponse),
        (status = 400, description = "Invalid input.", body = String),
        (status = 401, description = "Missing or invalid session cookie."),
        (status = 404, description = "Organization or project not found."),
        (status = 409, description = "Environment conflict.", body = String),
    ),
    tag = "environments"
)]
pub async fn create_environment(
    Path((org_slug, project_slug)): Path<(String, String)>,
    headers: HeaderMap,
    pool: Extension<PgPool>,
    Json(payload): Json<CreateEnvironmentRequest>,
) -> impl IntoResponse {
    let principal = match require_auth(&headers, &pool).await {
        Ok(principal) => principal,
        Err(status) => return status.into_response(),
    };

    let name = payload.name.trim();
    if name.is_empty() {
        return (StatusCode::BAD_REQUEST, "Environment name is required.").into_response();
    }

    let Some(slug) = normalize_slug(&payload.slug, ENV_SLUG_MIN, ENV_SLUG_MAX) else {
        return (StatusCode::BAD_REQUEST, "Invalid environment slug.").into_response();
    };

    let context = match resolve_org_context(&pool, principal.user_id, &org_slug).await {
        Ok(Some(context)) => context,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(err) => {
            error!("Failed to resolve org for environment: {err}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    if !context.can_manage() {
        return StatusCode::NOT_FOUND.into_response();
    }

    let project = match resolve_project(&pool, context.id, &project_slug).await {
        Ok(Some(project)) => project,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(err) => {
            error!("Failed to resolve project for environment: {err}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    match insert_environment(&pool, project.id, name, &slug, payload.tier).await {
        Ok(response) => (StatusCode::CREATED, Json(response)).into_response(),
        Err(err) => err.into_response(),
    }
}

#[utoipa::path(
    get,
    path = "/v1/orgs/{org_slug}/projects/{project_slug}/envs",
    params(
        ("org_slug" = String, Path, description = "Organization slug"),
        ("project_slug" = String, Path, description = "Project slug")
    ),
    responses(
        (status = 200, description = "List environments.", body = [EnvironmentResponse]),
        (status = 401, description = "Missing or invalid session cookie."),
        (status = 404, description = "Organization or project not found."),
    ),
    tag = "environments"
)]
pub async fn list_environments(
    Path((org_slug, project_slug)): Path<(String, String)>,
    headers: HeaderMap,
    pool: Extension<PgPool>,
) -> impl IntoResponse {
    let principal = match require_auth(&headers, &pool).await {
        Ok(principal) => principal,
        Err(status) => return status.into_response(),
    };

    let context = match resolve_org_context(&pool, principal.user_id, &org_slug).await {
        Ok(Some(context)) => context,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(err) => {
            error!("Failed to resolve org for env list: {err}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let project = match resolve_project(&pool, context.id, &project_slug).await {
        Ok(Some(project)) => project,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(err) => {
            error!("Failed to resolve project for env list: {err}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    match fetch_environments(&pool, project.id).await {
        Ok(rows) => (StatusCode::OK, Json(rows)).into_response(),
        Err(err) => {
            error!("Failed to list environments: {err}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[utoipa::path(
    post,
    path = "/v1/orgs/{org_slug}/projects/{project_slug}/envs/{env_slug}/apps",
    request_body = CreateApplicationRequest,
    params(
        ("org_slug" = String, Path, description = "Organization slug"),
        ("project_slug" = String, Path, description = "Project slug"),
        ("env_slug" = String, Path, description = "Environment slug")
    ),
    responses(
        (status = 201, description = "Application created.", body = ApplicationResponse),
        (status = 400, description = "Invalid input.", body = String),
        (status = 401, description = "Missing or invalid session cookie."),
        (status = 404, description = "Organization, project, or environment not found."),
        (status = 409, description = "Application already exists.", body = String),
    ),
    tag = "applications"
)]
pub async fn create_application(
    Path((org_slug, project_slug, env_slug)): Path<(String, String, String)>,
    headers: HeaderMap,
    pool: Extension<PgPool>,
    Json(payload): Json<CreateApplicationRequest>,
) -> impl IntoResponse {
    let principal = match require_auth(&headers, &pool).await {
        Ok(principal) => principal,
        Err(status) => return status.into_response(),
    };

    let name = payload.name.trim();
    if name.is_empty() {
        return (StatusCode::BAD_REQUEST, "Application name is required.").into_response();
    }

    let context = match resolve_org_context(&pool, principal.user_id, &org_slug).await {
        Ok(Some(context)) => context,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(err) => {
            error!("Failed to resolve org for application: {err}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    if !context.can_manage() {
        return StatusCode::NOT_FOUND.into_response();
    }

    let project = match resolve_project(&pool, context.id, &project_slug).await {
        Ok(Some(project)) => project,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(err) => {
            error!("Failed to resolve project for application: {err}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let env = match resolve_environment(&pool, project.id, &env_slug).await {
        Ok(Some(env)) => env,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(err) => {
            error!("Failed to resolve environment for application: {err}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    match insert_application(&pool, env.id, name).await {
        Ok(response) => (StatusCode::CREATED, Json(response)).into_response(),
        Err(err) => err.into_response(),
    }
}

#[utoipa::path(
    get,
    path = "/v1/orgs/{org_slug}/projects/{project_slug}/envs/{env_slug}/apps",
    params(
        ("org_slug" = String, Path, description = "Organization slug"),
        ("project_slug" = String, Path, description = "Project slug"),
        ("env_slug" = String, Path, description = "Environment slug")
    ),
    responses(
        (status = 200, description = "List applications.", body = [ApplicationResponse]),
        (status = 401, description = "Missing or invalid session cookie."),
        (status = 404, description = "Organization, project, or environment not found."),
    ),
    tag = "applications"
)]
pub async fn list_applications(
    Path((org_slug, project_slug, env_slug)): Path<(String, String, String)>,
    headers: HeaderMap,
    pool: Extension<PgPool>,
) -> impl IntoResponse {
    let principal = match require_auth(&headers, &pool).await {
        Ok(principal) => principal,
        Err(status) => return status.into_response(),
    };

    let context = match resolve_org_context(&pool, principal.user_id, &org_slug).await {
        Ok(Some(context)) => context,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(err) => {
            error!("Failed to resolve org for apps list: {err}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let project = match resolve_project(&pool, context.id, &project_slug).await {
        Ok(Some(project)) => project,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(err) => {
            error!("Failed to resolve project for apps list: {err}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let env = match resolve_environment(&pool, project.id, &env_slug).await {
        Ok(Some(env)) => env,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(err) => {
            error!("Failed to resolve environment for apps list: {err}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    match fetch_applications(&pool, env.id).await {
        Ok(rows) => (StatusCode::OK, Json(rows)).into_response(),
        Err(err) => {
            error!("Failed to list applications: {err}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[derive(Debug)]
pub(crate) struct OrgContext {
    id: Uuid,
    slug: String,
    name: String,
    created_at: String,
    roles: Vec<String>,
}

impl OrgContext {
    fn can_manage(&self) -> bool {
        self.roles
            .iter()
            .any(|role| role == ORG_ROLE_OWNER || role == ORG_ROLE_ADMIN)
    }

    fn to_response(&self) -> OrgResponse {
        OrgResponse {
            id: self.id.to_string(),
            slug: self.slug.clone(),
            name: self.name.clone(),
            created_at: self.created_at.clone(),
        }
    }
}

#[derive(Debug)]
pub(crate) struct ProjectRow {
    id: Uuid,
}

#[derive(Debug)]
pub(crate) struct EnvironmentRow {
    id: Uuid,
}

#[derive(Debug)]
enum OrgError {
    BadRequest(&'static str),
    Conflict(&'static str),
    Database(sqlx::Error),
}

impl IntoResponse for OrgError {
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

async fn create_org_with_roles(
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

async fn fetch_orgs_for_user(
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

async fn resolve_org_context(
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

async fn update_org_record(
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

async fn insert_project(
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

async fn fetch_projects(pool: &PgPool, org_id: Uuid) -> Result<Vec<ProjectResponse>, sqlx::Error> {
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

async fn resolve_project(
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

async fn insert_environment(
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

async fn fetch_environments(
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

async fn resolve_environment(
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

async fn insert_application(
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

async fn fetch_applications(
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

fn normalize_slug(input: &str, min: usize, max: usize) -> Option<String> {
    let mut slug = String::new();
    let mut prev_dash = false;
    for ch in input.trim().to_lowercase().chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch);
            prev_dash = false;
        } else if !prev_dash {
            slug.push('-');
            prev_dash = true;
        }
    }
    let trimmed = slug.trim_matches('-').to_string();
    if trimmed.is_empty() {
        return None;
    }
    let truncated: String = trimmed.chars().take(max).collect();
    let normalized = truncated.trim_matches('-').to_string();
    if normalized.len() < min || normalized.len() > max {
        return None;
    }
    Some(normalized)
}

fn with_suffix(base: &str, suffix: usize, max_len: usize) -> Option<String> {
    let suffix = format!("-{suffix}");
    if suffix.len() >= max_len {
        return None;
    }
    let allowed = max_len.saturating_sub(suffix.len());
    let mut base_part: String = base.chars().take(allowed).collect();
    base_part = base_part.trim_end_matches('-').to_string();
    if base_part.is_empty() {
        return None;
    }
    Some(format!("{base_part}{suffix}"))
}

fn is_unique_violation(err: &sqlx::Error) -> bool {
    match err {
        sqlx::Error::Database(db_err) => db_err.code().as_deref() == Some("23505"),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, Result};
    use axum::{
        Extension, Router,
        body::{Body, to_bytes},
        http::{
            Request, StatusCode,
            header::{CONTENT_TYPE, COOKIE},
        },
        routing::{get, post},
    };
    use serde_json::json;
    use sqlx::{Connection, PgConnection, PgPool, Row, postgres::PgPoolOptions};
    use test_support::{TestNetwork, postgres::PostgresContainer, runtime};
    use tower::ServiceExt;

    const PERMESI_SCHEMA_SQL: &str =
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/sql/schema.sql"));

    struct TestDb {
        _postgres: PostgresContainer,
        pool: PgPool,
    }

    impl TestDb {
        async fn new() -> Result<Self> {
            if let Err(err) = runtime::ensure_container_runtime() {
                eprintln!("Skipping integration test: {err}");
                return Err(err);
            }

            let network = TestNetwork::new("permesi-orgs");
            let postgres = PostgresContainer::start(network.name()).await?;
            postgres.wait_until_ready().await?;
            apply_schema(&postgres).await?;

            let pool = PgPoolOptions::new()
                .max_connections(5)
                .connect(&postgres.admin_dsn())
                .await
                .context("failed to connect test pool")?;

            Ok(Self {
                _postgres: postgres,
                pool,
            })
        }
    }

    async fn apply_schema(postgres: &PostgresContainer) -> Result<()> {
        let mut connection = PgConnection::connect(&postgres.admin_dsn())
            .await
            .context("failed to connect for schema setup")?;

        for (index, statement) in split_sql_statements(PERMESI_SCHEMA_SQL).iter().enumerate() {
            sqlx::query(statement)
                .execute(&mut connection)
                .await
                .with_context(|| format!("failed to execute schema statement {}", index + 1))?;
        }

        Ok(())
    }

    fn split_sql_statements(sql: &str) -> Vec<String> {
        let mut statements = Vec::new();
        let mut current = String::new();

        for line in sql.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("\\ir ") {
                continue;
            }
            current.push_str(line);
            current.push('\n');

            if trimmed.ends_with(';') {
                let statement = current.trim();
                if !statement.is_empty() {
                    statements.push(statement.to_string());
                }
                current.clear();
            }
        }

        let leftover = current.trim();
        if !leftover.is_empty() {
            statements.push(leftover.to_string());
        }

        statements
    }

    async fn insert_active_user(pool: &PgPool, email: &str) -> Result<Uuid> {
        let user_id = Uuid::new_v4();
        let query = r"
            INSERT INTO users (id, email, opaque_registration_record, status)
            VALUES ($1, $2, $3, 'active')
        ";
        sqlx::query(query)
            .bind(user_id)
            .bind(email)
            .bind(vec![0u8; 16])
            .execute(pool)
            .await
            .context("insert active user")?;
        Ok(user_id)
    }

    async fn insert_session(pool: &PgPool, user_id: Uuid) -> Result<String> {
        let token = super::super::auth::generate_session_token()?;
        let hash = super::super::auth::hash_session_token(&token);
        let query = r"
            INSERT INTO user_sessions (user_id, session_hash, expires_at)
            VALUES ($1, $2, NOW() + INTERVAL '1 hour')
        ";
        sqlx::query(query)
            .bind(user_id)
            .bind(hash)
            .execute(pool)
            .await
            .context("insert session")?;
        Ok(token)
    }

    async fn insert_member_role(
        pool: &PgPool,
        org_id: Uuid,
        user_id: Uuid,
        role: &str,
    ) -> Result<()> {
        sqlx::query(
            r"
            INSERT INTO org_memberships (org_id, user_id, status)
            VALUES ($1, $2, 'active')
            ON CONFLICT (org_id, user_id) DO NOTHING
            ",
        )
        .bind(org_id)
        .bind(user_id)
        .execute(pool)
        .await?;
        sqlx::query(
            r"
            INSERT INTO org_member_roles (org_id, user_id, role_name)
            VALUES ($1, $2, $3)
            ",
        )
        .bind(org_id)
        .bind(user_id)
        .bind(role)
        .execute(pool)
        .await?;
        Ok(())
    }

    fn app_router(pool: PgPool) -> Router {
        Router::new()
            .route("/v1/orgs", post(super::create_org).get(super::list_orgs))
            .route(
                "/v1/orgs/:org_slug",
                get(super::get_org).patch(super::patch_org),
            )
            .route(
                "/v1/orgs/:org_slug/projects",
                post(super::create_project).get(super::list_projects),
            )
            .route(
                "/v1/orgs/:org_slug/projects/:project_slug/envs",
                post(super::create_environment).get(super::list_environments),
            )
            .route(
                "/v1/orgs/:org_slug/projects/:project_slug/envs/:env_slug/apps",
                post(super::create_application).get(super::list_applications),
            )
            .layer(Extension(pool))
    }

    #[tokio::test]
    async fn org_creation_assigns_owner_role() -> Result<()> {
        let Ok(db) = TestDb::new().await else {
            return Ok(());
        };
        let user_id = insert_active_user(&db.pool, "owner@example.com").await?;
        let token = insert_session(&db.pool, user_id).await?;

        let app = app_router(db.pool.clone());
        let payload = json!({ "name": "Acme" });
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/orgs")
                    .header(COOKIE, format!("permesi_session={token}"))
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(payload.to_string()))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::CREATED);

        let row = sqlx::query(
            "SELECT org_id FROM org_member_roles WHERE user_id = $1 AND role_name = 'owner'",
        )
        .bind(user_id)
        .fetch_one(&db.pool)
        .await?;
        let org_id: Uuid = row.get("org_id");
        assert_ne!(org_id, Uuid::nil());
        Ok(())
    }

    #[tokio::test]
    async fn project_creation_requires_owner_or_admin() -> Result<()> {
        let Ok(db) = TestDb::new().await else {
            return Ok(());
        };
        let owner_id = insert_active_user(&db.pool, "owner2@example.com").await?;
        let owner_token = insert_session(&db.pool, owner_id).await?;
        let member_id = insert_active_user(&db.pool, "member@example.com").await?;
        let member_token = insert_session(&db.pool, member_id).await?;

        let app = app_router(db.pool.clone());
        let org_payload = json!({ "name": "Beta" });
        let org_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/orgs")
                    .header(COOKIE, format!("permesi_session={owner_token}"))
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(org_payload.to_string()))?,
            )
            .await?;
        assert_eq!(org_response.status(), StatusCode::CREATED);

        let org_row = sqlx::query("SELECT id, slug FROM organizations WHERE name = 'Beta'")
            .fetch_one(&db.pool)
            .await?;
        let org_id: Uuid = org_row.get("id");
        let org_slug: String = org_row.get("slug");

        insert_member_role(&db.pool, org_id, member_id, "member").await?;

        let payload = json!({ "name": "Payments" });
        let forbidden = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/orgs/{org_slug}/projects"))
                    .header(COOKIE, format!("permesi_session={member_token}"))
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(payload.to_string()))?,
            )
            .await?;
        assert_eq!(forbidden.status(), StatusCode::NOT_FOUND);

        let allowed = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/orgs/{org_slug}/projects"))
                    .header(COOKIE, format!("permesi_session={owner_token}"))
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(payload.to_string()))?,
            )
            .await?;
        assert_eq!(allowed.status(), StatusCode::CREATED);
        Ok(())
    }

    #[tokio::test]
    async fn environment_creation_enforces_single_production() -> Result<()> {
        let Ok(db) = TestDb::new().await else {
            return Ok(());
        };
        let user_id = insert_active_user(&db.pool, "env-owner@example.com").await?;
        let token = insert_session(&db.pool, user_id).await?;

        let app = app_router(db.pool.clone());
        let org_payload = json!({ "name": "Gamma" });
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/orgs")
                    .header(COOKIE, format!("permesi_session={token}"))
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(org_payload.to_string()))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::CREATED);

        let org_row = sqlx::query("SELECT id, slug FROM organizations WHERE name = 'Gamma'")
            .fetch_one(&db.pool)
            .await?;
        let org_id: Uuid = org_row.get("id");
        let org_slug: String = org_row.get("slug");

        let project_payload = json!({ "name": "Payments" });
        let project_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/orgs/{org_slug}/projects"))
                    .header(COOKIE, format!("permesi_session={token}"))
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(project_payload.to_string()))?,
            )
            .await?;
        assert_eq!(project_response.status(), StatusCode::CREATED);

        let project_row = sqlx::query("SELECT id, slug FROM projects WHERE org_id = $1")
            .bind(org_id)
            .fetch_one(&db.pool)
            .await?;
        let project_slug: String = project_row.get("slug");

        let non_prod_payload = json!({
            "name": "Dev",
            "slug": "dev",
            "tier": "non_production"
        });
        let non_prod_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/orgs/{org_slug}/projects/{project_slug}/envs"))
                    .header(COOKIE, format!("permesi_session={token}"))
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(non_prod_payload.to_string()))?,
            )
            .await?;
        assert_eq!(non_prod_response.status(), StatusCode::BAD_REQUEST);

        let prod_payload = json!({
            "name": "Production",
            "slug": "prod",
            "tier": "production"
        });
        let prod_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/orgs/{org_slug}/projects/{project_slug}/envs"))
                    .header(COOKIE, format!("permesi_session={token}"))
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(prod_payload.to_string()))?,
            )
            .await?;
        assert_eq!(prod_response.status(), StatusCode::CREATED);

        let second_prod = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/orgs/{org_slug}/projects/{project_slug}/envs"))
                    .header(COOKIE, format!("permesi_session={token}"))
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(prod_payload.to_string()))?,
            )
            .await?;
        assert_eq!(second_prod.status(), StatusCode::CONFLICT);
        Ok(())
    }

    #[tokio::test]
    async fn environment_list_returns_created_envs() -> Result<()> {
        let Ok(db) = TestDb::new().await else {
            return Ok(());
        };
        let user_id = insert_active_user(&db.pool, "env-list@example.com").await?;
        let token = insert_session(&db.pool, user_id).await?;

        let app = app_router(db.pool.clone());
        let org_payload = json!({ "name": "Delta" });
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/orgs")
                    .header(COOKIE, format!("permesi_session={token}"))
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(org_payload.to_string()))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::CREATED);

        let org_row = sqlx::query("SELECT id, slug FROM organizations WHERE name = 'Delta'")
            .fetch_one(&db.pool)
            .await?;
        let org_id: Uuid = org_row.get("id");
        let org_slug: String = org_row.get("slug");

        let project_payload = json!({ "name": "Core" });
        let project_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/orgs/{org_slug}/projects"))
                    .header(COOKIE, format!("permesi_session={token}"))
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(project_payload.to_string()))?,
            )
            .await?;
        assert_eq!(project_response.status(), StatusCode::CREATED);

        let project_row = sqlx::query("SELECT id, slug FROM projects WHERE org_id = $1")
            .bind(org_id)
            .fetch_one(&db.pool)
            .await?;
        let project_slug: String = project_row.get("slug");

        let prod_payload = json!({
            "name": "Production",
            "slug": "production",
            "tier": "production"
        });
        let prod_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/orgs/{org_slug}/projects/{project_slug}/envs"))
                    .header(COOKIE, format!("permesi_session={token}"))
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(prod_payload.to_string()))?,
            )
            .await?;
        assert_eq!(prod_response.status(), StatusCode::CREATED);

        let staging_payload = json!({
            "name": "Staging",
            "slug": "stage",
            "tier": "non_production"
        });
        let stage_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/orgs/{org_slug}/projects/{project_slug}/envs"))
                    .header(COOKIE, format!("permesi_session={token}"))
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(staging_payload.to_string()))?,
            )
            .await?;
        assert_eq!(stage_response.status(), StatusCode::CREATED);

        let list_response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/orgs/{org_slug}/projects/{project_slug}/envs"))
                    .header(COOKIE, format!("permesi_session={token}"))
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(list_response.status(), StatusCode::OK);
        Ok(())
    }

    #[tokio::test]
    async fn non_member_access_returns_404() -> Result<()> {
        let Ok(db) = TestDb::new().await else {
            return Ok(());
        };
        let owner_id = insert_active_user(&db.pool, "owner3@example.com").await?;
        let owner_token = insert_session(&db.pool, owner_id).await?;
        let stranger_id = insert_active_user(&db.pool, "stranger@example.com").await?;
        let stranger_token = insert_session(&db.pool, stranger_id).await?;

        let app = app_router(db.pool.clone());
        let org_payload = json!({ "name": "Epsilon" });
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/orgs")
                    .header(COOKIE, format!("permesi_session={owner_token}"))
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(org_payload.to_string()))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::CREATED);

        let org_row = sqlx::query("SELECT slug FROM organizations WHERE name = 'Epsilon'")
            .fetch_one(&db.pool)
            .await?;
        let org_slug: String = org_row.get("slug");

        let forbidden = app
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/orgs/{org_slug}"))
                    .header(COOKIE, format!("permesi_session={stranger_token}"))
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(forbidden.status(), StatusCode::NOT_FOUND);
        Ok(())
    }

    #[tokio::test]
    async fn owner_can_create_app() -> Result<()> {
        let Ok(db) = TestDb::new().await else {
            return Ok(());
        };
        let user_id = insert_active_user(&db.pool, "app-owner@example.com").await?;
        let token = insert_session(&db.pool, user_id).await?;

        let app = app_router(db.pool.clone());
        let org_payload = json!({ "name": "Zeta" });
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/orgs")
                    .header(COOKIE, format!("permesi_session={token}"))
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(org_payload.to_string()))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::CREATED);

        let org_row = sqlx::query("SELECT id, slug FROM organizations WHERE name = 'Zeta'")
            .fetch_one(&db.pool)
            .await?;
        let org_id: Uuid = org_row.get("id");
        let org_slug: String = org_row.get("slug");

        let project_payload = json!({ "name": "Frontend" });
        let project_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/orgs/{org_slug}/projects"))
                    .header(COOKIE, format!("permesi_session={token}"))
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(project_payload.to_string()))?,
            )
            .await?;
        assert_eq!(project_response.status(), StatusCode::CREATED);

        let project_row = sqlx::query("SELECT id, slug FROM projects WHERE org_id = $1")
            .bind(org_id)
            .fetch_one(&db.pool)
            .await?;
        let project_slug: String = project_row.get("slug");

        let prod_payload = json!({
            "name": "Production",
            "slug": "prod",
            "tier": "production"
        });
        let prod_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/orgs/{org_slug}/projects/{project_slug}/envs"))
                    .header(COOKIE, format!("permesi_session={token}"))
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(prod_payload.to_string()))?,
            )
            .await?;
        assert_eq!(prod_response.status(), StatusCode::CREATED);

        let app_payload = json!({ "name": "Payments API" });
        let app_response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!(
                        "/v1/orgs/{org_slug}/projects/{project_slug}/envs/prod/apps"
                    ))
                    .header(COOKIE, format!("permesi_session={token}"))
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(app_payload.to_string()))?,
            )
            .await?;
        assert_eq!(app_response.status(), StatusCode::CREATED);
        Ok(())
    }

    #[tokio::test]
    async fn soft_deleted_org_is_hidden_by_default() -> Result<()> {
        let Ok(db) = TestDb::new().await else {
            return Ok(());
        };
        let user_id = insert_active_user(&db.pool, "hidden-org@example.com").await?;
        let token = insert_session(&db.pool, user_id).await?;

        let app = app_router(db.pool.clone());
        let payload = json!({ "name": "HiddenOrg" });
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/orgs")
                    .header(COOKIE, format!("permesi_session={token}"))
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(payload.to_string()))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::CREATED);

        let org_row = sqlx::query("SELECT id, slug FROM organizations WHERE name = 'HiddenOrg'")
            .fetch_one(&db.pool)
            .await?;
        let org_id: Uuid = org_row.get("id");
        let org_slug: String = org_row.get("slug");

        sqlx::query("UPDATE organizations SET deleted_at = NOW() WHERE id = $1")
            .bind(org_id)
            .execute(&db.pool)
            .await?;

        let get_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/orgs/{org_slug}"))
                    .header(COOKIE, format!("permesi_session={token}"))
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(get_response.status(), StatusCode::NOT_FOUND);

        let list_response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/orgs")
                    .header(COOKIE, format!("permesi_session={token}"))
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(list_response.status(), StatusCode::OK);
        let body = to_bytes(list_response.into_body(), usize::MAX).await?;
        let list: Vec<serde_json::Value> = serde_json::from_slice(&body)?;
        assert!(list.iter().all(|item| {
            item.get("slug").and_then(|value| value.as_str()) != Some(org_slug.as_str())
        }));

        Ok(())
    }

    #[tokio::test]
    async fn soft_deleted_project_is_hidden_even_with_envs() -> Result<()> {
        let Ok(db) = TestDb::new().await else {
            return Ok(());
        };
        let user_id = insert_active_user(&db.pool, "hidden-project@example.com").await?;
        let token = insert_session(&db.pool, user_id).await?;

        let app = app_router(db.pool.clone());
        let org_payload = json!({ "name": "ProjectOrg" });
        let org_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/orgs")
                    .header(COOKIE, format!("permesi_session={token}"))
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(org_payload.to_string()))?,
            )
            .await?;
        assert_eq!(org_response.status(), StatusCode::CREATED);

        let org_row = sqlx::query("SELECT id, slug FROM organizations WHERE name = 'ProjectOrg'")
            .fetch_one(&db.pool)
            .await?;
        let org_id: Uuid = org_row.get("id");
        let org_slug: String = org_row.get("slug");

        let project_payload = json!({ "name": "HiddenProject" });
        let project_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/orgs/{org_slug}/projects"))
                    .header(COOKIE, format!("permesi_session={token}"))
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(project_payload.to_string()))?,
            )
            .await?;
        assert_eq!(project_response.status(), StatusCode::CREATED);

        let project_row = sqlx::query("SELECT id, slug FROM projects WHERE org_id = $1")
            .bind(org_id)
            .fetch_one(&db.pool)
            .await?;
        let project_id: Uuid = project_row.get("id");
        let project_slug: String = project_row.get("slug");

        let env_payload = json!({
            "name": "Production",
            "slug": "prod",
            "tier": "production"
        });
        let env_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/orgs/{org_slug}/projects/{project_slug}/envs"))
                    .header(COOKIE, format!("permesi_session={token}"))
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(env_payload.to_string()))?,
            )
            .await?;
        assert_eq!(env_response.status(), StatusCode::CREATED);

        sqlx::query("UPDATE projects SET deleted_at = NOW() WHERE id = $1")
            .bind(project_id)
            .execute(&db.pool)
            .await?;

        let list_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/orgs/{org_slug}/projects"))
                    .header(COOKIE, format!("permesi_session={token}"))
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(list_response.status(), StatusCode::OK);
        let body = to_bytes(list_response.into_body(), usize::MAX).await?;
        let list: Vec<serde_json::Value> = serde_json::from_slice(&body)?;
        assert!(list.is_empty());

        let env_list_response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/orgs/{org_slug}/projects/{project_slug}/envs"))
                    .header(COOKIE, format!("permesi_session={token}"))
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(env_list_response.status(), StatusCode::NOT_FOUND);

        Ok(())
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn soft_deleted_environment_is_hidden_even_with_apps() -> Result<()> {
        let Ok(db) = TestDb::new().await else {
            return Ok(());
        };
        let user_id = insert_active_user(&db.pool, "hidden-env@example.com").await?;
        let token = insert_session(&db.pool, user_id).await?;

        let app = app_router(db.pool.clone());
        let org_payload = json!({ "name": "EnvOrg" });
        let org_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/orgs")
                    .header(COOKIE, format!("permesi_session={token}"))
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(org_payload.to_string()))?,
            )
            .await?;
        assert_eq!(org_response.status(), StatusCode::CREATED);

        let org_row = sqlx::query("SELECT id, slug FROM organizations WHERE name = 'EnvOrg'")
            .fetch_one(&db.pool)
            .await?;
        let org_id: Uuid = org_row.get("id");
        let org_slug: String = org_row.get("slug");

        let project_payload = json!({ "name": "EnvProject" });
        let project_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/orgs/{org_slug}/projects"))
                    .header(COOKIE, format!("permesi_session={token}"))
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(project_payload.to_string()))?,
            )
            .await?;
        assert_eq!(project_response.status(), StatusCode::CREATED);

        let project_row = sqlx::query("SELECT id, slug FROM projects WHERE org_id = $1")
            .bind(org_id)
            .fetch_one(&db.pool)
            .await?;
        let project_id: Uuid = project_row.get("id");
        let project_slug: String = project_row.get("slug");

        let env_payload = json!({
            "name": "Production",
            "slug": "prod",
            "tier": "production"
        });
        let env_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/orgs/{org_slug}/projects/{project_slug}/envs"))
                    .header(COOKIE, format!("permesi_session={token}"))
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(env_payload.to_string()))?,
            )
            .await?;
        assert_eq!(env_response.status(), StatusCode::CREATED);

        let env_row = sqlx::query("SELECT id, slug FROM environments WHERE project_id = $1")
            .bind(project_id)
            .fetch_one(&db.pool)
            .await?;
        let env_id: Uuid = env_row.get("id");
        let env_slug: String = env_row.get("slug");

        let app_payload = json!({ "name": "HiddenEnvApp" });
        let app_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!(
                        "/v1/orgs/{org_slug}/projects/{project_slug}/envs/{env_slug}/apps"
                    ))
                    .header(COOKIE, format!("permesi_session={token}"))
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(app_payload.to_string()))?,
            )
            .await?;
        assert_eq!(app_response.status(), StatusCode::CREATED);

        sqlx::query("UPDATE environments SET deleted_at = NOW() WHERE id = $1")
            .bind(env_id)
            .execute(&db.pool)
            .await?;

        let env_list_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/orgs/{org_slug}/projects/{project_slug}/envs"))
                    .header(COOKIE, format!("permesi_session={token}"))
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(env_list_response.status(), StatusCode::OK);
        let body = to_bytes(env_list_response.into_body(), usize::MAX).await?;
        let list: Vec<serde_json::Value> = serde_json::from_slice(&body)?;
        assert!(list.is_empty());

        let app_list_response = app
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/v1/orgs/{org_slug}/projects/{project_slug}/envs/{env_slug}/apps"
                    ))
                    .header(COOKIE, format!("permesi_session={token}"))
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(app_list_response.status(), StatusCode::NOT_FOUND);

        Ok(())
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn soft_deleted_app_is_hidden_by_default() -> Result<()> {
        let Ok(db) = TestDb::new().await else {
            return Ok(());
        };
        let user_id = insert_active_user(&db.pool, "hidden-app@example.com").await?;
        let token = insert_session(&db.pool, user_id).await?;

        let app = app_router(db.pool.clone());
        let org_payload = json!({ "name": "AppOrg" });
        let org_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/orgs")
                    .header(COOKIE, format!("permesi_session={token}"))
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(org_payload.to_string()))?,
            )
            .await?;
        assert_eq!(org_response.status(), StatusCode::CREATED);

        let org_row = sqlx::query("SELECT id, slug FROM organizations WHERE name = 'AppOrg'")
            .fetch_one(&db.pool)
            .await?;
        let org_id: Uuid = org_row.get("id");
        let org_slug: String = org_row.get("slug");

        let project_payload = json!({ "name": "AppProject" });
        let project_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/orgs/{org_slug}/projects"))
                    .header(COOKIE, format!("permesi_session={token}"))
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(project_payload.to_string()))?,
            )
            .await?;
        assert_eq!(project_response.status(), StatusCode::CREATED);

        let project_row = sqlx::query("SELECT id, slug FROM projects WHERE org_id = $1")
            .bind(org_id)
            .fetch_one(&db.pool)
            .await?;
        let project_id: Uuid = project_row.get("id");
        let project_slug: String = project_row.get("slug");

        let env_payload = json!({
            "name": "Production",
            "slug": "prod",
            "tier": "production"
        });
        let env_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/orgs/{org_slug}/projects/{project_slug}/envs"))
                    .header(COOKIE, format!("permesi_session={token}"))
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(env_payload.to_string()))?,
            )
            .await?;
        assert_eq!(env_response.status(), StatusCode::CREATED);

        let env_row = sqlx::query("SELECT id, slug FROM environments WHERE project_id = $1")
            .bind(project_id)
            .fetch_one(&db.pool)
            .await?;
        let env_id: Uuid = env_row.get("id");
        let env_slug: String = env_row.get("slug");

        let app_payload = json!({ "name": "HiddenApp" });
        let app_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!(
                        "/v1/orgs/{org_slug}/projects/{project_slug}/envs/{env_slug}/apps"
                    ))
                    .header(COOKIE, format!("permesi_session={token}"))
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(app_payload.to_string()))?,
            )
            .await?;
        assert_eq!(app_response.status(), StatusCode::CREATED);

        let app_row = sqlx::query("SELECT id FROM applications WHERE environment_id = $1")
            .bind(env_id)
            .fetch_one(&db.pool)
            .await?;
        let app_id: Uuid = app_row.get("id");

        sqlx::query("UPDATE applications SET deleted_at = NOW() WHERE id = $1")
            .bind(app_id)
            .execute(&db.pool)
            .await?;

        let app_list_response = app
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/v1/orgs/{org_slug}/projects/{project_slug}/envs/{env_slug}/apps"
                    ))
                    .header(COOKIE, format!("permesi_session={token}"))
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(app_list_response.status(), StatusCode::OK);
        let body = to_bytes(app_list_response.into_body(), usize::MAX).await?;
        let list: Vec<serde_json::Value> = serde_json::from_slice(&body)?;
        assert!(list.is_empty());

        Ok(())
    }
}
