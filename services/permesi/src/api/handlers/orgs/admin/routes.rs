//! Explicit GET-only route contracts; all reads pass through the shared operator guard.

use super::{AdminMetadata, AdminPage, PageQuery, Scope, Selector};
use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    response::Response,
};
use sqlx::PgPool;
use uuid::Uuid;

/// Lists bounded metadata for enabled operators with a full session; grants no tenant write authority.
#[utoipa::path(get, operation_id = "admin_list_organizations", path = "/v1/admin/orgs",
    params(("after" = Option<String>, Query, description = "Last item UUID from the previous page")),
    responses((status = 200, body = AdminPage),
        (status = 400, description = "Invalid path or cursor"),
        (status = 401, description = "Valid full session required"),
        (status = 403, description = "Enabled platform operator required"),
        (status = 404, description = "Active ancestry or resource not found"),
        (status = 503, description = "Storage unavailable")), tag = "admin-tenants")]
pub(crate) async fn list_organizations(
    headers: HeaderMap,
    State(pool): State<PgPool>,
    query: Query<PageQuery>,
) -> Response {
    super::list(headers, pool, Scope::Organizations, query).await
}

/// Inspects one active resource for enabled operators with a full session; grants no tenant write authority.
#[utoipa::path(get, operation_id = "admin_get_organization", path = "/v1/admin/orgs/{org_slug}",
    params(("org_slug" = String, Path, description = "Resource ancestry")),
    responses((status = 200, body = AdminMetadata),
        (status = 400, description = "Invalid path or cursor"),
        (status = 401, description = "Valid full session required"),
        (status = 403, description = "Enabled platform operator required"),
        (status = 404, description = "Active ancestry or resource not found"),
        (status = 503, description = "Storage unavailable")), tag = "admin-tenants")]
pub(crate) async fn get_organization(
    Path(org): Path<String>,
    headers: HeaderMap,
    State(pool): State<PgPool>,
) -> Response {
    super::detail(headers, pool, Scope::Organizations, Selector::Slug(org)).await
}

/// Lists bounded metadata for enabled operators with a full session; grants no tenant write authority.
#[utoipa::path(get, operation_id = "admin_list_projects", path = "/v1/admin/orgs/{org_slug}/projects",
    params(("org_slug" = String, Path, description = "Resource ancestry"),("after" = Option<String>, Query, description = "Last item UUID from the previous page")),
    responses((status = 200, body = AdminPage),
        (status = 400, description = "Invalid path or cursor"),
        (status = 401, description = "Valid full session required"),
        (status = 403, description = "Enabled platform operator required"),
        (status = 404, description = "Active ancestry or resource not found"),
        (status = 503, description = "Storage unavailable")), tag = "admin-tenants")]
pub(crate) async fn list_projects(
    Path(org): Path<String>,
    headers: HeaderMap,
    State(pool): State<PgPool>,
    query: Query<PageQuery>,
) -> Response {
    super::list(headers, pool, Scope::Projects(org), query).await
}

/// Inspects one active resource for enabled operators with a full session; grants no tenant write authority.
#[utoipa::path(get, operation_id = "admin_get_project", path = "/v1/admin/orgs/{org_slug}/projects/{project_slug}",
    params(("org_slug" = String, Path, description = "Resource ancestry"),("project_slug" = String, Path, description = "Resource ancestry")),
    responses((status = 200, body = AdminMetadata),
        (status = 400, description = "Invalid path or cursor"),
        (status = 401, description = "Valid full session required"),
        (status = 403, description = "Enabled platform operator required"),
        (status = 404, description = "Active ancestry or resource not found"),
        (status = 503, description = "Storage unavailable")), tag = "admin-tenants")]
pub(crate) async fn get_project(
    Path((org, project)): Path<(String, String)>,
    headers: HeaderMap,
    State(pool): State<PgPool>,
) -> Response {
    super::detail(headers, pool, Scope::Projects(org), Selector::Slug(project)).await
}

/// Lists bounded metadata for enabled operators with a full session; grants no tenant write authority.
#[utoipa::path(get, operation_id = "admin_list_environments", path = "/v1/admin/orgs/{org_slug}/projects/{project_slug}/envs",
    params(("org_slug" = String, Path, description = "Resource ancestry"),("project_slug" = String, Path, description = "Resource ancestry"),("after" = Option<String>, Query, description = "Last item UUID from the previous page")),
    responses((status = 200, body = AdminPage),
        (status = 400, description = "Invalid path or cursor"),
        (status = 401, description = "Valid full session required"),
        (status = 403, description = "Enabled platform operator required"),
        (status = 404, description = "Active ancestry or resource not found"),
        (status = 503, description = "Storage unavailable")), tag = "admin-tenants")]
pub(crate) async fn list_environments(
    Path((org, project)): Path<(String, String)>,
    headers: HeaderMap,
    State(pool): State<PgPool>,
    query: Query<PageQuery>,
) -> Response {
    super::list(headers, pool, Scope::Environments(org, project), query).await
}

/// Inspects one active resource for enabled operators with a full session; grants no tenant write authority.
#[utoipa::path(get, operation_id = "admin_get_environment", path = "/v1/admin/orgs/{org_slug}/projects/{project_slug}/envs/{env_slug}",
    params(("org_slug" = String, Path, description = "Resource ancestry"),("project_slug" = String, Path, description = "Resource ancestry"),("env_slug" = String, Path, description = "Resource ancestry")),
    responses((status = 200, body = AdminMetadata),
        (status = 400, description = "Invalid path or cursor"),
        (status = 401, description = "Valid full session required"),
        (status = 403, description = "Enabled platform operator required"),
        (status = 404, description = "Active ancestry or resource not found"),
        (status = 503, description = "Storage unavailable")), tag = "admin-tenants")]
pub(crate) async fn get_environment(
    Path((org, project, environment)): Path<(String, String, String)>,
    headers: HeaderMap,
    State(pool): State<PgPool>,
) -> Response {
    super::detail(
        headers,
        pool,
        Scope::Environments(org, project),
        Selector::Slug(environment),
    )
    .await
}

/// Lists bounded metadata for enabled operators with a full session; grants no tenant write authority.
#[utoipa::path(get, operation_id = "admin_list_applications", path = "/v1/admin/orgs/{org_slug}/projects/{project_slug}/envs/{env_slug}/apps",
    params(("org_slug" = String, Path, description = "Resource ancestry"),("project_slug" = String, Path, description = "Resource ancestry"),("env_slug" = String, Path, description = "Resource ancestry"),("after" = Option<String>, Query, description = "Last item UUID from the previous page")),
    responses((status = 200, body = AdminPage),
        (status = 400, description = "Invalid path or cursor"),
        (status = 401, description = "Valid full session required"),
        (status = 403, description = "Enabled platform operator required"),
        (status = 404, description = "Active ancestry or resource not found"),
        (status = 503, description = "Storage unavailable")), tag = "admin-tenants")]
pub(crate) async fn list_applications(
    Path((org, project, environment)): Path<(String, String, String)>,
    headers: HeaderMap,
    State(pool): State<PgPool>,
    query: Query<PageQuery>,
) -> Response {
    super::list(
        headers,
        pool,
        Scope::Applications(org, project, environment),
        query,
    )
    .await
}

/// Inspects one active resource for enabled operators with a full session; grants no tenant write authority.
#[utoipa::path(get, operation_id = "admin_get_application", path = "/v1/admin/orgs/{org_slug}/projects/{project_slug}/envs/{env_slug}/apps/{app_id}",
    params(("org_slug" = String, Path, description = "Resource ancestry"),("project_slug" = String, Path, description = "Resource ancestry"),("env_slug" = String, Path, description = "Resource ancestry"),("app_id" = String, Path, description = "Resource ancestry")),
    responses((status = 200, body = AdminMetadata),
        (status = 400, description = "Invalid path or cursor"),
        (status = 401, description = "Valid full session required"),
        (status = 403, description = "Enabled platform operator required"),
        (status = 404, description = "Active ancestry or resource not found"),
        (status = 503, description = "Storage unavailable")), tag = "admin-tenants")]
pub(crate) async fn get_application(
    Path((org, project, environment, app)): Path<(String, String, String, Uuid)>,
    headers: HeaderMap,
    State(pool): State<PgPool>,
) -> Response {
    super::detail(
        headers,
        pool,
        Scope::Applications(org, project, environment),
        Selector::Id(app),
    )
    .await
}
