//! Project endpoints scoped to an organization.
//!
//! These handlers validate slugs, enforce org-scoped authorization, and delegate
//! database operations to `storage`.

use axum::{
    Json,
    extract::{Extension, Path},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use sqlx::PgPool;
use tracing::error;

use super::super::auth::principal::require_auth;
use super::{
    PROJECT_SLUG_MAX, PROJECT_SLUG_MIN,
    slug::normalize_slug,
    storage::{fetch_projects, insert_project, resolve_org_context},
    types::{CreateProjectRequest, ProjectResponse},
};

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
/// Creates a project under an organization and returns a `ProjectResponse`.
/// Callers must pass `OrgContext::can_manage`; unauthorized callers receive `404` to avoid leaking existence.
/// The slug is normalized and uniqueness violations are mapped to `409`.
/// The response omits any org membership or role information.
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

    match insert_project(&pool, context.id(), name, &slug).await {
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
/// Lists active (non-deleted) projects for an organization as `ProjectResponse` DTOs.
/// Only active org members can list; non-members receive `404` to avoid tenant leakage.
/// The response returns only project fields, not nested org membership or roles.
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

    match fetch_projects(&pool, context.id()).await {
        Ok(rows) => (StatusCode::OK, Json(rows)).into_response(),
        Err(err) => {
            error!("Failed to list projects: {err}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
