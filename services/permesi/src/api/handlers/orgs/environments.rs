//! Environment endpoints scoped to an org project.
//!
//! The API enforces a single production environment per project and blocks
//! non-production environments until a production environment exists. This file
//! wires the HTTP flow and leaves database logic to `storage`.

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
    ENV_SLUG_MAX, ENV_SLUG_MIN,
    slug::normalize_slug,
    storage::{fetch_environments, insert_environment, resolve_org_context, resolve_project},
    types::{CreateEnvironmentRequest, EnvironmentResponse},
};

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
/// Creates an environment within a project and returns an `EnvironmentResponse`.
/// Requires `OrgContext::can_manage`; unauthorized callers receive `404` to avoid leaking existence.
/// `storage::insert_environment` enforces a single `production` tier and gates `non_production`.
/// The response includes only environment DTO fields.
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

    let project = match resolve_project(&pool, context.id(), &project_slug).await {
        Ok(Some(project)) => project,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(err) => {
            error!("Failed to resolve project for environment: {err}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    match insert_environment(&pool, project.id(), name, &slug, payload.tier).await {
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
/// Lists active (non-deleted) environments for a project as `EnvironmentResponse` DTOs.
/// Requires org membership and hides project existence from non-members via `404`.
/// The response returns only environment fields, not project/org membership details.
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

    let project = match resolve_project(&pool, context.id(), &project_slug).await {
        Ok(Some(project)) => project,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(err) => {
            error!("Failed to resolve project for env list: {err}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    match fetch_environments(&pool, project.id()).await {
        Ok(rows) => (StatusCode::OK, Json(rows)).into_response(),
        Err(err) => {
            error!("Failed to list environments: {err}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
