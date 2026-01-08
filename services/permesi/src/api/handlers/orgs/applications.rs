//! Application endpoints scoped to an environment.
//!
//! Applications are created and listed within an environment under a project
//! within an organization. Authorization and existence checks happen via the
//! shared `storage` queries.

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
    storage::{
        fetch_applications, insert_application, resolve_environment, resolve_org_context,
        resolve_project,
    },
    types::{ApplicationResponse, CreateApplicationRequest},
};

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
/// Creates an application within an environment and returns an `ApplicationResponse`.
/// Requires `OrgContext::can_manage` and returns `404` when the org/project/env is inaccessible.
/// The response includes only app fields, not environment or membership details.
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

    let project = match resolve_project(&pool, context.id(), &project_slug).await {
        Ok(Some(project)) => project,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(err) => {
            error!("Failed to resolve project for application: {err}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let env = match resolve_environment(&pool, project.id(), &env_slug).await {
        Ok(Some(env)) => env,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(err) => {
            error!("Failed to resolve environment for application: {err}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    match insert_application(&pool, env.id(), name).await {
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
/// Lists active (non-deleted) applications for an environment as `ApplicationResponse` DTOs.
/// Returns `404` when the org/project/env cannot be resolved for the current principal.
/// The response returns only app fields, not environment or org membership data.
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

    let project = match resolve_project(&pool, context.id(), &project_slug).await {
        Ok(Some(project)) => project,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(err) => {
            error!("Failed to resolve project for apps list: {err}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let env = match resolve_environment(&pool, project.id(), &env_slug).await {
        Ok(Some(env)) => env,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(err) => {
            error!("Failed to resolve environment for apps list: {err}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    match fetch_applications(&pool, env.id()).await {
        Ok(rows) => (StatusCode::OK, Json(rows)).into_response(),
        Err(err) => {
            error!("Failed to list applications: {err}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
