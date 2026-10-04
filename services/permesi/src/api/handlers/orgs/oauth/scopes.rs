//! Application OAuth scope registry management.
//!
//! All routes resolve session membership and active ancestry before calling domain services.
//! Mutations require org owner/admin; inaccessible resources return 404 and DTOs exclude secrets.

use super::{
    resolve_application,
    types::{ApplicationPath, CreateScopeRequest, PatchScopeRequest, ScopePath, ScopeResponse},
};
use crate::oauth::service;
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use sqlx::PgPool;

#[utoipa::path(
    post, path = "/v1/orgs/{org_slug}/projects/{project_slug}/envs/{env_slug}/apps/{app_id}/oauth/scopes",
    request_body = CreateScopeRequest,
    params(
        ("org_slug" = String, Path, description = "org slug"),
        ("project_slug" = String, Path, description = "project slug"),
        ("env_slug" = String, Path, description = "env slug"),
        ("app_id" = String, Path, description = "UUID")
    ),
    responses(
        (status = 201, description = "Operation succeeded.", body = ScopeResponse),
        (status = 400, description = "Invalid input or OAuth configuration."),
        (status = 401, description = "Missing or invalid full session."),
        (status = 404, description = "Resource inaccessible or absent."),
        (status = 415, description = "JSON content type required."),
        (status = 422, description = "JSON payload deserialization failed."),
        (status = 409, description = "Configuration already exists."),
        (status = 500, description = "Persistence failure.")
    ), tag = "oauth-scopes"
)]
/// Defines API authority for this application; owner/admin required and protocol names reserved.
pub(crate) async fn create_scope(
    Path(path): Path<ApplicationPath>,
    headers: HeaderMap,
    State(pool): State<PgPool>,
    Json(payload): Json<CreateScopeRequest>,
) -> Response {
    let context = match resolve_application(&pool, &headers, &path, true).await {
        Ok(context) => context,
        Err(status) => return status.into_response(),
    };
    match service::create_scope(&pool, &context, payload.name, payload.description).await {
        Ok(scope) => (StatusCode::CREATED, Json(ScopeResponse::from(scope))).into_response(),
        Err(error) => error.into_response(),
    }
}

#[utoipa::path(
    get, path = "/v1/orgs/{org_slug}/projects/{project_slug}/envs/{env_slug}/apps/{app_id}/oauth/scopes",
    params(
        ("org_slug" = String, Path, description = "org slug"),
        ("project_slug" = String, Path, description = "project slug"),
        ("env_slug" = String, Path, description = "env slug"),
        ("app_id" = String, Path, description = "UUID")
    ),
    responses(
        (status = 200, description = "Operation succeeded.", body = [ScopeResponse]),
        (status = 400, description = "Invalid input or OAuth configuration."),
        (status = 401, description = "Missing or invalid full session."),
        (status = 404, description = "Resource inaccessible or absent."),
        (status = 500, description = "Persistence failure.")
    ), tag = "oauth-scopes"
)]
/// Lists application and read-only protocol scope metadata to active organization members.
pub(crate) async fn list_scopes(
    Path(path): Path<ApplicationPath>,
    headers: HeaderMap,
    State(pool): State<PgPool>,
) -> Response {
    let context = match resolve_application(&pool, &headers, &path, false).await {
        Ok(context) => context,
        Err(status) => return status.into_response(),
    };
    match service::list_scopes(&pool, &context).await {
        Ok(scopes) => Json(
            scopes
                .into_iter()
                .map(ScopeResponse::from)
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(error) => error.into_response(),
    }
}

#[utoipa::path(
    patch, path = "/v1/orgs/{org_slug}/projects/{project_slug}/envs/{env_slug}/apps/{app_id}/oauth/scopes/{scope_id}",
    request_body = PatchScopeRequest,
    params(
        ("org_slug" = String, Path, description = "org slug"),
        ("project_slug" = String, Path, description = "project slug"),
        ("env_slug" = String, Path, description = "env slug"),
        ("app_id" = String, Path, description = "UUID"),
        ("scope_id" = String, Path, description = "UUID")
    ),
    responses(
        (status = 200, description = "Operation succeeded.", body = ScopeResponse),
        (status = 400, description = "Invalid input or OAuth configuration."),
        (status = 401, description = "Missing or invalid full session."),
        (status = 404, description = "Resource inaccessible or absent."),
        (status = 415, description = "JSON content type required."),
        (status = 422, description = "JSON payload deserialization failed."),
        (status = 500, description = "Persistence failure.")
    ), tag = "oauth-scopes"
)]
/// Updates an API scope description for org managers; names and protocol entries are immutable.
pub(crate) async fn patch_scope(
    Path(path): Path<ScopePath>,
    headers: HeaderMap,
    State(pool): State<PgPool>,
    Json(payload): Json<PatchScopeRequest>,
) -> Response {
    let context = match resolve_application(&pool, &headers, &path.application, true).await {
        Ok(context) => context,
        Err(status) => return status.into_response(),
    };
    match service::patch_scope(&pool, &context, path.scope_id, payload.description).await {
        Ok(scope) => Json(ScopeResponse::from(scope)).into_response(),
        Err(error) => error.into_response(),
    }
}

#[utoipa::path(
    delete, path = "/v1/orgs/{org_slug}/projects/{project_slug}/envs/{env_slug}/apps/{app_id}/oauth/scopes/{scope_id}",
    params(
        ("org_slug" = String, Path, description = "org slug"),
        ("project_slug" = String, Path, description = "project slug"),
        ("env_slug" = String, Path, description = "env slug"),
        ("app_id" = String, Path, description = "UUID"),
        ("scope_id" = String, Path, description = "UUID")
    ),
    responses(
        (status = 204, description = "Operation succeeded."),
        (status = 400, description = "Invalid input or OAuth configuration."),
        (status = 401, description = "Missing or invalid full session."),
        (status = 404, description = "Resource inaccessible or absent."),
        (status = 500, description = "Persistence failure.")
    ), tag = "oauth-scopes"
)]
/// Deletes API authority for org managers and removes dependent allow-list/grant edges.
pub(crate) async fn delete_scope(
    Path(path): Path<ScopePath>,
    headers: HeaderMap,
    State(pool): State<PgPool>,
) -> Response {
    let context = match resolve_application(&pool, &headers, &path.application, true).await {
        Ok(context) => context,
        Err(status) => return status.into_response(),
    };
    match service::delete_scope(&pool, &context, path.scope_id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => error.into_response(),
    }
}
