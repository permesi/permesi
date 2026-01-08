//! Organization CRUD handlers.
//!
//! This module implements org-level endpoints and delegates database access to
//! the shared `storage` module. It intentionally returns `404` for unauthorized
//! access to avoid leaking tenant existence.

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
    ORG_SLUG_MAX, ORG_SLUG_MIN,
    slug::normalize_slug,
    storage::{create_org_with_roles, fetch_orgs_for_user, resolve_org_context, update_org_record},
    types::{CreateOrgRequest, OrgResponse, UpdateOrgRequest},
};

#[utoipa::path(
    post,
    path = "/v1/orgs",
    request_body = CreateOrgRequest,
    responses(
        (status = 201, description = "Organization created.", body = OrgResponse),
        (status = 400, description = "Invalid input.", body = String),
        (status = 401, description = "Missing or invalid session cookie."),
        (status = 409, description = "Organization with this name already exists for this user.", body = String),
    ),
    tag = "orgs"
)]
/// Creates a new organization for the authenticated user and returns an `OrgResponse`.
/// On success, the creator is enrolled as an active member and granted the `owner` role.
/// The slug is normalized and collision-resolved on insert; creator name conflicts return `409`.
/// The response intentionally omits membership state and roles.
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
/// Lists organizations the authenticated user is an active member of.
/// Soft-deleted orgs are excluded, and membership scoping avoids leaking org existence across tenants.
/// The response uses only public `OrgResponse` fields.
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
/// Fetches organization details by slug for the authenticated caller.
/// Returns `404` for non-members or inactive memberships to reduce cross-tenant enumeration.
/// Converts `OrgContext` to `OrgResponse`, excluding roles and membership status.
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
/// Updates an organization's name and/or slug and returns the updated `OrgResponse`.
/// Requires `OrgContext::can_manage`; otherwise it returns `404` to avoid leaking org existence.
/// The slug is normalized and uniqueness conflicts map to `409`, and roles are never returned.
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
