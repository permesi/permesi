//! Session-scoped capability hints for tenant deletion controls.
//!
//! Flow Overview: authenticate a full session, resolve current active membership,
//! and return role eligibility with the immutable organization ID. No browser flag
//! grants authority; mutation handlers recheck roles and lifecycle state themselves.
//! Responses are never cached and omit raw roles and internal platform permissions.

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header::CACHE_CONTROL},
    response::{IntoResponse, Response},
};
use sqlx::PgPool;

use super::{
    super::auth::principal::require_auth, storage::resolve_org_context, types::OrgCapabilities,
};

#[utoipa::path(
    get,
    path = "/v1/orgs/{org_slug}/capabilities",
    params(("org_slug" = String, Path, description = "Organization slug")),
    responses(
        (status = 200, description = "Current role eligibility; not mutation authorization. Cache-Control: no-store.", body = OrgCapabilities),
        (status = 401, description = "Full authenticated session required."),
        (status = 404, description = "Organization inaccessible or not found."),
        (status = 500, description = "Capability lookup unavailable."),
    ),
    tag = "orgs"
)]
/// Returns only server-derived owner/admin eligibility for an active tenant member.
/// Inaccessible tenants return 404; all outcomes prohibit caching stale authority hints.
pub async fn get_capabilities(
    Path(slug): Path<String>,
    headers: HeaderMap,
    State(pool): State<PgPool>,
) -> Response {
    let mut response = resolve(&headers, &pool, &slug).await;
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// Resolves full-session authority without disclosing SQL values or raw membership roles.
async fn resolve(headers: &HeaderMap, pool: &PgPool, slug: &str) -> Response {
    let principal = match require_auth(headers, pool).await {
        Ok(principal) => principal,
        Err(status) => return status.into_response(),
    };
    match resolve_org_context(pool, principal.user_id, slug).await {
        Ok(Some(context)) => Json(OrgCapabilities {
            organization_id: context.id().to_string(),
            can_manage_resources: context.can_manage(),
            can_delete_organization: context.is_owner(),
        })
        .into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            tracing::error!(sqlstate = ?error.as_database_error().and_then(sqlx::error::DatabaseError::code), "Tenant capabilities lookup failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
