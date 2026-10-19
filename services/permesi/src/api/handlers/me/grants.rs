//! Self-service OAuth saved-consent listing and revocation.
//!
//! Flow Overview: The existing full session identifies the user; the database
//! lists only grants bound to that user and a currently active tenant hierarchy.
//! Revocation updates the exact user's grant, which code redemption and refresh
//! recheck under PostgreSQL locks. Internal principal permissions are never
//! presented as delegated OAuth scopes.

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use utoipa::ToSchema;
use uuid::Uuid;

use super::super::auth::principal::require_auth;
use crate::oauth::grant::{self, GRANT_PAGE_SIZE};

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantListQuery {
    after: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SavedGrantResponse {
    pub id: String,
    pub client_id: String,
    pub client_name: String,
    pub application_name: String,
    pub organization_slug: String,
    pub organization_name: String,
    pub scopes: Vec<String>,
    pub created_at: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SavedGrantPage {
    pub grants: Vec<SavedGrantResponse>,
    pub next_cursor: Option<String>,
}

impl From<grant::SavedGrant> for SavedGrantResponse {
    fn from(value: grant::SavedGrant) -> Self {
        Self {
            id: value.id.to_string(),
            client_id: value.client_id.to_string(),
            client_name: value.client_name,
            application_name: value.application_name,
            organization_slug: value.organization_slug,
            organization_name: value.organization_name,
            scopes: value.scopes,
            created_at: value.created_at.to_rfc3339(),
        }
    }
}

/// Prevents browser and intermediary caches from retaining delegated authority metadata.
fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// Lists the session user's current saved OAuth consent in bounded, cursor-based pages.
#[utoipa::path(
    get,
    path = "/v1/me/oauth/grants",
    params(("after" = Option<String>, Query, description = "Last grant ID from the previous page.")),
    responses(
        (status = 200, description = "Active grants for the authenticated user.", body = SavedGrantPage),
        (status = 400, description = "Invalid cursor."),
        (status = 401, description = "Missing or invalid full session."),
        (status = 503, description = "Grant storage unavailable."),
    ),
    tag = "me"
)]
pub async fn list_grants(
    headers: HeaderMap,
    State(pool): State<PgPool>,
    Query(query): Query<GrantListQuery>,
) -> Response {
    let principal = match require_auth(&headers, &pool).await {
        Ok(principal) => principal,
        Err(status) => return no_store(status.into_response()),
    };
    let after = match query.after {
        Some(value) => match Uuid::parse_str(&value) {
            Ok(value) => Some(value),
            Err(_) => return no_store(StatusCode::BAD_REQUEST.into_response()),
        },
        None => None,
    };
    let response = match grant::list_user_grants(&pool, principal.user_id, after).await {
        Ok(mut grants) => {
            let has_more = grants.len() > GRANT_PAGE_SIZE;
            grants.truncate(GRANT_PAGE_SIZE);
            let next_cursor = if has_more {
                grants.last().map(|grant| grant.id.to_string())
            } else {
                None
            };
            let grants = grants.into_iter().map(SavedGrantResponse::from).collect();
            (
                StatusCode::OK,
                Json(SavedGrantPage {
                    grants,
                    next_cursor,
                }),
            )
                .into_response()
        }
        Err(error) => {
            tracing::error!(?error, "Failed to list saved OAuth grants");
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
    };
    no_store(response)
}

/// Permanently revokes one owned grant; foreign, unknown and repeated IDs all return 404.
#[utoipa::path(
    delete,
    path = "/v1/me/oauth/grants/{grant_id}",
    params(("grant_id" = String, Path, description = "Saved grant ID.")),
    responses(
        (status = 204, description = "Saved consent revoked."),
        (status = 400, description = "Invalid grant ID."),
        (status = 401, description = "Missing or invalid full session."),
        (status = 404, description = "Grant not found for this user."),
        (status = 503, description = "Grant storage unavailable."),
    ),
    tag = "me"
)]
pub async fn revoke_grant(
    Path(grant_id): Path<String>,
    headers: HeaderMap,
    State(pool): State<PgPool>,
) -> Response {
    let principal = match require_auth(&headers, &pool).await {
        Ok(principal) => principal,
        Err(status) => return no_store(status.into_response()),
    };
    let Ok(grant_id) = Uuid::parse_str(&grant_id) else {
        return no_store(StatusCode::BAD_REQUEST.into_response());
    };
    let response = match grant::revoke_user_grant(&pool, principal.user_id, grant_id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            tracing::error!(?error, "Failed to revoke saved OAuth grant");
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
    };
    no_store(response)
}
