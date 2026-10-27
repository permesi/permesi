//! Read-only platform inspection, separate from membership-authorized tenant management.
//!
//! Flow Overview: validate a full session and current operator designation, resolve
//! active ancestry, then return one metadata record or a bounded page. No membership
//! is created and no tenant write authority is granted. UI elevation remains a
//! presentation gate; these reads follow the global user-data session boundary.
//! All responses prohibit caching, including extraction and method errors.

mod routes;
mod storage;

pub(crate) use routes::*;

use axum::{
    Json,
    extract::Query,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use utoipa::ToSchema;
use uuid::Uuid;

use super::super::auth::principal::{Permission, require_auth};
use storage::{Scope, Selector};

/// A fixed protocol bound, matching the existing saved-consent pagination model.
const PAGE_SIZE: usize = 50;

/// Public resource metadata only; roles, credentials and OAuth configuration are absent.
#[derive(Debug, Serialize, ToSchema)]
pub struct AdminMetadata {
    id: String,
    name: String,
    created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    slug: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tier: Option<String>,
}

/// A bounded collection with an opaque ordering reference, never an authority token.
#[derive(Debug, Serialize, ToSchema)]
pub struct AdminPage {
    items: Vec<AdminMetadata>,
    next_cursor: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageQuery {
    after: Option<Uuid>,
}

/// Applies privacy policy even when Axum rejects a path, query or unsupported method.
pub(crate) async fn prevent_cache(uri: axum::http::Uri, mut response: Response) -> Response {
    if uri.path() != "/v1/admin/orgs" && !uri.path().starts_with("/v1/admin/orgs/") {
        return response;
    }
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// Authorizes inspection only from a current full session and database-derived operator scope.
async fn authorize(headers: &HeaderMap, pool: &PgPool) -> Result<(), StatusCode> {
    let principal = require_auth(headers, pool).await?;
    if !principal.allows(Permission::InspectTenants) {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(())
}

/// Returns a bounded page after authorization and exact active-parent/cursor validation.
async fn list(
    headers: HeaderMap,
    pool: PgPool,
    scope: Scope,
    Query(query): Query<PageQuery>,
) -> Response {
    async {
        authorize(&headers, &pool).await?;
        storage::require_parent(&pool, &scope).await?;
        let cursor = match query.after {
            Some(id) => Some(
                storage::find(&pool, &scope, &Selector::Id(id))
                    .await?
                    .ok_or(StatusCode::BAD_REQUEST)?,
            ),
            None => None,
        };
        let mut records = storage::page(&pool, &scope, cursor).await?;
        let has_more = records.len() > PAGE_SIZE;
        records.truncate(PAGE_SIZE);
        let next_cursor = if has_more {
            records.last().map(|row| row.id.to_string())
        } else {
            None
        };
        Ok::<_, StatusCode>(Json(AdminPage {
            items: records.into_iter().map(storage::Record::metadata).collect(),
            next_cursor,
        }))
    }
    .await
    .into_response()
}

/// Reads one record through the complete active ancestry without changing tenant authority.
async fn detail(headers: HeaderMap, pool: PgPool, scope: Scope, selector: Selector) -> Response {
    async {
        authorize(&headers, &pool).await?;
        let record = storage::find(&pool, &scope, &selector)
            .await?
            .ok_or(StatusCode::NOT_FOUND)?;
        Ok::<_, StatusCode>(Json(record.metadata()))
    }
    .await
    .into_response()
}
