//! Authenticated self-service endpoints.
//!
//! Flow Overview:
//! 1) Authenticate via session cookie.
//! 2) Resolve the current user from the database.
//! 3) Apply allow-listed updates and session management.

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

#[derive(Debug, Serialize, ToSchema)]
pub struct MeResponse {
    pub id: String,
    pub email: String,
    pub display_name: Option<String>,
    pub locale: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub roles: Vec<String>,
    pub scopes: Vec<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct MeUpdateRequest {
    pub display_name: Option<String>,
    pub locale: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SessionSummary {
    pub id: String,
    pub created_at: String,
    pub last_seen_at: Option<String>,
    pub expires_at: String,
}

#[utoipa::path(
    get,
    path = "/v1/me",
    responses(
        (status = 200, description = "Return the authenticated user profile.", body = MeResponse),
        (status = 401, description = "Missing or invalid session cookie."),
    ),
    tag = "me"
)]
pub async fn get_me(headers: HeaderMap, pool: Extension<PgPool>) -> impl IntoResponse {
    let principal = match require_auth(&headers, &pool).await {
        Ok(principal) => principal,
        Err(status) => return status.into_response(),
    };

    match fetch_profile(&pool, principal.user_id).await {
        Ok(Some(profile)) => {
            let response = MeResponse {
                id: profile.id,
                email: principal.email,
                display_name: profile.display_name,
                locale: profile.locale,
                created_at: profile.created_at,
                updated_at: profile.updated_at,
                roles: Vec::new(),
                scopes: principal.scopes,
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(err) => {
            error!("Failed to fetch /me profile: {err}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[utoipa::path(
    patch,
    path = "/v1/me",
    request_body = MeUpdateRequest,
    responses(
        (status = 200, description = "Profile updated.", body = MeResponse),
        (status = 400, description = "Invalid update payload."),
        (status = 401, description = "Missing or invalid session cookie."),
    ),
    tag = "me"
)]
pub async fn patch_me(
    headers: HeaderMap,
    pool: Extension<PgPool>,
    Json(payload): Json<MeUpdateRequest>,
) -> impl IntoResponse {
    let principal = match require_auth(&headers, &pool).await {
        Ok(principal) => principal,
        Err(status) => return status.into_response(),
    };

    let display_name = normalize_optional(payload.display_name);
    let locale = normalize_optional(payload.locale);

    if display_name.is_none() && locale.is_none() {
        return (StatusCode::BAD_REQUEST, "No updates provided.").into_response();
    }

    match update_profile(&pool, principal.user_id, display_name, locale).await {
        Ok(Some(profile)) => {
            let response = MeResponse {
                id: profile.id,
                email: principal.email,
                display_name: profile.display_name,
                locale: profile.locale,
                created_at: profile.created_at,
                updated_at: profile.updated_at,
                roles: Vec::new(),
                scopes: principal.scopes,
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(err) => {
            error!("Failed to update /me profile: {err}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[utoipa::path(
    get,
    path = "/v1/me/sessions",
    responses(
        (status = 200, description = "Active sessions for the authenticated user.", body = [SessionSummary]),
        (status = 401, description = "Missing or invalid session cookie."),
    ),
    tag = "me"
)]
pub async fn list_sessions(headers: HeaderMap, pool: Extension<PgPool>) -> impl IntoResponse {
    let principal = match require_auth(&headers, &pool).await {
        Ok(principal) => principal,
        Err(status) => return status.into_response(),
    };

    match fetch_sessions(&pool, principal.user_id).await {
        Ok(rows) => (StatusCode::OK, Json(rows)).into_response(),
        Err(err) => {
            error!("Failed to list sessions: {err}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[utoipa::path(
    delete,
    path = "/v1/me/sessions/{sid}",
    params(("sid" = String, Path, description = "Session id")),
    responses(
        (status = 204, description = "Session revoked."),
        (status = 401, description = "Missing or invalid session cookie."),
        (status = 404, description = "Session not found."),
    ),
    tag = "me"
)]
pub async fn revoke_session(
    Path(sid): Path<String>,
    headers: HeaderMap,
    pool: Extension<PgPool>,
) -> impl IntoResponse {
    let principal = match require_auth(&headers, &pool).await {
        Ok(principal) => principal,
        Err(status) => return status.into_response(),
    };

    let Ok(session_id) = Uuid::parse_str(sid.trim()) else {
        return StatusCode::BAD_REQUEST.into_response();
    };

    match delete_session(&pool, principal.user_id, session_id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(err) => {
            error!("Failed to revoke session: {err}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

struct MeProfileRow {
    id: String,
    display_name: Option<String>,
    locale: Option<String>,
    created_at: String,
    updated_at: String,
}

async fn fetch_profile(pool: &PgPool, user_id: Uuid) -> Result<Option<MeProfileRow>, sqlx::Error> {
    let query = r#"
        SELECT
            id::text AS id,
            display_name,
            locale,
            to_char(created_at AT TIME ZONE 'utc', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS created_at,
            to_char(updated_at AT TIME ZONE 'utc', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS updated_at
        FROM users
        WHERE id = $1
        LIMIT 1
    "#;
    let row = sqlx::query(query)
        .bind(user_id)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|row| MeProfileRow {
        id: row.get("id"),
        display_name: row.get("display_name"),
        locale: row.get("locale"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    }))
}

async fn update_profile(
    pool: &PgPool,
    user_id: Uuid,
    display_name: Option<String>,
    locale: Option<String>,
) -> Result<Option<MeProfileRow>, sqlx::Error> {
    let query = r#"
        UPDATE users
        SET
            display_name = COALESCE($1, display_name),
            locale = COALESCE($2, locale)
        WHERE id = $3
        RETURNING
            id::text AS id,
            display_name,
            locale,
            to_char(created_at AT TIME ZONE 'utc', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS created_at,
            to_char(updated_at AT TIME ZONE 'utc', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS updated_at
    "#;
    let row = sqlx::query(query)
        .bind(display_name)
        .bind(locale)
        .bind(user_id)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|row| MeProfileRow {
        id: row.get("id"),
        display_name: row.get("display_name"),
        locale: row.get("locale"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    }))
}

async fn fetch_sessions(pool: &PgPool, user_id: Uuid) -> Result<Vec<SessionSummary>, sqlx::Error> {
    let query = r#"
        SELECT
            id::text AS id,
            to_char(created_at AT TIME ZONE 'utc', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS created_at,
            CASE
                WHEN last_seen_at IS NULL THEN NULL
                ELSE to_char(last_seen_at AT TIME ZONE 'utc', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
            END AS last_seen_at,
            to_char(expires_at AT TIME ZONE 'utc', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS expires_at
        FROM user_sessions
        WHERE user_id = $1 AND expires_at > NOW()
        ORDER BY created_at DESC
    "#;
    let rows = sqlx::query(query).bind(user_id).fetch_all(pool).await?;
    Ok(rows
        .into_iter()
        .map(|row| SessionSummary {
            id: row.get("id"),
            created_at: row.get("created_at"),
            last_seen_at: row.get("last_seen_at"),
            expires_at: row.get("expires_at"),
        })
        .collect())
}

async fn delete_session(
    pool: &PgPool,
    user_id: Uuid,
    session_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let query = "DELETE FROM user_sessions WHERE id = $1 AND user_id = $2";
    let result = sqlx::query(query)
        .bind(session_id)
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

fn normalize_optional(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}
