//! Self-service handlers for the authenticated user.
//!
//! This module provides endpoints for users to manage their own profile,
//! view active sessions, and configure multi-factor authentication (MFA).

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use std::sync::Arc;
use tracing::error;
use utoipa::ToSchema;
use uuid::Uuid;

use super::auth::{
    AuthState,
    authority_guard::{AuthorityGuard, Policy},
    mfa::{self, MfaState},
    principal::require_auth,
};

const RECOVERY_RECENT_AUTH_SECONDS: i64 = 10 * 60;

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct MeResponse {
    pub id: String,
    pub email: String,
    pub display_name: Option<String>,
    pub locale: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub roles: Vec<String>,
    pub scopes: Vec<String>,
    pub mfa_enabled: bool,
    pub totp_enabled: bool,
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

#[derive(Debug, Serialize, ToSchema)]
pub struct RecoveryCodesResponse {
    pub codes: Vec<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SecurityKeySummary {
    pub credential_id: String,
    pub label: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
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
pub async fn get_me(headers: HeaderMap, pool: State<PgPool>) -> impl IntoResponse {
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
                mfa_enabled: profile.mfa_enabled,
                totp_enabled: profile.totp_enabled,
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
    pool: State<PgPool>,
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
                mfa_enabled: profile.mfa_enabled,
                totp_enabled: profile.totp_enabled,
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
pub async fn list_sessions(headers: HeaderMap, pool: State<PgPool>) -> impl IntoResponse {
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
    get,
    path = "/v1/me/mfa/security-keys",
    responses(
        (status = 200, description = "List of registered security keys.", body = [SecurityKeySummary]),
        (status = 401, description = "Unauthorized")
    ),
    tag = "me"
)]
pub async fn list_security_keys(headers: HeaderMap, pool: State<PgPool>) -> impl IntoResponse {
    let principal = match require_auth(&headers, &pool).await {
        Ok(principal) => principal,
        Err(status) => return status.into_response(),
    };

    match crate::webauthn::SecurityKeyRepo::list_user_keys(&pool, principal.user_id).await {
        Ok(keys) => {
            let summaries: Vec<SecurityKeySummary> = keys
                .into_iter()
                .map(|k| SecurityKeySummary {
                    credential_id: hex::encode(k.credential_id),
                    label: k.label,
                    created_at: k.created_at.to_rfc3339(),
                    last_used_at: k.last_used_at.map(|t| t.to_rfc3339()),
                })
                .collect();
            (StatusCode::OK, Json(summaries)).into_response()
        }
        Err(err) => {
            error!("Failed to list security keys: {err}");
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
        (status = 400, description = "Invalid session id."),
        (status = 401, description = "Missing or invalid session cookie."),
        (status = 404, description = "Session not found."),
    ),
    tag = "me"
)]
pub async fn revoke_session(
    Path(sid): Path<String>,
    headers: HeaderMap,
    pool: State<PgPool>,
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

/// Replaces recovery authority only after locking the exact current, recently authenticated session.
/// Code and batch writes commit together; dependency failures disclose no new recovery codes.
#[utoipa::path(
    post,
    path = "/v1/me/mfa/recovery-codes",
    responses(
        (status = 200, description = "Recovery codes regenerated.", body = RecoveryCodesResponse),
        (status = 503, description = "Authentication storage unavailable."),
        (status = 401, description = "Missing or invalid session cookie."),
        (status = 409, description = "MFA not enabled.")
    ),
    tag = "me"
)]
pub async fn regenerate_recovery_codes(
    headers: HeaderMap,
    pool: State<PgPool>,
    auth_state: State<Arc<AuthState>>,
) -> impl IntoResponse {
    let principal = match require_auth(&headers, &pool).await {
        Ok(principal) => principal,
        Err(status) => return status.into_response(),
    };

    if !recent_auth_ok(&principal) {
        return (
            StatusCode::UNAUTHORIZED,
            "Recent authentication required.".to_string(),
        )
            .into_response();
    }

    let Some(pepper) = auth_state.mfa().recovery_pepper() else {
        error!("MFA recovery codes requested without pepper configured");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "Recovery unavailable.".to_string(),
        )
            .into_response();
    };

    let mut guard = match AuthorityGuard::acquire(
        &pool,
        &headers,
        principal.user_id,
        Policy::Full,
        auth_state.config().opaque_exchange_timeout_ms(),
    )
    .await
    {
        Ok(guard) => guard,
        Err(status) => return status.into_response(),
    };
    if let Err(status) = guard
        .require_recent_auth(RECOVERY_RECENT_AUTH_SECONDS)
        .await
    {
        return status.into_response();
    }
    let state = match mfa::storage::load_mfa_state(guard.connection(), principal.user_id).await {
        Ok(state) => state,
        Err(err) => {
            error!("Failed to load MFA state: {err}");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };

    let Some(state) = state else {
        return (StatusCode::CONFLICT, "MFA not enabled.".to_string()).into_response();
    };
    if state.state != MfaState::Enabled {
        return (StatusCode::CONFLICT, "MFA not enabled.".to_string()).into_response();
    }

    let batch = match mfa::recovery::RecoveryCodeBatch::generate(pepper) {
        Ok(batch) => batch,
        Err(err) => {
            error!("Failed to generate recovery codes: {err}");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };

    if let Err(err) = mfa::storage::insert_recovery_codes_on(
        guard.connection(),
        principal.user_id,
        batch.batch_id,
        &batch.code_hashes,
    )
    .await
    {
        error!("Failed to insert recovery codes: {err}");
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }

    if let Err(err) = mfa::storage::upsert_mfa_state(
        guard.connection(),
        principal.user_id,
        MfaState::Enabled,
        Some(batch.batch_id),
    )
    .await
    {
        error!("Failed to update recovery batch id: {err}");
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }

    if guard.commit().await.is_err() {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    (
        StatusCode::OK,
        Json(RecoveryCodesResponse { codes: batch.codes }),
    )
        .into_response()
}

/// Removes TOTP under current identity/session locks and a fresh database recency check.
/// Storage failures roll back factor and MFA-state changes and return generic 503.
#[utoipa::path(
    delete,
    path = "/v1/me/mfa/totp",
    responses(
        (status = 204, description = "TOTP disabled."),
        (status = 503, description = "Authentication storage unavailable."),
        (status = 401, description = "Unauthorized or recent auth required."),
    ),
    tag = "me"
)]
pub async fn disable_totp(
    headers: HeaderMap,
    pool: State<PgPool>,
    auth_state: State<Arc<AuthState>>,
) -> impl IntoResponse {
    let principal = match require_auth(&headers, &pool).await {
        Ok(principal) => principal,
        Err(status) => return status.into_response(),
    };

    if !recent_auth_ok(&principal) {
        return (
            StatusCode::UNAUTHORIZED,
            "Recent authentication required.".to_string(),
        )
            .into_response();
    }

    let mut guard = match AuthorityGuard::acquire(
        &pool,
        &headers,
        principal.user_id,
        Policy::Full,
        auth_state.config().opaque_exchange_timeout_ms(),
    )
    .await
    {
        Ok(guard) => guard,
        Err(status) => return status.into_response(),
    };
    if let Err(status) = guard
        .require_recent_auth(RECOVERY_RECENT_AUTH_SECONDS)
        .await
    {
        return status.into_response();
    }
    if sqlx::query("DELETE FROM totp_credentials WHERE user_id=$1")
        .bind(principal.user_id)
        .execute(guard.connection())
        .await
        .is_err()
    {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let remaining = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM security_keys WHERE user_id=$1)",
    )
    .bind(principal.user_id)
    .fetch_one(guard.connection())
    .await;
    let state = match remaining {
        Ok(true) => MfaState::Enabled,
        Ok(false) => MfaState::Disabled,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    if mfa::storage::upsert_mfa_state(guard.connection(), principal.user_id, state, None)
        .await
        .is_err()
        || guard.commit().await.is_err()
    {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    StatusCode::NO_CONTENT.into_response()
}

struct MeProfileRow {
    id: String,
    display_name: Option<String>,
    locale: Option<String>,
    created_at: String,
    updated_at: String,
    mfa_enabled: bool,
    totp_enabled: bool,
}

async fn fetch_profile(pool: &PgPool, user_id: Uuid) -> Result<Option<MeProfileRow>, sqlx::Error> {
    let query = r#"
        SELECT
            users.id::text AS id,
            users.display_name,
            users.locale,
            to_char(users.created_at AT TIME ZONE 'utc', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS created_at,
            to_char(users.updated_at AT TIME ZONE 'utc', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS updated_at,
            COALESCE(user_mfa_state.state = 'enabled', FALSE) AS mfa_enabled,
            (user_mfa_state.recovery_batch_id IS NOT NULL) AS totp_enabled
        FROM users
        LEFT JOIN user_mfa_state ON user_mfa_state.user_id = users.id
        WHERE users.id = $1
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
        mfa_enabled: row.get("mfa_enabled"),
        totp_enabled: row.get("totp_enabled"),
    }))
}

async fn update_profile(
    pool: &PgPool,
    user_id: Uuid,
    display_name: Option<String>,
    locale: Option<String>,
) -> Result<Option<MeProfileRow>, sqlx::Error> {
    let query = r#"
        WITH updated AS (
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
        )
        SELECT
            updated.*,
            COALESCE(user_mfa_state.state = 'enabled', FALSE) AS mfa_enabled,
            (user_mfa_state.recovery_batch_id IS NOT NULL) AS totp_enabled
        FROM updated
        LEFT JOIN user_mfa_state ON user_mfa_state.user_id = (updated.id)::uuid
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
        mfa_enabled: row.get("mfa_enabled"),
        totp_enabled: row.get("totp_enabled"),
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

/// Requires the existing recent-authentication window for high-risk session operations.
/// Uses server-stored authentication time, falling back to session creation for legacy sessions.
pub(super) fn recent_auth_ok(principal: &super::auth::principal::Principal) -> bool {
    let now = unix_now();
    let auth_time = principal
        .session_auth_time_unix
        .unwrap_or(principal.session_issued_at_unix);
    now.saturating_sub(auth_time) <= RECOVERY_RECENT_AUTH_SECONDS
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| i64::try_from(duration.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or_default()
}
