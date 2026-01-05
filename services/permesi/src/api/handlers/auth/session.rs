//! Session endpoints for cookie and bearer auth.

use axum::{
    Json,
    extract::Extension,
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{AUTHORIZATION, InvalidHeaderValue, SET_COOKIE},
    },
    response::IntoResponse,
};
use sqlx::PgPool;
use std::sync::Arc;
use tracing::error;

use super::{
    admin_storage::operator_enabled,
    state::AuthState,
    storage::{SessionRecord, delete_session, lookup_session},
    types::SessionResponse,
    utils::hash_session_token,
};

const SESSION_COOKIE_NAME: &str = "permesi_session";

#[utoipa::path(
    get,
    path = "/v1/auth/session",
    responses(
        (status = 200, description = "Session is active", body = SessionResponse),
        (status = 204, description = "No active session")
    ),
    tag = "auth"
)]
pub async fn session(headers: HeaderMap, pool: Extension<PgPool>) -> impl IntoResponse {
    // Missing cookies are treated as "no session" to avoid leaking auth state.
    let Some(token) = extract_session_token(&headers) else {
        return StatusCode::NO_CONTENT.into_response();
    };
    // Only the hash is stored; never compare raw tokens against the database.
    let token_hash = hash_session_token(&token);
    match lookup_session(&pool, &token_hash).await {
        Ok(Some(SessionRecord {
            user_id,
            email,
            created_at_unix: _,
        })) => {
            let is_operator = operator_enabled(&pool, user_id).await.unwrap_or(false);
            let response = SessionResponse {
                user_id: user_id.to_string(),
                email,
                is_operator,
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Ok(None) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => {
            error!("Failed to lookup session: {err}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Resolve a session cookie into a session record, if present.
///
/// Returns `Ok(None)` when the cookie is missing or invalid.
pub(crate) async fn authenticate_session(
    headers: &HeaderMap,
    pool: &PgPool,
) -> Result<Option<SessionRecord>, StatusCode> {
    let Some(token) = extract_session_token(headers) else {
        return Ok(None);
    };
    let token_hash = hash_session_token(&token);
    match lookup_session(pool, &token_hash).await {
        Ok(record) => Ok(record),
        Err(err) => {
            error!("Failed to lookup session: {err}");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

#[utoipa::path(
    post,
    path = "/v1/auth/logout",
    responses(
        (status = 204, description = "Session cleared")
    ),
    tag = "auth"
)]
pub async fn logout(
    headers: HeaderMap,
    pool: Extension<PgPool>,
    auth_state: Extension<Arc<AuthState>>,
) -> impl IntoResponse {
    if let Some(token) = extract_session_token(&headers) {
        let token_hash = hash_session_token(&token);
        if let Err(err) = delete_session(&pool, &token_hash).await {
            error!("Failed to delete session: {err}");
        }
    }

    // Always clear the cookie, even if the session record was missing.
    let mut response_headers = HeaderMap::new();
    if let Ok(cookie) = clear_session_cookie(auth_state.config()) {
        response_headers.insert(SET_COOKIE, cookie);
    }
    (StatusCode::NO_CONTENT, response_headers).into_response()
}

/// Build a secure `HttpOnly` cookie for the session token.
pub(super) fn session_cookie(
    auth_state: &AuthState,
    token: &str,
) -> Result<HeaderValue, InvalidHeaderValue> {
    let ttl_seconds = auth_state.config().session_ttl_seconds();
    // Only mark cookies secure when the frontend is served over HTTPS.
    let secure = auth_state.config().session_cookie_secure();
    let mut cookie = format!(
        "{SESSION_COOKIE_NAME}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={ttl_seconds}"
    );
    if secure {
        cookie.push_str("; Secure");
    }
    HeaderValue::from_str(&cookie)
}

fn clear_session_cookie(
    auth_config: &super::state::AuthConfig,
) -> Result<HeaderValue, InvalidHeaderValue> {
    let secure = auth_config.session_cookie_secure();
    let mut cookie = format!("{SESSION_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0");
    if secure {
        cookie.push_str("; Secure");
    }
    HeaderValue::from_str(&cookie)
}

fn extract_session_token(headers: &HeaderMap) -> Option<String> {
    if let Some(token) = extract_bearer_token(headers) {
        return Some(token);
    }
    let header = headers.get(axum::http::header::COOKIE)?;
    let value = header.to_str().ok()?;
    for pair in value.split(';') {
        let trimmed = pair.trim();
        let mut parts = trimmed.splitn(2, '=');
        let key = parts.next()?.trim();
        let val = parts.next()?.trim();
        if key == SESSION_COOKIE_NAME {
            return Some(val.to_string());
        }
    }
    None
}

fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?;
    let trimmed = value.trim();
    let token = trimmed
        .strip_prefix("Bearer ")
        .or_else(|| trimmed.strip_prefix("bearer "))?
        .trim();
    if token.is_empty() {
        None
    } else {
        Some(token.to_string())
    }
}
