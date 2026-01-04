//! Authenticated principal extraction and authorization helpers.
//!
//! Flow Overview: read the session cookie, resolve it to a user, and return a
//! principal that downstream handlers can use. Org-scoped roles are resolved
//! per organization in those handlers, not globally here.

use axum::http::{HeaderMap, StatusCode};
use sqlx::PgPool;

use super::session::authenticate_session;

/// Authenticated user context derived from the session cookie.
#[derive(Clone, Debug)]
pub struct Principal {
    pub user_id: uuid::Uuid,
    pub email: String,
    pub scopes: Vec<String>,
}

/// Resolve a session cookie into a principal, or return 401 for missing sessions.
pub async fn require_auth(headers: &HeaderMap, pool: &PgPool) -> Result<Principal, StatusCode> {
    match authenticate_session(headers, pool).await {
        Ok(Some(record)) => Ok(Principal {
            scopes: Vec::new(),
            user_id: record.user_id,
            email: record.email,
        }),
        Ok(None) => Err(StatusCode::UNAUTHORIZED),
        Err(status) => Err(status),
    }
}
