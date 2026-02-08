//! Authenticated principal extraction and authorization helpers.
//!
//! This module provides functions to extract and verify the user principal
//! from session cookies, supporting different session kinds
//! (full, bootstrap, challenge).

use axum::http::{HeaderMap, StatusCode};
use sqlx::PgPool;

use super::{session::authenticate_session, session_kind::SessionKind};

/// Authenticated user context derived from the session cookie.
#[derive(Clone, Debug)]
pub struct Principal {
    pub user_id: uuid::Uuid,
    pub email: String,
    pub scopes: Vec<String>,
    pub session_issued_at_unix: i64,
    pub session_auth_time_unix: Option<i64>,
}

/// Logical permissions available in the platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permission {
    /// Ability to update user profiles.
    Write,
    /// Ability to delete users.
    Delete,
    /// Ability to assign roles to users.
    AssignRole,
}

impl Principal {
    /// Returns `true` if the principal holds the requested permission.
    ///
    /// Authorization is deny-by-default. Only server-issued scopes are trusted.
    #[must_use]
    pub fn allows(&self, permission: Permission) -> bool {
        let has = |scope: &str| self.scopes.iter().any(|value| value == scope);
        has("platform:admin")
            || match permission {
                Permission::Write => has("users:write"),
                Permission::Delete => has("users:delete"),
                Permission::AssignRole => has("users:assign-role"),
            }
    }
}

/// Resolve a session cookie into a principal, or return 401 for missing sessions.
pub async fn require_auth(headers: &HeaderMap, pool: &PgPool) -> Result<Principal, StatusCode> {
    match authenticate_session(headers, pool).await {
        Ok(Some(record)) => {
            if record.kind != SessionKind::Full {
                return Err(StatusCode::UNAUTHORIZED);
            }
            Ok(Principal {
                scopes: Vec::new(),
                user_id: record.user_id,
                email: record.email,
                session_issued_at_unix: record.created_at_unix,
                session_auth_time_unix: record.auth_time_unix,
            })
        }
        Ok(None) => Err(StatusCode::UNAUTHORIZED),
        Err(status) => Err(status),
    }
}

/// Require either a full session or an MFA bootstrap session.
pub async fn require_any_auth(headers: &HeaderMap, pool: &PgPool) -> Result<Principal, StatusCode> {
    match authenticate_session(headers, pool).await {
        Ok(Some(record)) => {
            if record.kind != SessionKind::Full && record.kind != SessionKind::MfaBootstrap {
                return Err(StatusCode::UNAUTHORIZED);
            }
            Ok(Principal {
                scopes: Vec::new(),
                user_id: record.user_id,
                email: record.email,
                session_issued_at_unix: record.created_at_unix,
                session_auth_time_unix: record.auth_time_unix,
            })
        }
        Ok(None) => Err(StatusCode::UNAUTHORIZED),
        Err(status) => Err(status),
    }
}

/// Require an MFA challenge session to complete recovery or factor verification.
///
/// Only sessions tagged as `mfa_challenge` are accepted.
pub async fn require_mfa_challenge(
    headers: &HeaderMap,
    pool: &PgPool,
) -> Result<Principal, StatusCode> {
    match authenticate_session(headers, pool).await {
        Ok(Some(record)) => {
            if record.kind != SessionKind::MfaChallenge {
                return Err(StatusCode::UNAUTHORIZED);
            }
            Ok(Principal {
                scopes: Vec::new(),
                user_id: record.user_id,
                email: record.email,
                session_issued_at_unix: record.created_at_unix,
                session_auth_time_unix: record.auth_time_unix,
            })
        }
        Ok(None) => Err(StatusCode::UNAUTHORIZED),
        Err(status) => Err(status),
    }
}
