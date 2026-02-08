//! Authenticated principal extraction and authorization helpers.
//!
//! This module provides functions to extract and verify the user principal
//! from session cookies, supporting different session kinds
//! (full, bootstrap, challenge).
//!
//! Flow Overview:
//! 1) Resolve and validate the session cookie.
//! 2) Load server-side authorization context (`platform_operators`, `user_roles`).
//! 3) Build a deny-by-default principal used by handlers for permission decisions.
//!
//! Security boundary:
//! - Role and scope decisions are derived only from server-side database state.
//!   Client input is never trusted for authorization.

use axum::http::{HeaderMap, StatusCode};
use sqlx::{PgPool, Row};
use tracing::error;
use uuid::Uuid;

use super::{session::authenticate_session, session_kind::SessionKind};

const SCOPE_PLATFORM_ADMIN: &str = "platform:admin";
const SCOPE_USERS_WRITE: &str = "users:write";
const SCOPE_USERS_DELETE: &str = "users:delete";
const SCOPE_USERS_ASSIGN_ROLE: &str = "users:assign-role";

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
    /// Ability to list and inspect users in global user-management endpoints.
    Read,
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
        has(SCOPE_PLATFORM_ADMIN)
            || match permission {
                Permission::Read => {
                    has(SCOPE_USERS_WRITE)
                        || has(SCOPE_USERS_DELETE)
                        || has(SCOPE_USERS_ASSIGN_ROLE)
                }
                Permission::Write => has(SCOPE_USERS_WRITE),
                Permission::Delete => has(SCOPE_USERS_DELETE),
                Permission::AssignRole => has(SCOPE_USERS_ASSIGN_ROLE),
            }
    }
}

/// Build server-issued scopes for a user from trusted role/operator records.
///
/// This function never reads client-provided claims. Unknown roles map to no scopes.
async fn resolve_scopes(pool: &PgPool, user_id: Uuid) -> Result<Vec<String>, sqlx::Error> {
    let row = sqlx::query(
        r"
        SELECT
            EXISTS (
                SELECT 1
                FROM platform_operators
                WHERE user_id = $1 AND enabled = TRUE
            ) AS is_operator,
            (
                SELECT role
                FROM user_roles
                WHERE user_id = $1
                LIMIT 1
            ) AS role
        ",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    let mut scopes = Vec::new();
    if row.get::<bool, _>("is_operator") {
        add_scope(&mut scopes, SCOPE_PLATFORM_ADMIN);
    }

    let role = row.get::<Option<String>, _>("role");
    match role.as_deref() {
        Some("owner" | "admin") => {
            add_scope(&mut scopes, SCOPE_USERS_WRITE);
            add_scope(&mut scopes, SCOPE_USERS_DELETE);
            add_scope(&mut scopes, SCOPE_USERS_ASSIGN_ROLE);
        }
        Some("editor") => {
            add_scope(&mut scopes, SCOPE_USERS_WRITE);
        }
        _ => {}
    }

    Ok(scopes)
}

fn add_scope(scopes: &mut Vec<String>, scope: &str) {
    if !scopes.iter().any(|existing| existing == scope) {
        scopes.push(scope.to_string());
    }
}

/// Resolve a session cookie into a principal, or return 401 for missing sessions.
pub async fn require_auth(headers: &HeaderMap, pool: &PgPool) -> Result<Principal, StatusCode> {
    match authenticate_session(headers, pool).await {
        Ok(Some(record)) => {
            if record.kind != SessionKind::Full {
                return Err(StatusCode::UNAUTHORIZED);
            }
            let scopes = resolve_scopes(pool, record.user_id).await.map_err(|err| {
                error!("Failed to resolve principal scopes: {err}");
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
            Ok(Principal {
                scopes,
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
            let scopes = resolve_scopes(pool, record.user_id).await.map_err(|err| {
                error!("Failed to resolve principal scopes: {err}");
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
            Ok(Principal {
                scopes,
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
            let scopes = resolve_scopes(pool, record.user_id).await.map_err(|err| {
                error!("Failed to resolve principal scopes: {err}");
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
            Ok(Principal {
                scopes,
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

#[cfg(test)]
mod tests {
    use super::{
        Permission, Principal, SCOPE_PLATFORM_ADMIN, SCOPE_USERS_ASSIGN_ROLE, SCOPE_USERS_DELETE,
        SCOPE_USERS_WRITE,
    };
    use uuid::Uuid;

    fn principal_with_scopes(scopes: &[&str]) -> Principal {
        Principal {
            user_id: Uuid::new_v4(),
            email: "member@example.com".to_string(),
            scopes: scopes.iter().map(|scope| (*scope).to_string()).collect(),
            session_issued_at_unix: 0,
            session_auth_time_unix: None,
        }
    }

    #[test]
    fn allows_read_for_write_scope() {
        let principal = principal_with_scopes(&[SCOPE_USERS_WRITE]);
        assert!(principal.allows(Permission::Read));
    }

    #[test]
    fn allows_read_for_delete_scope() {
        let principal = principal_with_scopes(&[SCOPE_USERS_DELETE]);
        assert!(principal.allows(Permission::Read));
    }

    #[test]
    fn allows_read_for_assign_scope() {
        let principal = principal_with_scopes(&[SCOPE_USERS_ASSIGN_ROLE]);
        assert!(principal.allows(Permission::Read));
    }

    #[test]
    fn denies_read_without_user_management_scope() {
        let principal = principal_with_scopes(&[]);
        assert!(!principal.allows(Permission::Read));
    }

    #[test]
    fn platform_admin_allows_all_permissions() {
        let principal = principal_with_scopes(&[SCOPE_PLATFORM_ADMIN]);
        assert!(principal.allows(Permission::Read));
        assert!(principal.allows(Permission::Write));
        assert!(principal.allows(Permission::Delete));
        assert!(principal.allows(Permission::AssignRole));
    }
}
