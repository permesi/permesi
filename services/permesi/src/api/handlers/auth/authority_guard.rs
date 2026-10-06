//! Transactional session authority for MFA enrollment, recovery and elevation.
//!
//! Flow Overview: after ordinary principal authentication, lock the current user
//! and exact original session again, verify the factor, mutate MFA state and issue
//! replacement authority on this transaction. Password rotation takes the same user
//! lock before revoking sessions, so either elevation commits first and is revoked,
//! or rotation wins and the old session cannot elevate. No browser field supplies
//! the session kind, identity or authorization decision.

use super::{session::extract_session_token, session_kind::SessionKind, utils::hash_session_token};
use axum::http::{HeaderMap, StatusCode};
use sqlx::{PgConnection, PgPool, Postgres, Transaction};
use uuid::Uuid;

/// Server-selected routes' session capabilities, checked again under lifecycle locks.
#[derive(Clone, Copy)]
pub(crate) enum Policy {
    Full,
    Enrollment,
    Challenge,
}

/// Holds current identity and session locks until all new authority is committed.
pub(crate) struct AuthorityGuard {
    transaction: Transaction<'static, Postgres>,
    user: Uuid,
    hash: Vec<u8>,
    kind: SessionKind,
}

impl AuthorityGuard {
    /// Authorizes an active user with an unexpired exact session of the route's allowed kind.
    /// Lock order is identity then session; dependency failure yields only a generic 503.
    pub(crate) async fn acquire(
        pool: &PgPool,
        headers: &HeaderMap,
        user: Uuid,
        policy: Policy,
        timeout_ms: i64,
    ) -> Result<Self, StatusCode> {
        let token = extract_session_token(headers).ok_or(StatusCode::UNAUTHORIZED)?;
        let kind = SessionKind::from_token(&token);
        let allowed = match policy {
            Policy::Full => kind == SessionKind::Full,
            Policy::Enrollment => matches!(kind, SessionKind::Full | SessionKind::MfaBootstrap),
            Policy::Challenge => kind == SessionKind::MfaChallenge,
        };
        if !allowed {
            return Err(StatusCode::UNAUTHORIZED);
        }
        let hash = hash_session_token(&token);
        let mut transaction = super::operations::begin(pool, timeout_ms)
            .await
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        // NO KEY UPDATE serializes lifecycle writers/elevations while permitting FK
        // key-share locks taken by separate factor/storage services.
        let status: Option<String> =
            sqlx::query_scalar("SELECT status::text FROM users WHERE id=$1 FOR NO KEY UPDATE")
                .bind(user)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        if status.as_deref() != Some("active") {
            return Err(StatusCode::UNAUTHORIZED);
        }
        let query = match kind {
            SessionKind::Full => {
                "SELECT expires_at>clock_timestamp() FROM user_sessions WHERE user_id=$1 AND session_hash=$2 FOR UPDATE"
            }
            SessionKind::MfaBootstrap => {
                "SELECT expires_at>clock_timestamp() FROM user_mfa_bootstrap_sessions WHERE user_id=$1 AND session_hash=$2 FOR UPDATE"
            }
            SessionKind::MfaChallenge => {
                "SELECT expires_at>clock_timestamp() FROM user_mfa_challenge_sessions WHERE user_id=$1 AND session_hash=$2 FOR UPDATE"
            }
        };
        let valid: Option<bool> = sqlx::query_scalar(query)
            .bind(user)
            .bind(&hash)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        if valid != Some(true) {
            return Err(StatusCode::UNAUTHORIZED);
        }
        if kind == SessionKind::MfaBootstrap {
            // Another enrollment may already have enabled MFA after this limited cookie was issued.
            let unenrolled: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM user_mfa_state WHERE user_id=$1 AND state='required_unenrolled')",
            )
            .bind(user)
            .fetch_one(&mut *transaction)
            .await
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
            if !unenrolled {
                return Err(StatusCode::UNAUTHORIZED);
            }
        }
        Ok(Self {
            transaction,
            user,
            hash,
            kind,
        })
    }

    /// The connection on which protected state changes and replacement sessions must run.
    pub(crate) fn connection(&mut self) -> &mut PgConnection {
        &mut self.transaction
    }

    /// Consumes the exact verified original session; failure rolls back replacement authority.
    pub(crate) async fn consume_original(&mut self) -> Result<(), sqlx::Error> {
        let query = match self.kind {
            SessionKind::Full => "DELETE FROM user_sessions WHERE user_id=$1 AND session_hash=$2",
            SessionKind::MfaBootstrap => {
                "DELETE FROM user_mfa_bootstrap_sessions WHERE user_id=$1 AND session_hash=$2"
            }
            SessionKind::MfaChallenge => {
                "DELETE FROM user_mfa_challenge_sessions WHERE user_id=$1 AND session_hash=$2"
            }
        };
        sqlx::query(query)
            .bind(self.user)
            .bind(&self.hash)
            .execute(&mut *self.transaction)
            .await?;
        Ok(())
    }

    /// Publishes authority only after all factor/lifecycle changes have succeeded.
    pub(crate) async fn commit(self) -> Result<(), sqlx::Error> {
        self.transaction.commit().await
    }
}

impl AuthorityGuard {
    /// Issues full authority only after the caller verified the factor; consumes the original session.
    pub(crate) async fn issue_full(
        mut self,
        auth: &super::AuthState,
    ) -> Result<axum::http::HeaderValue, StatusCode> {
        let ttl = auth.config().session_ttl_seconds();
        let user = self.user;
        let token = super::storage::insert_session_on(self.connection(), user, ttl)
            .await
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        self.consume_original()
            .await
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        // Completion ends enrollment authority for every earlier password login,
        // including ceremonies started on other replicas before MFA was enabled.
        sqlx::query("DELETE FROM user_mfa_bootstrap_sessions WHERE user_id=$1")
            .bind(user)
            .execute(self.connection())
            .await
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        let cookie = super::session::session_cookie_with_ttl(auth, &token, ttl)
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        self.commit()
            .await
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        Ok(cookie)
    }
}
