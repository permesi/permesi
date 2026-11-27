//! Operator elevation stored in PostgreSQL and tied to the session that earned it.
//!
//! An elevation is the step-up an enabled platform operator performs with an OpenBao
//! token before reading the infrastructure status route. It used to be a PASETO signed
//! with a key each process generated at start, which another replica could not verify
//! and which stayed valid after its session ended. A row removes both problems without
//! a shared signing key: every replica reads the same table, and the row is deleted
//! with its session.
//!
//! ## Flow Overview
//! 1. `POST /v1/auth/admin/elevate` validates the OpenBao token, then takes the identity
//!    and exact-session locks of `AuthorityGuard` and calls [`grant`] on that transaction.
//! 2. [`grant`] rechecks the account, the session and the operator designation under
//!    those locks and writes the session's one row, replacing an earlier grant.
//! 3. `GET /v1/auth/admin/infra` calls [`authorize`] with the session cookie's hash.
//!    One statement decides from the session, the account, the designation and the grant.
//!
//! ## Security boundaries
//! The grant is keyed by the session, so it cannot name another account and no browser
//! field selects it. Logout, session replacement, password rotation, containment and
//! expiry cleanup delete the session and the grant with it. Disabling the designation or
//! suspending the account rotates the designation revision, which leaves a surviving
//! row unusable. The grant never outlives the session, the configured lifetime or the
//! OpenBao token that earned it. No OpenBao token is stored.

use anyhow::{Context, Result};
use sqlx::{PgConnection, PgPool};
use tracing::Instrument;
use uuid::Uuid;

/// What the session cookie may do on the infrastructure status route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Access {
    /// A live full session of an active account holds a current, unexpired grant.
    Elevated,
    /// The session is valid, and it holds no grant that is still good.
    NotElevated,
    /// No live full session of an active account matches the cookie.
    NoSession,
}

/// Records the elevation of one locked session and returns its expiry (RFC 3339, UTC,
/// whole seconds), or `None` when the session, account or designation no longer qualifies.
///
/// The caller must hold `AuthorityGuard` locks for `user` and this session on
/// `connection`, and must already have validated the OpenBao token; `ttl_seconds` is the
/// smaller of the configured lifetime and that token's remaining life. The row binds
/// the designation revision read here and expires no later than the session. A repeated
/// elevation replaces the row, so the newest step-up decides the expiry. A lifetime that
/// is not positive grants nothing and reaches no statement.
///
/// # Errors
/// Returns an error if the statement fails; the caller's transaction must then roll back.
pub(super) async fn grant(
    connection: &mut PgConnection,
    user: Uuid,
    session_hash: &[u8],
    ttl_seconds: i64,
) -> Result<Option<String>> {
    if ttl_seconds <= 0 {
        return Ok(None);
    }
    // One clock reading for the session check and both timestamps, so the row cannot be
    // written with an expiry at or before its creation.
    let query = r#"
        WITH clock AS MATERIALIZED (SELECT clock_timestamp() AS now)
        INSERT INTO platform_operator_elevations (session_id, operator_revision, created_at, expires_at)
        SELECT s.id,
               po.token_revision,
               clock.now,
               LEAST(clock.now + $3::bigint * INTERVAL '1 second', s.expires_at)
        FROM clock
        JOIN user_sessions s
          ON s.user_id = $1 AND s.session_hash = $2 AND s.expires_at > clock.now
        JOIN users u ON u.id = s.user_id AND u.status = 'active'
        JOIN platform_operators po ON po.user_id = s.user_id AND po.enabled
        ON CONFLICT (session_id) DO UPDATE
            SET operator_revision = EXCLUDED.operator_revision,
                created_at = EXCLUDED.created_at,
                expires_at = EXCLUDED.expires_at
        RETURNING to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
    "#;
    let span = tracing::info_span!(
        "db.query",
        db.system = "postgresql",
        db.operation = "INSERT",
        db.statement = query
    );
    sqlx::query_scalar(query)
        .bind(user)
        .bind(session_hash)
        .bind(ttl_seconds)
        .fetch_optional(connection)
        .instrument(span)
        .await
        .context("failed to record operator elevation")
}

/// Decides whether the session behind `session_hash` may read infrastructure status.
///
/// Authorizes only a live full session of an active account whose user is an enabled
/// platform operator and which holds an unexpired grant issued under the operator's
/// current designation revision. Every input is server data read in one statement; no
/// header, claim or role supplied by the client takes part. Read-only, with no side
/// effects: it does not touch the session's activity time.
///
/// # Errors
/// Returns an error if the lookup fails; callers must treat that as a refusal.
pub(super) async fn authorize(pool: &PgPool, session_hash: &[u8]) -> Result<Access> {
    let query = r"
        SELECT (po.enabled
                AND e.operator_revision = po.token_revision
                AND e.expires_at > clock_timestamp()) IS TRUE AS elevated
        FROM user_sessions s
        JOIN users u ON u.id = s.user_id AND u.status = 'active'
        LEFT JOIN platform_operators po ON po.user_id = s.user_id
        LEFT JOIN platform_operator_elevations e ON e.session_id = s.id
        WHERE s.session_hash = $1
          AND s.expires_at > clock_timestamp()
    ";
    let span = tracing::info_span!(
        "db.query",
        db.system = "postgresql",
        db.operation = "SELECT",
        db.statement = query
    );
    let elevated: Option<bool> = sqlx::query_scalar(query)
        .bind(session_hash)
        .fetch_optional(pool)
        .instrument(span)
        .await
        .context("failed to look up operator elevation")?;
    Ok(match elevated {
        Some(true) => Access::Elevated,
        Some(false) => Access::NotElevated,
        None => Access::NoSession,
    })
}
