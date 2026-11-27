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
//! 1. `POST /v1/auth/admin/elevate` reads the database [`clock`], then validates the
//!    OpenBao token. [`openbao_deadline`] turns that reading and the token's remaining
//!    life into the instant the elevation may not pass.
//! 2. The handler takes the identity and exact-session locks of `AuthorityGuard` and
//!    calls [`grant`] on that transaction. It rechecks the account, the session and the
//!    operator designation and writes the session's one row, replacing an earlier grant.
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
//!
//! Every time bound is measured on the database clock, in one place, so replicas need
//! not agree on the time. The OpenBao bound is an instant fixed before the lookup, not
//! a duration added when the row is written: time spent waiting for OpenBao, for a lock
//! or for the statement shortens the elevation and can never extend it.
//!
//! Step-ups on one session are applied in the order they commit. Two that overlap are
//! each backed by their own valid OpenBao token, and the later commit decides the row.

use anyhow::{Context, Result};
use jiff::SignedDuration;
use jiff_sqlx::{Timestamp, ToSqlx};
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

/// Reads the database clock. Taken before the OpenBao lookup, it anchors the deadline
/// of the elevation on the same clock that later writes and checks the grant.
///
/// # Errors
/// Returns an error if the database cannot be read; no elevation may then proceed.
pub(super) async fn clock(pool: &PgPool) -> Result<Timestamp> {
    sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(pool)
        .await
        .context("failed to read the database clock")
}

/// The instant an elevation earned with an OpenBao token may not pass, or `None` when
/// the token leaves no usable time.
///
/// `anchor` must have been read before the lookup that reported `openbao_ttl_seconds`,
/// so the token cannot end before `anchor` plus its real remaining life. OpenBao
/// reports that life in whole seconds, rounded, so one second is given up: the deadline
/// is never later than the token's own end. A missing or negative lifetime, which the
/// lookup reports as zero or less, grants nothing. The lifetime is capped just above
/// `configured_seconds` first; that changes no result and keeps the arithmetic in range.
pub(super) fn openbao_deadline(
    anchor: Timestamp,
    openbao_ttl_seconds: i64,
    configured_seconds: i64,
) -> Option<Timestamp> {
    let usable = openbao_ttl_seconds
        .min(configured_seconds.saturating_add(1))
        .checked_sub(1)
        .filter(|seconds| *seconds > 0)?;
    anchor
        .to_jiff()
        .checked_add(SignedDuration::from_secs(usable))
        .ok()
        .map(ToSqlx::to_sqlx)
}

/// Records the elevation of one locked session and returns its expiry, or `None` when
/// the session, account or designation no longer qualifies or no lifetime is left.
///
/// The caller must hold `AuthorityGuard` locks for `user` and this session on
/// `connection`, and must already have validated the OpenBao token. The row expires at
/// the earliest of `ttl_seconds` from now, `deadline` (see [`openbao_deadline`]) and the
/// session's own expiry, and binds the designation revision read here. A repeated
/// elevation replaces the row. A lifetime that is not positive reaches no statement.
///
/// # Errors
/// Returns an error if the statement fails; the caller's transaction must then roll back.
pub(super) async fn grant(
    connection: &mut PgConnection,
    user: Uuid,
    session_hash: &[u8],
    ttl_seconds: i64,
    deadline: Timestamp,
) -> Result<Option<Timestamp>> {
    if ttl_seconds <= 0 {
        return Ok(None);
    }
    // One clock reading for the session check, the bounds and both timestamps, so the
    // row cannot be written with an expiry at or before its creation.
    let query = r"
        WITH clock AS MATERIALIZED (SELECT clock_timestamp() AS now),
        candidate AS (
            SELECT s.id,
                   po.token_revision,
                   clock.now,
                   LEAST(clock.now + $3::bigint * INTERVAL '1 second', $4, s.expires_at)
                       AS expires_at
            FROM clock
            JOIN user_sessions s
              ON s.user_id = $1 AND s.session_hash = $2 AND s.expires_at > clock.now
            JOIN users u ON u.id = s.user_id AND u.status = 'active'
            JOIN platform_operators po ON po.user_id = s.user_id AND po.enabled
        )
        INSERT INTO platform_operator_elevations (session_id, operator_revision, created_at, expires_at)
        SELECT id, token_revision, now, expires_at
        FROM candidate
        WHERE expires_at > now
        ON CONFLICT (session_id) DO UPDATE
            SET operator_revision = EXCLUDED.operator_revision,
                created_at = EXCLUDED.created_at,
                expires_at = EXCLUDED.expires_at
        RETURNING expires_at
    ";
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
        .bind(deadline)
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
