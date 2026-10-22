//! Audited platform-operator designation with durable two-person restoration.
//!
//! Flow Overview: an enabled operator with a recently authenticated full session
//! requests designation of an active verified account. A different enabled operator
//! approves it under the same PostgreSQL identity locks. Only the initial operator
//! may approve their own request for the first *new* second designation. Disabling
//! another operator is immediate but cannot remove the last enabled operator.
//! Every mutation is atomic with its fixed-reason audit event and retires target
//! sessions/proofs on a designation change. Admin tokens bind to a revision that
//! changes on each transition, preventing old tokens from reviving after recovery.

use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use sqlx::{PgConnection, PgPool};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::api::handlers::auth::{
    AuthState,
    authority_guard::{AuthorityGuard, FACTOR_RECENT_AUTH_SECONDS},
    principal::{Permission, require_auth},
};

const DESIGNATION_LOCK_ID: i64 = 4_201_111;

/// Fixed audit reason; arbitrary text is excluded from operator history.
#[derive(Clone, Copy, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum OperatorReason {
    Administrative,
    IncidentRecovery,
    SuspectedCompromise,
}

impl OperatorReason {
    /// Maps the typed request classification to the database constraint.
    const fn as_str(self) -> &'static str {
        match self {
            Self::Administrative => "administrative",
            Self::IncidentRecovery => "incident_recovery",
            Self::SuspectedCompromise => "suspected_compromise",
        }
    }
}

/// The actor supplies only a fixed reason, never authority or approval identity.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct OperatorRequest {
    pub reason: OperatorReason,
}

/// Current designation and request state visible only to enabled operators.
#[derive(Serialize, ToSchema)]
pub struct OperatorStatus {
    pub designation: &'static str,
    pub pending_enable: bool,
    pub requested_by_me: bool,
    pub requested_by_email: Option<String>,
    pub requested_reason: Option<String>,
    pub requested_at: Option<String>,
    pub can_approve: bool,
}

type OperatorStatusRow = (
    Option<bool>,
    Option<Uuid>,
    Option<String>,
    Option<String>,
    Option<String>,
);

#[derive(Clone, Copy)]
enum Action {
    RequestEnable,
    Enable,
    Disable,
}

impl Action {
    /// Audit operation is chosen by the route, never by browser JSON.
    const fn as_str(self) -> &'static str {
        match self {
            Self::RequestEnable => "request_enable",
            Self::Enable => "enable",
            Self::Disable => "disable",
        }
    }
}

#[utoipa::path(
    get, path = "/v1/users/{id}/operator",
    params(("id" = String, Path, description = "Target account UUID")),
    responses(
        (status = 200, body = OperatorStatus, description = "Designation and pending approval."),
        (status = 400, description = "Invalid UUID."),
        (status = 401, description = "Full session required."),
        (status = 403, description = "Enabled platform operator required."),
        (status = 404, description = "Account not found."),
        (status = 503, description = "Database unavailable.")
    ), tag = "users"
)]
/// Reads designation state only after server-side operator authorization.
pub async fn get_operator(
    headers: HeaderMap,
    Path(id): Path<String>,
    State(pool): State<PgPool>,
) -> Response {
    let principal = match require_auth(&headers, &pool).await {
        Ok(value) => value,
        Err(status) => return status.into_response(),
    };
    if !principal.allows(Permission::ManageStatus) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Ok(target) = Uuid::parse_str(&id) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let actor_enabled: Result<Option<Uuid>, _> =
        sqlx::query_scalar("SELECT user_id FROM platform_operators WHERE user_id=$1 AND enabled")
            .bind(principal.user_id)
            .fetch_optional(&pool)
            .await;
    match actor_enabled {
        Ok(Some(_)) => {}
        Ok(None) => return StatusCode::FORBIDDEN.into_response(),
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
    let row: Result<Option<OperatorStatusRow>, _> = sqlx::query_as(
        "SELECT po.enabled, r.requested_by, proposer.email AS requested_by_email, r.reason, to_char(r.requested_at AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI:SS') AS requested_at FROM users u LEFT JOIN platform_operators po ON po.user_id=u.id LEFT JOIN platform_operator_enable_requests r ON r.target_id=u.id AND r.requested_at > clock_timestamp()-($2 * INTERVAL '1 second') LEFT JOIN users proposer ON proposer.id=r.requested_by WHERE u.id=$1",
    )
    .bind(target)
    .bind(FACTOR_RECENT_AUTH_SECONDS)
    .fetch_optional(&pool)
    .await;
    match row {
        Ok(Some((enabled, requester, requester_email, requested_reason, requested_at))) => {
            let first_expansion = if requester == Some(principal.user_id) && enabled.is_none() {
                let count: Result<i64, _> =
                    sqlx::query_scalar("SELECT count(*) FROM platform_operators")
                        .fetch_one(&pool)
                        .await;
                match count {
                    Ok(value) => value == 1,
                    Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
                }
            } else {
                false
            };
            Json(OperatorStatus {
                designation: match enabled {
                    Some(true) => "enabled",
                    Some(false) => "disabled",
                    None => "none",
                },
                pending_enable: requester.is_some(),
                requested_by_me: requester == Some(principal.user_id),
                requested_by_email: requester_email,
                requested_reason,
                requested_at,
                can_approve: requester.is_some()
                    && (requester != Some(principal.user_id) || first_expansion),
            })
            .into_response()
        }
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

#[utoipa::path(
    post, path = "/v1/users/{id}/operator/request-enable",
    params(("id" = String, Path, description = "Target account UUID")),
    request_body = OperatorRequest,
    responses(
        (status = 204, description = "Durable designation request recorded."),
        (status = 400, description = "Invalid UUID or JSON."),
        (status = 401, description = "Recent full session required."),
        (status = 403, description = "Enabled operator required."),
        (status = 404, description = "Account not found."),
        (status = 409, description = "Self-action, unverified/inactive or already-enabled target, or another current requester."),
        (status = 422, description = "Invalid reason."),
        (status = 503, description = "Database unavailable; no partial transition.")
    ), tag = "users"
)]
/// Proposes one active verified account for operator designation without granting it.
pub async fn request_enable(
    headers: HeaderMap,
    Path(id): Path<String>,
    State(pool): State<PgPool>,
    State(auth): State<Arc<AuthState>>,
    Json(payload): Json<OperatorRequest>,
) -> Response {
    transition(
        &pool,
        &auth,
        &headers,
        &id,
        Action::RequestEnable,
        payload.reason,
    )
    .await
    .into_response()
}

#[utoipa::path(
    post, path = "/v1/users/{id}/operator/enable",
    params(("id" = String, Path, description = "Target account UUID")),
    request_body = OperatorRequest,
    responses(
        (status = 204, description = "Distinct approval enabled designation and retired prior sessions."),
        (status = 400, description = "Invalid UUID or JSON."),
        (status = 401, description = "Recent full session required."),
        (status = 403, description = "Enabled operator required."),
        (status = 404, description = "Account not found."),
        (status = 409, description = "Missing/expired request, invalid proposer, self-approval, or unverified/inactive/already-enabled target."),
        (status = 422, description = "Invalid reason."),
        (status = 503, description = "Database unavailable; no partial transition.")
    ), tag = "users"
)]
/// Approves another operator's durable request; the sole bootstrap operator may add a second.
pub async fn enable(
    headers: HeaderMap,
    Path(id): Path<String>,
    State(pool): State<PgPool>,
    State(auth): State<Arc<AuthState>>,
    Json(payload): Json<OperatorRequest>,
) -> Response {
    transition(&pool, &auth, &headers, &id, Action::Enable, payload.reason)
        .await
        .into_response()
}

#[utoipa::path(
    post, path = "/v1/users/{id}/operator/disable",
    params(("id" = String, Path, description = "Target account UUID")),
    request_body = OperatorRequest,
    responses(
        (status = 204, description = "Designation disabled; sessions and elevation revision retired."),
        (status = 400, description = "Invalid UUID or JSON."),
        (status = 401, description = "Recent full session required."),
        (status = 403, description = "Enabled operator required."),
        (status = 404, description = "Account not found."),
        (status = 409, description = "Self-action, last operator, or designation missing/already disabled."),
        (status = 422, description = "Invalid reason."),
        (status = 503, description = "Database unavailable; no partial transition.")
    ), tag = "users"
)]
/// Removes another operator's live authority without changing tenant or OAuth scopes.
pub async fn disable(
    headers: HeaderMap,
    Path(id): Path<String>,
    State(pool): State<PgPool>,
    State(auth): State<Arc<AuthState>>,
    Json(payload): Json<OperatorRequest>,
) -> Response {
    transition(&pool, &auth, &headers, &id, Action::Disable, payload.reason)
        .await
        .into_response()
}

/// Rechecks the exact session and operator row after lock waits before any mutation.
async fn transition(
    pool: &PgPool,
    auth: &AuthState,
    headers: &HeaderMap,
    id: &str,
    action: Action,
    reason: OperatorReason,
) -> Result<StatusCode, StatusCode> {
    let principal = require_auth(headers, pool).await?;
    if !principal.allows(Permission::ManageStatus) {
        return Err(StatusCode::FORBIDDEN);
    }
    let target = Uuid::parse_str(id).map_err(|_| StatusCode::BAD_REQUEST)?;
    if target == principal.user_id {
        return Err(StatusCode::CONFLICT);
    }
    let mut guard = AuthorityGuard::acquire_for_target(
        pool,
        headers,
        principal.user_id,
        target,
        auth.config().opaque_exchange_timeout_ms(),
    )
    .await?;
    // Take the designation lock before touching an operator row. Otherwise a
    // concurrent disable can hold this lock while waiting for our FOR SHARE row
    // lock, while this request waits for the designation lock.
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(DESIGNATION_LOCK_ID)
        .execute(guard.connection())
        .await
        .map_err(unavailable)?;
    let operator: Option<Uuid> = sqlx::query_scalar(
        "SELECT user_id FROM platform_operators WHERE user_id=$1 AND enabled FOR SHARE",
    )
    .bind(principal.user_id)
    .fetch_optional(guard.connection())
    .await
    .map_err(unavailable)?;
    if operator.is_none() {
        return Err(StatusCode::FORBIDDEN);
    }
    guard
        .require_recent_auth(FACTOR_RECENT_AUTH_SECONDS)
        .await?;
    apply(
        guard.connection(),
        principal.user_id,
        target,
        action,
        reason,
    )
    .await?;
    guard.commit().await.map_err(unavailable)?;
    Ok(StatusCode::NO_CONTENT)
}

/// Holds the global designation lock while enforcing bootstrap and last-operator rules.
async fn apply(
    connection: &mut PgConnection,
    actor: Uuid,
    target: Uuid,
    action: Action,
    reason: OperatorReason,
) -> Result<(), StatusCode> {
    let target_state: Option<(String, bool)> =
        sqlx::query_as("SELECT status::text,email_verified_at IS NOT NULL FROM users WHERE id=$1")
            .bind(target)
            .fetch_optional(&mut *connection)
            .await
            .map_err(unavailable)?;
    let Some((status, verified)) = target_state else {
        return Err(StatusCode::NOT_FOUND);
    };
    let designation: Option<bool> =
        sqlx::query_scalar("SELECT enabled FROM platform_operators WHERE user_id=$1 FOR UPDATE")
            .bind(target)
            .fetch_optional(&mut *connection)
            .await
            .map_err(unavailable)?;
    let mut requested_by: Option<Uuid> = None;
    match action {
        Action::RequestEnable => {
            if status != "active" || !verified || designation == Some(true) {
                return Err(StatusCode::CONFLICT);
            }
            let updated = sqlx::query("INSERT INTO platform_operator_enable_requests(target_id,requested_by,reason) VALUES($1,$2,$4) ON CONFLICT(target_id) DO UPDATE SET requested_by=EXCLUDED.requested_by,requested_at=clock_timestamp(),reason=EXCLUDED.reason WHERE platform_operator_enable_requests.requested_by=EXCLUDED.requested_by OR platform_operator_enable_requests.requested_at <= clock_timestamp()-($3 * INTERVAL '1 second')")
                .bind(target).bind(actor).bind(FACTOR_RECENT_AUTH_SECONDS).bind(reason.as_str())
                .execute(&mut *connection).await.map_err(unavailable)?;
            if updated.rows_affected() != 1 {
                return Err(StatusCode::CONFLICT);
            }
        }
        Action::Enable => {
            if status != "active" || !verified || designation == Some(true) {
                return Err(StatusCode::CONFLICT);
            }
            requested_by = sqlx::query_scalar(
                "SELECT requested_by FROM platform_operator_enable_requests WHERE target_id=$1 AND requested_at > clock_timestamp()-($2 * INTERVAL '1 second') FOR UPDATE",
            )
            .bind(target)
            .bind(FACTOR_RECENT_AUTH_SECONDS)
            .fetch_optional(&mut *connection)
            .await
            .map_err(unavailable)?;
            let requester = requested_by.ok_or(StatusCode::CONFLICT)?;
            let requester_active: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM platform_operators po JOIN users u ON u.id=po.user_id WHERE po.user_id=$1 AND po.enabled AND u.status='active')",
            )
            .bind(requester)
            .fetch_one(&mut *connection)
            .await
            .map_err(unavailable)?;
            if !requester_active {
                return Err(StatusCode::CONFLICT);
            }
            if requester == actor {
                let count: i64 = sqlx::query_scalar("SELECT count(*) FROM platform_operators")
                    .fetch_one(&mut *connection)
                    .await
                    .map_err(unavailable)?;
                if designation.is_some() || count != 1 {
                    return Err(StatusCode::CONFLICT);
                }
            }
            sqlx::query("INSERT INTO platform_operators(user_id,created_by) VALUES($1,$2) ON CONFLICT(user_id) DO UPDATE SET enabled=TRUE,token_revision=uuidv4()")
                .bind(target).bind(requester).execute(&mut *connection).await.map_err(unavailable)?;
            sqlx::query("DELETE FROM platform_operator_enable_requests WHERE target_id=$1")
                .bind(target)
                .execute(&mut *connection)
                .await
                .map_err(unavailable)?;
            retire_sessions(connection, target)
                .await
                .map_err(unavailable)?;
        }
        Action::Disable => {
            if designation != Some(true) {
                return Err(StatusCode::CONFLICT);
            }
            let count: i64 =
                sqlx::query_scalar("SELECT count(*) FROM platform_operators WHERE enabled")
                    .fetch_one(&mut *connection)
                    .await
                    .map_err(unavailable)?;
            if count <= 1 {
                return Err(StatusCode::CONFLICT);
            }
            sqlx::query("UPDATE platform_operators SET enabled=FALSE,token_revision=uuidv4() WHERE user_id=$1")
                .bind(target).execute(&mut *connection).await.map_err(unavailable)?;
            sqlx::query("DELETE FROM platform_operator_enable_requests WHERE target_id=$1 OR requested_by=$1")
                .bind(target).execute(&mut *connection).await.map_err(unavailable)?;
            retire_sessions(connection, target)
                .await
                .map_err(unavailable)?;
        }
    }
    sqlx::query("INSERT INTO platform_operator_audit_log(actor_id,target_id,action,reason,requested_by) VALUES($1,$2,$3,$4,$5)")
        .bind(actor).bind(target).bind(action.as_str()).bind(reason.as_str()).bind(requested_by)
        .execute(connection).await.map_err(unavailable)?;
    Ok(())
}

/// Removes existing cookies and unfinished authentication proofs; delegated OAuth grants remain intact.
async fn retire_sessions(connection: &mut PgConnection, user: Uuid) -> Result<(), sqlx::Error> {
    for query in [
        "DELETE FROM user_sessions WHERE user_id=$1",
        "DELETE FROM user_mfa_bootstrap_sessions WHERE user_id=$1",
        "DELETE FROM user_mfa_challenge_sessions WHERE user_id=$1",
        "DELETE FROM opaque_exchanges WHERE user_id=$1",
        "DELETE FROM webauthn_exchanges WHERE user_id=$1",
    ] {
        sqlx::query(query)
            .bind(user)
            .execute(&mut *connection)
            .await?;
    }
    Ok(())
}

/// Suppresses SQL details on the public response path.
fn unavailable(_: sqlx::Error) -> StatusCode {
    StatusCode::SERVICE_UNAVAILABLE
}

#[cfg(test)]
mod tests;
