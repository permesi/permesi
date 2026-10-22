//! Platform-operator account containment, with one atomic database authority boundary.
//!
//! Flow Overview: authenticate a full session, lock actor/target identities in UUID order,
//! recheck the exact recent session and enabled operator record, then change status,
//! retire authority and append an audit event in the same bounded transaction.
//! Suspension is global, not a tenant-manager capability. Reactivation restores only
//! account eligibility; old sessions, proofs, grants and refresh families remain invalid.
//! Offline resource servers still accept already-issued JWTs until their normal expiry.

use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use sqlx::{PgConnection, PgPool};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::api::handlers::auth::{
    AuthState,
    authority_guard::AuthorityGuard,
    principal::{Permission, require_auth},
};

/// Fixed audit classifications: no free-form credential, token or personal-data field.
#[derive(Clone, Copy, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleReason {
    SuspectedCompromise,
    Abuse,
    Administrative,
    IncidentResolved,
}

impl LifecycleReason {
    /// Stable database classification, never arbitrary browser-supplied text.
    const fn as_str(self) -> &'static str {
        match self {
            Self::SuspectedCompromise => "suspected_compromise",
            Self::Abuse => "abuse",
            Self::Administrative => "administrative",
            Self::IncidentResolved => "incident_resolved",
        }
    }
}

/// A reason is mandatory; role, status and authority are selected only by the server.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct LifecycleRequest {
    pub reason: LifecycleReason,
}

#[derive(Clone, Copy)]
enum Action {
    Suspend,
    Reactivate,
}

impl Action {
    /// Fixed endpoint-selected operation; no request field can select another action.
    const fn as_str(self) -> &'static str {
        match self {
            Self::Suspend => "suspend",
            Self::Reactivate => "reactivate",
        }
    }
}

#[utoipa::path(
    post, path = "/v1/users/{id}/suspend",
    params(("id" = String, Path, description = "Target account UUID")),
    request_body = LifecycleRequest,
    responses(
        (status = 204, description = "Suspended; account authority retired atomically, including repeated requests."),
        (status = 400, description = "Invalid UUID or malformed JSON."),
        (status = 422, description = "Missing/unknown reason or unexpected JSON field."),
        (status = 401, description = "Full session with authentication in the last ten minutes required."),
        (status = 403, description = "Enabled platform operator required."),
        (status = 404, description = "Account not found, disclosed only after operator authorization."),
        (status = 409, description = "Self-containment is forbidden."),
        (status = 503, description = "Bounded database operation unavailable; no partial transition.")
    ), tag = "users"
)]
/// Suspends only with current enabled platform authority and exact recent full-session authentication.
pub async fn suspend(
    headers: HeaderMap,
    Path(id): Path<String>,
    State(pool): State<PgPool>,
    State(auth): State<Arc<AuthState>>,
    Json(payload): Json<LifecycleRequest>,
) -> Response {
    transition(&pool, &auth, &headers, &id, Action::Suspend, payload.reason)
        .await
        .into_response()
}

#[utoipa::path(
    post, path = "/v1/users/{id}/reactivate",
    params(("id" = String, Path, description = "Target account UUID")),
    request_body = LifecycleRequest,
    responses(
        (status = 204, description = "Account eligible again; unverified accounts remain pending. Retired authority is never restored."),
        (status = 400, description = "Invalid UUID or malformed JSON."),
        (status = 422, description = "Missing/unknown reason or unexpected JSON field."),
        (status = 401, description = "Full session with authentication in the last ten minutes required."),
        (status = 403, description = "Enabled platform operator required."),
        (status = 404, description = "Account not found, disclosed only after operator authorization."),
        (status = 409, description = "Self-containment is forbidden."),
        (status = 503, description = "Bounded database operation unavailable; no partial transition.")
    ), tag = "users"
)]
/// Restores verified accounts to active and unverified accounts to pending, without reviving authority.
pub async fn reactivate(
    headers: HeaderMap,
    Path(id): Path<String>,
    State(pool): State<PgPool>,
    State(auth): State<Arc<AuthState>>,
    Json(payload): Json<LifecycleRequest>,
) -> Response {
    transition(
        &pool,
        &auth,
        &headers,
        &id,
        Action::Reactivate,
        payload.reason,
    )
    .await
    .into_response()
}

/// Rechecks operator authority after all lock waits; errors expose no database or credential data.
async fn transition(
    pool: &PgPool,
    auth: &AuthState,
    headers: &HeaderMap,
    id: &str,
    action: Action,
    reason: LifecycleReason,
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
        .require_recent_auth(
            crate::api::handlers::auth::authority_guard::FACTOR_RECENT_AUTH_SECONDS,
        )
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

/// Mutates only while caller-held identity/operator/session locks remain live through audit commit.
async fn apply(
    connection: &mut PgConnection,
    actor: Uuid,
    target: Uuid,
    action: Action,
    reason: LifecycleReason,
) -> Result<(), StatusCode> {
    let (previous, verified): (String, bool) =
        sqlx::query_as("SELECT status::text,email_verified_at IS NOT NULL FROM users WHERE id=$1")
            .bind(target)
            .fetch_optional(&mut *connection)
            .await
            .map_err(unavailable)?
            .ok_or(StatusCode::NOT_FOUND)?;
    let next = match action {
        Action::Suspend => "disabled",
        Action::Reactivate if previous == "disabled" => {
            if verified {
                "active"
            } else {
                "pending_verification"
            }
        }
        Action::Reactivate => &previous,
    };
    if matches!(action, Action::Suspend) || previous != next {
        // Advancing the revision also covers old codes/receipts; the schema trigger
        // advances the login cutoff whenever status changes, including reactivation.
        sqlx::query(
            "UPDATE users SET status=$2::user_status,authorization_revision=uuidv4() WHERE id=$1",
        )
        .bind(target)
        .bind(next)
        .execute(&mut *connection)
        .await
        .map_err(unavailable)?;
        retire_authority(connection, target)
            .await
            .map_err(unavailable)?;
    }
    sqlx::query("INSERT INTO user_lifecycle_audit_log(actor_id,target_id,action,reason,previous_status,new_status,outcome) VALUES($1,$2,$3,$4,$5::user_status,$6::user_status,$7)")
        .bind(actor).bind(target).bind(action.as_str()).bind(reason.as_str())
        .bind(&previous).bind(next).bind(if previous == next { "unchanged" } else { "changed" })
        .execute(connection).await.map_err(unavailable)?;
    Ok(())
}

/// Permanently retires delegated and pending authority without erasing retained token history.
async fn retire_authority(connection: &mut PgConnection, user: Uuid) -> Result<(), sqlx::Error> {
    crate::oauth::tokens::revoke_user_authority(
        connection,
        user,
        crate::oauth::tokens::UserRevocation::Suspension,
    )
    .await?;
    for query in [
        "UPDATE oauth_grants SET revoked_at=clock_timestamp() WHERE user_id=$1 AND revoked_at IS NULL",
        "DELETE FROM user_sessions WHERE user_id=$1",
        "DELETE FROM user_mfa_bootstrap_sessions WHERE user_id=$1",
        "DELETE FROM user_mfa_challenge_sessions WHERE user_id=$1",
        "DELETE FROM opaque_exchanges WHERE user_id=$1",
        "DELETE FROM webauthn_exchanges WHERE user_id=$1",
        "DELETE FROM totp_credentials WHERE user_id=$1 AND confirmed_at IS NULL",
        "UPDATE email_verification_tokens SET consumed_at=clock_timestamp() WHERE user_id=$1 AND consumed_at IS NULL",
        "UPDATE email_outbox SET status='failed',payload_json='{}'::jsonb,last_error='account_unavailable',claim_id=NULL,claim_expires_at=NULL WHERE to_email=(SELECT email FROM users WHERE id=$1) AND template='verify_email' AND status='pending'",
    ] {
        sqlx::query(query)
            .bind(user)
            .execute(&mut *connection)
            .await?;
    }
    Ok(())
}

/// Keeps SQL/credential details out of both responses and diagnostic logging.
fn unavailable(_: sqlx::Error) -> StatusCode {
    StatusCode::SERVICE_UNAVAILABLE
}

#[cfg(test)]
mod tests;
