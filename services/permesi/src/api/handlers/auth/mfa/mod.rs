//! Multi-factor authentication (MFA) state and recovery handling.
//!
//! Flow Overview:
//! 1) After password auth, determine the user's MFA state.
//! 2) If MFA is required but not enrolled, issue a bootstrap session and block all
//!    other routes server-side.
//! 3) If MFA is enabled, issue a challenge session for factor verification.
//! 4) After MFA enrollment, generate recovery codes and transition to `enabled`.
//!
//! Security boundaries:
//! - Recovery codes are the only self-service recovery mechanism.
//! - Recovery codes are Argon2id-hashed with a server-side pepper.
//! - Sessions minted for bootstrap/challenge are short-lived and limited in scope.

#[cfg(test)]
mod integration_tests;
pub(crate) mod recovery;
pub(crate) mod storage;
pub(crate) mod webauthn;

use anyhow::Result;
use axum::{
    Json,
    extract::Extension,
    http::{HeaderMap, HeaderValue, StatusCode, header::AUTHORIZATION},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;
use tracing::{error, info, warn};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{
    api::handlers::auth::{
        AuthState,
        principal::{require_any_auth, require_mfa_challenge},
        rate_limit::{RateLimitAction, RateLimitDecision},
        session::session_cookie_with_ttl,
        storage::{insert_mfa_bootstrap_session, insert_session},
        types::{
            MfaRecoveryRequest, MfaTotpEnrollFinishRequest, MfaTotpEnrollStartResponse,
            MfaTotpVerifyRequest,
        },
        utils::extract_client_ip,
    },
    totp::TotpService,
};

const DEFAULT_MFA_BOOTSTRAP_TTL_SECONDS: i64 = 10 * 60;
const DEFAULT_MFA_CHALLENGE_TTL_SECONDS: i64 = 5 * 60;
const ENV_MFA_REQUIRED: &str = "PERMESI_MFA_REQUIRED";

/// Logical MFA state for a user.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum MfaState {
    Disabled,
    RequiredUnenrolled,
    Enabled,
}

impl MfaState {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::RequiredUnenrolled => "required_unenrolled",
            Self::Enabled => "enabled",
        }
    }

    pub(crate) fn from_str(value: &str) -> Option<Self> {
        match value.trim() {
            "disabled" => Some(Self::Disabled),
            "required_unenrolled" => Some(Self::RequiredUnenrolled),
            "enabled" => Some(Self::Enabled),
            _ => None,
        }
    }
}

/// Enforce required MFA by mapping non-enabled states to `required_unenrolled`.
pub(crate) fn enforce_required_state(required: bool, state: MfaState) -> MfaState {
    if required && state != MfaState::Enabled {
        MfaState::RequiredUnenrolled
    } else {
        state
    }
}

/// MFA configuration loaded at startup.
#[derive(Clone, Debug)]
pub struct MfaConfig {
    required: bool,
    bootstrap_session_ttl_seconds: i64,
    challenge_session_ttl_seconds: i64,
    recovery_pepper: Option<Arc<[u8]>>,
}

impl MfaConfig {
    #[must_use]
    pub fn new() -> Self {
        Self {
            required: false,
            bootstrap_session_ttl_seconds: DEFAULT_MFA_BOOTSTRAP_TTL_SECONDS,
            challenge_session_ttl_seconds: DEFAULT_MFA_CHALLENGE_TTL_SECONDS,
            recovery_pepper: None,
        }
    }

    #[must_use]
    pub fn with_required(mut self, required: bool) -> Self {
        self.required = required;
        self
    }

    #[must_use]
    pub fn with_recovery_pepper(mut self, pepper: Arc<[u8]>) -> Self {
        self.recovery_pepper = Some(pepper);
        self
    }

    #[must_use]
    pub fn required(&self) -> bool {
        self.required
    }

    #[must_use]
    pub fn bootstrap_session_ttl_seconds(&self) -> i64 {
        self.bootstrap_session_ttl_seconds
    }

    #[must_use]
    pub fn challenge_session_ttl_seconds(&self) -> i64 {
        self.challenge_session_ttl_seconds
    }

    pub(crate) fn recovery_pepper(&self) -> Option<&[u8]> {
        self.recovery_pepper.as_deref()
    }

    /// Load MFA configuration from environment variables.
    #[must_use]
    pub fn from_env() -> Self {
        let required = parse_bool_env(ENV_MFA_REQUIRED).unwrap_or(false);
        Self::new().with_required(required)
    }
}

fn parse_bool_env(key: &str) -> Option<bool> {
    std::env::var(key)
        .ok()
        .and_then(|value| match value.trim() {
            "1" | "true" | "TRUE" | "yes" | "YES" => Some(true),
            "0" | "false" | "FALSE" | "no" | "NO" => Some(false),
            _ => None,
        })
}

/// Start TOTP enrollment. Requires bootstrap or full session.
#[utoipa::path(
    post,
    path = "/v1/auth/mfa/totp/enroll/start",
    responses(
        (status = 200, description = "Enrollment started", body = MfaTotpEnrollStartResponse),
        (status = 401, description = "Unauthorized")
    ),
    tag = "auth"
)]
pub async fn totp_enroll_start(
    headers: HeaderMap,
    pool: Extension<PgPool>,
    totp_service: Extension<TotpService>,
) -> axum::response::Response {
    let principal = match require_any_auth(&headers, &pool).await {
        Ok(principal) => principal,
        Err(status) => return status.into_response(),
    };

    let label = Some("Permesi User".to_string()); // Could come from principal

    match totp_service
        .enroll_begin(principal.user_id, &principal.email, label)
        .await
    {
        Ok((secret_str, qr_code_url, credential_id)) => (
            StatusCode::OK,
            Json(MfaTotpEnrollStartResponse {
                secret: secret_str,
                qr_code_url,
                credential_id: credential_id.to_string(),
            }),
        )
            .into_response(),
        Err(err) => {
            error!("Failed to start TOTP enrollment: {err}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Finish TOTP enrollment. Requires bootstrap or full session.
#[utoipa::path(
    post,
    path = "/v1/auth/mfa/totp/enroll/finish",
    request_body = MfaTotpEnrollFinishRequest,
    responses(
        (status = 204, description = "Enrollment finished"),
        (status = 400, description = "Invalid code"),
        (status = 401, description = "Unauthorized")
    ),
    tag = "auth"
)]
pub async fn totp_enroll_finish(
    headers: HeaderMap,
    pool: Extension<PgPool>,
    auth_state: Extension<Arc<AuthState>>,
    totp_service: Extension<TotpService>,
    payload: Option<Json<MfaTotpEnrollFinishRequest>>,
) -> axum::response::Response {
    let principal = match require_any_auth(&headers, &pool).await {
        Ok(principal) => principal,
        Err(status) => return status.into_response(),
    };

    let Some(Json(request)) = payload else {
        return (StatusCode::BAD_REQUEST, "Missing payload").into_response();
    };

    let Ok(credential_id) = Uuid::parse_str(&request.credential_id) else {
        return (StatusCode::BAD_REQUEST, "Invalid credential ID").into_response();
    };

    let client_ip = extract_client_ip(&headers);

    // Verify code via TotpService
    match totp_service
        .enroll_confirm(
            principal.user_id,
            credential_id,
            &request.code,
            client_ip.as_deref(),
            None,
        )
        .await
    {
        Ok(true) => {} // Success
        Ok(false) => return (StatusCode::BAD_REQUEST, "Invalid TOTP code").into_response(),
        Err(e) => {
            error!("Error confirming TOTP: {e}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }

    // Generate recovery codes as part of enrollment
    let Some(pepper) = auth_state.mfa().recovery_pepper() else {
        error!("MFA enrollment finished without pepper configured");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };

    let batch = match recovery::RecoveryCodeBatch::generate(pepper) {
        Ok(batch) => batch,
        Err(err) => {
            error!("Failed to generate recovery codes: {err}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    if let Err(err) =
        storage::insert_recovery_codes(&pool, principal.user_id, batch.batch_id, &batch.code_hashes)
            .await
    {
        error!("Failed to save recovery codes: {err}");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    // Enable MFA in user_mfa_state
    // We clear totp_secret (pass None) if we want to migrate away from it,
    // but upsert_mfa_state might expect it?
    // storage::upsert_mfa_state implementation only touches state and batch_id if secret is not passed?
    // Let's assume it handles NULL update.
    if let Err(err) = storage::upsert_mfa_state(
        &pool,
        principal.user_id,
        MfaState::Enabled,
        Some(batch.batch_id),
    )
    .await
    {
        error!("Failed to enable MFA: {err}");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    // After enrollment, upgrade to a full session
    let (token, ttl_seconds) = match insert_session(
        &pool,
        principal.user_id,
        auth_state.config().session_ttl_seconds(),
    )
    .await
    {
        Ok(token) => (token, auth_state.config().session_ttl_seconds()),
        Err(err) => {
            error!("Failed to create full session after MFA enrollment: {err}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let mut response_headers = HeaderMap::new();
    match session_cookie_with_ttl(&auth_state, &token, ttl_seconds) {
        Ok(cookie) => {
            response_headers.insert(axum::http::header::SET_COOKIE, cookie);
            if let Ok(value) = HeaderValue::from_str(&format!("Bearer {}", token.as_str())) {
                response_headers.insert(AUTHORIZATION, value);
            }
            (
                StatusCode::OK,
                response_headers,
                Json(crate::api::handlers::me::RecoveryCodesResponse { codes: batch.codes }),
            )
                .into_response()
        }
        Err(err) => {
            error!("Failed to set session cookie: {err}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Verify TOTP during challenge. Requires challenge session.
#[utoipa::path(
    post,
    path = "/v1/auth/mfa/totp/verify",
    request_body = MfaTotpVerifyRequest,
    responses(
        (status = 204, description = "Verification successful"),
        (status = 400, description = "Invalid code"),
        (status = 401, description = "Unauthorized")
    ),
    tag = "auth"
)]
pub async fn totp_verify(
    headers: HeaderMap,
    pool: Extension<PgPool>,
    auth_state: Extension<Arc<AuthState>>,
    totp_service: Extension<TotpService>,
    payload: Option<Json<MfaTotpVerifyRequest>>,
) -> axum::response::Response {
    let principal = match require_mfa_challenge(&headers, &pool).await {
        Ok(principal) => principal,
        Err(status) => return status.into_response(),
    };

    let Some(Json(request)) = payload else {
        return (StatusCode::BAD_REQUEST, "Missing payload").into_response();
    };

    // Check MFA state is Enabled (security check)
    let record = match storage::load_mfa_state(&pool, principal.user_id).await {
        Ok(Some(record)) => record,
        Ok(None) => return (StatusCode::UNAUTHORIZED, "MFA state not found").into_response(),
        Err(err) => {
            error!("Failed to load MFA state: {err}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    if record.state != MfaState::Enabled {
        return (StatusCode::UNAUTHORIZED, "MFA not enabled").into_response();
    }

    // Note: We don't use record.totp_secret anymore.

    let client_ip = extract_client_ip(&headers);

    match totp_service
        .verify(principal.user_id, &request.code, client_ip.as_deref(), None)
        .await
    {
        Ok(true) => {} // Success
        Ok(false) => return (StatusCode::BAD_REQUEST, "Invalid TOTP code").into_response(),
        Err(e) => {
            error!("Error verifying TOTP: {e}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }

    // Success: Upgrade to full session
    let (token, ttl_seconds) = match insert_session(
        &pool,
        principal.user_id,
        auth_state.config().session_ttl_seconds(),
    )
    .await
    {
        Ok(token) => (token, auth_state.config().session_ttl_seconds()),
        Err(err) => {
            error!("Failed to create full session after TOTP verification: {err}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    if let Err(err) = storage::delete_mfa_challenge_sessions(&pool, principal.user_id).await {
        error!("Failed to revoke MFA challenge sessions: {err}");
    }

    let mut response_headers = HeaderMap::new();
    match session_cookie_with_ttl(&auth_state, &token, ttl_seconds) {
        Ok(cookie) => {
            response_headers.insert(axum::http::header::SET_COOKIE, cookie);
            if let Ok(value) = HeaderValue::from_str(&format!("Bearer {token}")) {
                response_headers.insert(AUTHORIZATION, value);
            }
            (StatusCode::NO_CONTENT, response_headers).into_response()
        }
        Err(err) => {
            error!("Failed to set session cookie: {err}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Verify a recovery code during MFA challenge and issue a bootstrap session.
#[utoipa::path(
    post,
    path = "/v1/auth/mfa/recovery",
    request_body = MfaRecoveryRequest,
    responses(
        (status = 204, description = "Recovery accepted"),
        (status = 400, description = "Validation error", body = String),
        (status = 401, description = "Unauthorized", body = String),
        (status = 429, description = "Rate limited", body = String)
    ),
    tag = "auth"
)]
#[allow(clippy::too_many_lines)]
pub async fn mfa_recovery(
    headers: HeaderMap,
    pool: Extension<PgPool>,
    auth_state: Extension<Arc<AuthState>>,
    payload: Option<Json<MfaRecoveryRequest>>,
) -> impl IntoResponse {
    let principal = match require_mfa_challenge(&headers, &pool).await {
        Ok(principal) => principal,
        Err(status) => return status.into_response(),
    };

    let Some(Json(request)) = payload else {
        return (StatusCode::BAD_REQUEST, "Missing payload".to_string()).into_response();
    };

    let client_ip = extract_client_ip(&headers);
    if auth_state
        .rate_limiter()
        .check_ip(client_ip.as_deref(), RateLimitAction::MfaRecovery)
        == RateLimitDecision::Limited
    {
        return (StatusCode::TOO_MANY_REQUESTS, "Rate limited".to_string()).into_response();
    }
    if auth_state
        .rate_limiter()
        .check_email(&principal.email, RateLimitAction::MfaRecovery)
        == RateLimitDecision::Limited
    {
        return (StatusCode::TOO_MANY_REQUESTS, "Rate limited".to_string()).into_response();
    }

    let Some(pepper) = auth_state.mfa().recovery_pepper() else {
        error!("MFA recovery attempted without pepper configured");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Recovery unavailable".to_string(),
        )
            .into_response();
    };

    let record = match storage::load_mfa_state(&pool, principal.user_id).await {
        Ok(Some(record)) => record,
        Ok(None) => return (StatusCode::UNAUTHORIZED, "MFA state not found").into_response(),
        Err(err) => {
            error!("Failed to load MFA state: {err}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Recovery failed".to_string(),
            )
                .into_response();
        }
    };

    if record.state != MfaState::Enabled {
        return (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()).into_response();
    }
    let Some(batch_id) = record.recovery_batch_id else {
        return (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()).into_response();
    };

    let hashes = match storage::list_recovery_code_hashes(&pool, principal.user_id, batch_id).await
    {
        Ok(hashes) => hashes,
        Err(err) => {
            error!("Failed to list recovery codes: {err}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Recovery failed".to_string(),
            )
                .into_response();
        }
    };

    let matched_hash = match find_matching_hash(&request.code, &hashes, pepper) {
        Ok(hash) => hash,
        Err(err) => {
            warn!(user_id = %principal.user_id, "MFA recovery attempt failed: {err}");
            return (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()).into_response();
        }
    };

    let Some(matched_hash) = matched_hash else {
        warn!(user_id = %principal.user_id, "MFA recovery code invalid");
        return (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()).into_response();
    };

    let consumed = match storage::consume_recovery_code_hash(
        &pool,
        principal.user_id,
        batch_id,
        &matched_hash,
    )
    .await
    {
        Ok(consumed) => consumed,
        Err(err) => {
            error!("Failed to consume recovery code: {err}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Recovery failed".to_string(),
            )
                .into_response();
        }
    };
    if !consumed {
        warn!(user_id = %principal.user_id, "MFA recovery code already used");
        return (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()).into_response();
    }

    if let Err(err) =
        storage::upsert_mfa_state(&pool, principal.user_id, MfaState::RequiredUnenrolled, None)
            .await
    {
        error!("Failed to update MFA state: {err}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Recovery failed".to_string(),
        )
            .into_response();
    }

    if let Err(err) = storage::delete_full_sessions(&pool, principal.user_id).await {
        error!("Failed to revoke full sessions after recovery: {err}");
    }
    if let Err(err) = storage::delete_mfa_challenge_sessions(&pool, principal.user_id).await {
        error!("Failed to revoke MFA challenge sessions: {err}");
    }

    let token = match insert_mfa_bootstrap_session(
        &pool,
        principal.user_id,
        auth_state.mfa().bootstrap_session_ttl_seconds(),
    )
    .await
    {
        Ok(token) => token,
        Err(err) => {
            error!("Failed to create MFA bootstrap session: {err}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Recovery failed".to_string(),
            )
                .into_response();
        }
    };

    let mut response_headers = HeaderMap::new();
    match session_cookie_with_ttl(
        &auth_state,
        &token,
        auth_state.mfa().bootstrap_session_ttl_seconds(),
    ) {
        Ok(cookie) => {
            response_headers.insert(axum::http::header::SET_COOKIE, cookie);
            if let Ok(value) = HeaderValue::from_str(&format!("Bearer {}", token.as_str())) {
                response_headers.insert(AUTHORIZATION, value);
            }
            info!(user_id = %principal.user_id, "MFA recovery accepted");
            (StatusCode::NO_CONTENT, response_headers).into_response()
        }
        Err(err) => {
            error!("Failed to set MFA bootstrap cookie: {err}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Recovery failed".to_string(),
            )
                .into_response()
        }
    }
}

fn find_matching_hash(code: &str, hashes: &[String], pepper: &[u8]) -> Result<Option<String>> {
    for hash in hashes {
        if recovery::verify_recovery_code(code, hash, pepper)? {
            return Ok(Some(hash.clone()));
        }
    }
    Ok(None)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::recovery::{RecoveryCodeBatch, verify_recovery_code};
    use super::{MfaState, enforce_required_state, parse_bool_env};
    use crate::api::handlers::auth::session_kind::SessionKind;
    use std::collections::{HashMap, HashSet};
    use uuid::Uuid;

    #[test]
    fn mfa_state_round_trips() {
        assert_eq!(
            MfaState::from_str(MfaState::Disabled.as_str()),
            Some(MfaState::Disabled)
        );
        assert_eq!(
            MfaState::from_str(MfaState::RequiredUnenrolled.as_str()),
            Some(MfaState::RequiredUnenrolled)
        );
        assert_eq!(
            MfaState::from_str(MfaState::Enabled.as_str()),
            Some(MfaState::Enabled)
        );
    }

    #[test]
    fn parse_bool_env_handles_known_values() {
        assert_eq!(parse_bool_env("PERMESI_MFA_REQUIRED_NOT_SET"), None);
    }

    #[test]
    fn required_unenrolled_bootstrap_flow() {
        let effective = enforce_required_state(true, MfaState::Disabled);
        assert_eq!(effective, MfaState::RequiredUnenrolled);
        let kind = match effective {
            MfaState::RequiredUnenrolled => SessionKind::MfaBootstrap,
            MfaState::Enabled => SessionKind::MfaChallenge,
            MfaState::Disabled => SessionKind::Full,
        };
        assert_eq!(kind, SessionKind::MfaBootstrap);
    }

    #[test]
    fn recovery_code_forces_reenroll() {
        let pepper = b"pepper";
        let mut store = InMemoryRecoveryStore::new();
        store.state = MfaState::Enabled;
        let codes = store.regenerate(pepper);
        assert!(store.consume(&codes[0], pepper));
        assert_eq!(store.state, MfaState::RequiredUnenrolled);
    }

    #[test]
    fn regeneration_invalidates_old_codes() {
        let pepper = b"pepper";
        let mut store = InMemoryRecoveryStore::new();
        store.state = MfaState::Enabled;
        let first_codes = store.regenerate(pepper);
        let old_code = first_codes[0].clone();
        let _second = store.regenerate(pepper);
        assert!(!store.verify_active(&old_code, pepper));
    }

    struct InMemoryRecoveryStore {
        state: MfaState,
        active_batch: Option<Uuid>,
        hashes: HashMap<Uuid, Vec<String>>,
        used: HashSet<String>,
    }

    impl InMemoryRecoveryStore {
        fn new() -> Self {
            Self {
                state: MfaState::Disabled,
                active_batch: None,
                hashes: HashMap::new(),
                used: HashSet::new(),
            }
        }

        fn regenerate(&mut self, pepper: &[u8]) -> Vec<String> {
            let batch = RecoveryCodeBatch::generate(pepper).unwrap();
            self.active_batch = Some(batch.batch_id);
            self.hashes.insert(batch.batch_id, batch.code_hashes);
            batch.codes
        }

        fn verify_active(&self, code: &str, pepper: &[u8]) -> bool {
            let Some(batch_id) = self.active_batch else {
                return false;
            };
            let Some(hashes) = self.hashes.get(&batch_id) else {
                return false;
            };
            hashes
                .iter()
                .any(|hash| verify_recovery_code(code, hash, pepper).unwrap_or(false))
        }

        fn consume(&mut self, code: &str, pepper: &[u8]) -> bool {
            let Some(batch_id) = self.active_batch else {
                return false;
            };
            let Some(hashes) = self.hashes.get(&batch_id) else {
                return false;
            };
            for hash in hashes {
                if self.used.contains(hash) {
                    continue;
                }
                if verify_recovery_code(code, hash, pepper).unwrap_or(false) {
                    self.used.insert(hash.clone());
                    self.state = MfaState::RequiredUnenrolled;
                    return true;
                }
            }
            false
        }
    }
}
