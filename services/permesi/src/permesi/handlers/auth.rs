use crate::permesi::APP_USER_AGENT;
use anyhow::{Context, Result, anyhow};
use axum::{
    Json,
    extract::Extension,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use base64::Engine;
use opaque_ke::{
    CipherSuite, CredentialFinalization, CredentialRequest, Identifiers, RegistrationRequest,
    RegistrationUpload, ServerLogin, ServerLoginStartParameters, ServerRegistration, ServerSetup,
    key_exchange::tripledh::TripleDh,
};
use rand::{RngCore, SeedableRng, rngs::OsRng};
use rand_chacha::ChaCha20Rng;
use regex::Regex;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::{Instrument, error, info_span};
use unicode_normalization::UnicodeNormalization;
use utoipa::ToSchema;
use uuid::Uuid;

const ZERO_TOKEN_HEADER: &str = "x-permesi-zero-token";
const DEFAULT_TOKEN_TTL_SECONDS: i64 = 30 * 60;
const DEFAULT_RESEND_COOLDOWN_SECONDS: i64 = 60;
const DEFAULT_OPAQUE_LOGIN_TTL_SECONDS: u64 = 5 * 60;
const DEFAULT_OPAQUE_KV_MOUNT: &str = "kv";
const DEFAULT_OPAQUE_KV_PATH: &str = "permesi/opaque";
const DEFAULT_OPAQUE_SERVER_ID: &str = "api.permesi.dev";
const USERNAME_MIN_LENGTH: usize = 3;
const USERNAME_MAX_LENGTH: usize = 32;

#[derive(Clone, Debug)]
pub struct AuthConfig {
    zero_token_validate_url: String,
    frontend_base_url: String,
    email_token_ttl_seconds: i64,
    resend_cooldown_seconds: i64,
    opaque_kv_mount: String,
    opaque_kv_path: String,
    opaque_server_id: String,
    opaque_login_ttl_seconds: u64,
}

impl AuthConfig {
    #[must_use]
    pub fn new(zero_token_validate_url: String, frontend_base_url: String) -> Self {
        Self {
            zero_token_validate_url,
            frontend_base_url,
            email_token_ttl_seconds: DEFAULT_TOKEN_TTL_SECONDS,
            resend_cooldown_seconds: DEFAULT_RESEND_COOLDOWN_SECONDS,
            opaque_kv_mount: DEFAULT_OPAQUE_KV_MOUNT.to_string(),
            opaque_kv_path: DEFAULT_OPAQUE_KV_PATH.to_string(),
            opaque_server_id: DEFAULT_OPAQUE_SERVER_ID.to_string(),
            opaque_login_ttl_seconds: DEFAULT_OPAQUE_LOGIN_TTL_SECONDS,
        }
    }

    #[must_use]
    pub fn with_email_token_ttl_seconds(mut self, seconds: i64) -> Self {
        self.email_token_ttl_seconds = seconds;
        self
    }

    #[must_use]
    pub fn with_resend_cooldown_seconds(mut self, seconds: i64) -> Self {
        self.resend_cooldown_seconds = seconds;
        self
    }

    #[must_use]
    pub fn with_opaque_kv_mount(mut self, mount: String) -> Self {
        self.opaque_kv_mount = mount;
        self
    }

    #[must_use]
    pub fn with_opaque_kv_path(mut self, path: String) -> Self {
        self.opaque_kv_path = path;
        self
    }

    #[must_use]
    pub fn with_opaque_server_id(mut self, server_id: String) -> Self {
        self.opaque_server_id = server_id;
        self
    }

    #[must_use]
    pub fn with_opaque_login_ttl_seconds(mut self, seconds: u64) -> Self {
        self.opaque_login_ttl_seconds = seconds;
        self
    }

    #[must_use]
    pub fn opaque_kv_mount(&self) -> &str {
        &self.opaque_kv_mount
    }

    #[must_use]
    pub fn opaque_kv_path(&self) -> &str {
        &self.opaque_kv_path
    }

    #[must_use]
    pub fn opaque_server_id(&self) -> &str {
        &self.opaque_server_id
    }

    #[must_use]
    pub fn opaque_login_ttl_seconds(&self) -> u64 {
        self.opaque_login_ttl_seconds
    }
}

struct OpaqueSuite;

impl CipherSuite for OpaqueSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeGroup = opaque_ke::Ristretto255;
    type KeyExchange = TripleDh;
    type Ksf = argon2::Argon2<'static>;
}

struct OpaqueLoginState {
    state: ServerLogin<OpaqueSuite>,
    user_id: Option<Uuid>,
    created_at: Instant,
}

pub struct OpaqueState {
    server_setup: ServerSetup<OpaqueSuite>,
    server_id: Vec<u8>,
    login_ttl: Duration,
    login_states: Mutex<HashMap<Uuid, OpaqueLoginState>>,
}

impl OpaqueState {
    pub fn from_seed(seed: [u8; 32], server_id: String, login_ttl: Duration) -> Self {
        let mut rng = ChaCha20Rng::from_seed(seed);
        let server_setup = ServerSetup::<OpaqueSuite>::new(&mut rng);
        Self {
            server_setup,
            server_id: server_id.into_bytes(),
            login_ttl,
            login_states: Mutex::new(HashMap::new()),
        }
    }

    fn server_setup(&self) -> &ServerSetup<OpaqueSuite> {
        &self.server_setup
    }

    fn server_id(&self) -> &[u8] {
        &self.server_id
    }

    async fn store_login_state(
        &self,
        state: ServerLogin<OpaqueSuite>,
        user_id: Option<Uuid>,
    ) -> Uuid {
        let login_id = Uuid::new_v4();
        let mut states = self.login_states.lock().await;
        states.retain(|_, entry| entry.created_at.elapsed() < self.login_ttl);
        states.insert(
            login_id,
            OpaqueLoginState {
                state,
                user_id,
                created_at: Instant::now(),
            },
        );
        login_id
    }

    async fn take_login_state(&self, login_id: Uuid) -> Option<OpaqueLoginState> {
        let mut states = self.login_states.lock().await;
        if let Some(state) = states.remove(&login_id)
            && state.created_at.elapsed() < self.login_ttl
        {
            Some(state)
        } else {
            None
        }
    }
}

pub struct AuthState {
    config: AuthConfig,
    opaque: OpaqueState,
    client: Client,
    rate_limiter: Arc<dyn RateLimiter>,
}

impl AuthState {
    /// # Errors
    /// Returns an error if the HTTP client cannot be created.
    pub fn new(
        config: AuthConfig,
        opaque: OpaqueState,
        rate_limiter: Arc<dyn RateLimiter>,
    ) -> Result<Self> {
        let client = Client::builder()
            .user_agent(APP_USER_AGENT)
            .timeout(Duration::from_secs(5))
            .build()
            .context("failed to build auth HTTP client")?;
        Ok(Self {
            config,
            opaque,
            client,
            rate_limiter,
        })
    }

    #[must_use]
    pub fn config(&self) -> &AuthConfig {
        &self.config
    }

    #[must_use]
    pub fn opaque(&self) -> &OpaqueState {
        &self.opaque
    }
}

#[derive(Clone, Copy, Debug)]
pub enum RateLimitAction {
    Signup,
    Login,
    VerifyEmail,
    ResendVerification,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RateLimitDecision {
    Allowed,
    Limited,
}

pub trait RateLimiter: Send + Sync {
    fn check_ip(&self, ip: Option<&str>, action: RateLimitAction) -> RateLimitDecision;
    fn check_email(&self, email: &str, action: RateLimitAction) -> RateLimitDecision;
}

#[derive(Clone, Debug)]
pub struct NoopRateLimiter;

impl RateLimiter for NoopRateLimiter {
    fn check_ip(&self, _ip: Option<&str>, _action: RateLimitAction) -> RateLimitDecision {
        RateLimitDecision::Allowed
    }

    fn check_email(&self, _email: &str, _action: RateLimitAction) -> RateLimitDecision {
        RateLimitDecision::Allowed
    }
}

#[derive(ToSchema, Serialize, Deserialize, Debug)]
pub struct OpaqueSignupStartRequest {
    pub username: String,
    pub email: String,
    pub registration_request: String,
}

#[derive(ToSchema, Serialize, Deserialize, Debug)]
pub struct OpaqueSignupStartResponse {
    pub registration_response: String,
}

#[derive(ToSchema, Serialize, Deserialize, Debug)]
pub struct OpaqueSignupFinishRequest {
    pub username: String,
    pub email: String,
    pub registration_record: String,
}

#[derive(ToSchema, Serialize, Deserialize, Debug)]
pub struct OpaqueSignupFinishResponse {
    pub message: String,
}

#[derive(ToSchema, Serialize, Deserialize, Debug)]
pub struct OpaqueLoginStartRequest {
    pub email: String,
    pub credential_request: String,
}

#[derive(ToSchema, Serialize, Deserialize, Debug)]
pub struct OpaqueLoginStartResponse {
    pub login_id: String,
    pub credential_response: String,
}

#[derive(ToSchema, Serialize, Deserialize, Debug)]
pub struct OpaqueLoginFinishRequest {
    pub login_id: String,
    pub email: String,
    pub credential_finalization: String,
}

#[derive(ToSchema, Serialize, Deserialize, Debug)]
pub struct OpaqueLoginFinishResponse {
    pub message: String,
}

#[derive(ToSchema, Serialize, Deserialize, Debug)]
pub struct VerifyEmailRequest {
    pub token: String,
}

#[derive(ToSchema, Serialize, Deserialize, Debug)]
pub struct ResendVerificationRequest {
    pub email: String,
}

#[derive(Debug)]
enum SignupOutcome {
    Created,
    Conflict,
}

#[derive(Debug)]
enum ResendOutcome {
    Queued,
    Cooldown,
    Noop,
}

#[utoipa::path(
    post,
    path = "/v1/auth/opaque/signup/start",
    request_body = OpaqueSignupStartRequest,
    params(
        ("X-Permesi-Zero-Token" = String, Header, description = "Genesis zero token")
    ),
    responses(
        (status = 200, description = "OPAQUE signup started", body = OpaqueSignupStartResponse),
        (status = 400, description = "Validation error", body = String),
        (status = 429, description = "Rate limited", body = String)
    ),
    tag = "auth"
)]
pub async fn opaque_signup_start(
    headers: HeaderMap,
    auth_state: Extension<Arc<AuthState>>,
    payload: Option<Json<OpaqueSignupStartRequest>>,
) -> impl IntoResponse {
    let request: OpaqueSignupStartRequest = match payload {
        Some(Json(payload)) => payload,
        None => return (StatusCode::BAD_REQUEST, "Missing payload".to_string()).into_response(),
    };

    let username = request.username.trim().to_string();
    let email = request.email.trim().to_string();

    let username_normalized = normalize_username(&username);
    if !valid_username(&username_normalized) {
        return (StatusCode::BAD_REQUEST, "Invalid username".to_string()).into_response();
    }

    let email_normalized = normalize_email(&email);
    if !valid_email(&email_normalized) {
        return (StatusCode::BAD_REQUEST, "Invalid email".to_string()).into_response();
    }

    let client_ip = extract_client_ip(&headers);
    if auth_state
        .rate_limiter
        .check_ip(client_ip.as_deref(), RateLimitAction::Signup)
        == RateLimitDecision::Limited
    {
        return (StatusCode::TOO_MANY_REQUESTS, "Rate limited".to_string()).into_response();
    }
    if auth_state
        .rate_limiter
        .check_email(&email_normalized, RateLimitAction::Signup)
        == RateLimitDecision::Limited
    {
        return (StatusCode::TOO_MANY_REQUESTS, "Rate limited".to_string()).into_response();
    }

    if let Err(err) = require_zero_token(&headers, &auth_state).await {
        if let ZeroTokenError::Unavailable(ref inner) = err {
            error!("Zero token validation failed: {inner}");
        }
        let (status, message) = zero_token_error_response(&err);
        return (status, message).into_response();
    }

    let request_bytes = match decode_base64_field(&request.registration_request) {
        Ok(bytes) => bytes,
        Err(err) => return (StatusCode::BAD_REQUEST, err).into_response(),
    };

    let Ok(registration_request) = RegistrationRequest::<OpaqueSuite>::deserialize(&request_bytes)
    else {
        return (
            StatusCode::BAD_REQUEST,
            "Invalid registration request".to_string(),
        )
            .into_response();
    };

    let Ok(response) = ServerRegistration::start(
        auth_state.opaque().server_setup(),
        registration_request,
        email_normalized.as_bytes(),
    ) else {
        return (
            StatusCode::BAD_REQUEST,
            "Invalid registration request".to_string(),
        )
            .into_response();
    };

    let registration_response =
        base64::engine::general_purpose::STANDARD.encode(response.message.serialize());
    (
        StatusCode::OK,
        Json(OpaqueSignupStartResponse {
            registration_response,
        }),
    )
        .into_response()
}

#[utoipa::path(
    post,
    path = "/v1/auth/opaque/signup/finish",
    request_body = OpaqueSignupFinishRequest,
    params(
        ("X-Permesi-Zero-Token" = String, Header, description = "Genesis zero token")
    ),
    responses(
        (status = 201, description = "Signup accepted", body = OpaqueSignupFinishResponse),
        (status = 400, description = "Validation error", body = String),
        (status = 429, description = "Rate limited", body = String)
    ),
    tag = "auth"
)]
pub async fn opaque_signup_finish(
    headers: HeaderMap,
    pool: Extension<PgPool>,
    auth_state: Extension<Arc<AuthState>>,
    payload: Option<Json<OpaqueSignupFinishRequest>>,
) -> impl IntoResponse {
    let request: OpaqueSignupFinishRequest = match payload {
        Some(Json(payload)) => payload,
        None => return (StatusCode::BAD_REQUEST, "Missing payload".to_string()).into_response(),
    };

    let username = request.username.trim().to_string();
    let email = request.email.trim().to_string();

    let username_normalized = normalize_username(&username);
    if !valid_username(&username_normalized) {
        return (StatusCode::BAD_REQUEST, "Invalid username".to_string()).into_response();
    }

    let email_normalized = normalize_email(&email);
    if !valid_email(&email_normalized) {
        return (StatusCode::BAD_REQUEST, "Invalid email".to_string()).into_response();
    }

    let client_ip = extract_client_ip(&headers);
    if auth_state
        .rate_limiter
        .check_ip(client_ip.as_deref(), RateLimitAction::Signup)
        == RateLimitDecision::Limited
    {
        return (StatusCode::TOO_MANY_REQUESTS, "Rate limited".to_string()).into_response();
    }
    if auth_state
        .rate_limiter
        .check_email(&email_normalized, RateLimitAction::Signup)
        == RateLimitDecision::Limited
    {
        return (StatusCode::TOO_MANY_REQUESTS, "Rate limited".to_string()).into_response();
    }

    if let Err(err) = require_zero_token(&headers, &auth_state).await {
        if let ZeroTokenError::Unavailable(ref inner) = err {
            error!("Zero token validation failed: {inner}");
        }
        let (status, message) = zero_token_error_response(&err);
        return (status, message).into_response();
    }

    let record_bytes = match decode_base64_field(&request.registration_record) {
        Ok(bytes) => bytes,
        Err(err) => return (StatusCode::BAD_REQUEST, err).into_response(),
    };

    let Ok(registration_upload) = RegistrationUpload::<OpaqueSuite>::deserialize(&record_bytes)
    else {
        return (
            StatusCode::BAD_REQUEST,
            "Invalid registration record".to_string(),
        )
            .into_response();
    };

    let password_file = ServerRegistration::finish(registration_upload);
    let opaque_record = password_file.serialize().to_vec();

    let outcome = insert_user_and_verification(
        &pool,
        &username,
        &username_normalized,
        &email,
        &email_normalized,
        &opaque_record,
        auth_state.config(),
    )
    .await;

    let message = "If the account can be created, you'll receive a verification email.".to_string();
    match outcome {
        Ok(SignupOutcome::Created | SignupOutcome::Conflict) => (
            StatusCode::CREATED,
            Json(OpaqueSignupFinishResponse { message }),
        )
            .into_response(),
        Err(err) => {
            error!("Signup failed: {err}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(OpaqueSignupFinishResponse {
                    message: "Signup failed".to_string(),
                }),
            )
                .into_response()
        }
    }
}

#[utoipa::path(
    post,
    path = "/v1/auth/opaque/login/start",
    request_body = OpaqueLoginStartRequest,
    params(
        ("X-Permesi-Zero-Token" = String, Header, description = "Genesis zero token")
    ),
    responses(
        (status = 200, description = "OPAQUE login started", body = OpaqueLoginStartResponse),
        (status = 400, description = "Validation error", body = String),
        (status = 429, description = "Rate limited", body = String)
    ),
    tag = "auth"
)]
pub async fn opaque_login_start(
    headers: HeaderMap,
    pool: Extension<PgPool>,
    auth_state: Extension<Arc<AuthState>>,
    payload: Option<Json<OpaqueLoginStartRequest>>,
) -> impl IntoResponse {
    let request: OpaqueLoginStartRequest = match payload {
        Some(Json(payload)) => payload,
        None => return (StatusCode::BAD_REQUEST, "Missing payload".to_string()).into_response(),
    };

    let email = request.email.trim().to_string();
    let email_normalized = normalize_email(&email);
    if !valid_email(&email_normalized) {
        return (StatusCode::BAD_REQUEST, "Invalid email".to_string()).into_response();
    }

    let client_ip = extract_client_ip(&headers);
    if auth_state
        .rate_limiter
        .check_ip(client_ip.as_deref(), RateLimitAction::Login)
        == RateLimitDecision::Limited
    {
        return (StatusCode::TOO_MANY_REQUESTS, "Rate limited".to_string()).into_response();
    }
    if auth_state
        .rate_limiter
        .check_email(&email_normalized, RateLimitAction::Login)
        == RateLimitDecision::Limited
    {
        return (StatusCode::TOO_MANY_REQUESTS, "Rate limited".to_string()).into_response();
    }

    if let Err(err) = require_zero_token(&headers, &auth_state).await {
        if let ZeroTokenError::Unavailable(ref inner) = err {
            error!("Zero token validation failed: {inner}");
        }
        let (status, message) = zero_token_error_response(&err);
        return (status, message).into_response();
    }

    let credential_bytes = match decode_base64_field(&request.credential_request) {
        Ok(bytes) => bytes,
        Err(err) => return (StatusCode::BAD_REQUEST, err).into_response(),
    };

    let Ok(credential_request) = CredentialRequest::<OpaqueSuite>::deserialize(&credential_bytes)
    else {
        return (
            StatusCode::BAD_REQUEST,
            "Invalid credential request".to_string(),
        )
            .into_response();
    };

    let response =
        match build_login_start_response(&pool, &auth_state, &email_normalized, credential_request)
            .await
        {
            Ok(response) => response,
            Err((status, message)) => return (status, message).into_response(),
        };

    (StatusCode::OK, Json(response)).into_response()
}

async fn build_login_start_response(
    pool: &PgPool,
    auth_state: &AuthState,
    email_normalized: &str,
    credential_request: CredentialRequest<OpaqueSuite>,
) -> Result<OpaqueLoginStartResponse, (StatusCode, String)> {
    let login_record = match lookup_login_record(pool, email_normalized).await {
        Ok(record) => record,
        Err(err) => {
            error!("Login lookup failed: {err}");
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Login failed".to_string(),
            ));
        }
    };

    let (password_file, user_id) = match login_record {
        Some(record) if record.status == "active" => {
            let password_file = ServerRegistration::deserialize(&record.opaque_record)
                .map_err(|_| anyhow!("Invalid stored registration record"));
            match password_file {
                Ok(file) => (Some(file), Some(record.user_id)),
                Err(err) => {
                    error!("Invalid registration record: {err}");
                    (None, None)
                }
            }
        }
        _ => (None, None),
    };

    let params = ServerLoginStartParameters {
        context: None,
        identifiers: Identifiers {
            client: Some(email_normalized.as_bytes()),
            server: Some(auth_state.opaque().server_id()),
        },
    };

    let mut rng = OsRng;
    let Ok(start_result) = ServerLogin::start(
        &mut rng,
        auth_state.opaque().server_setup(),
        password_file,
        credential_request,
        email_normalized.as_bytes(),
        params,
    ) else {
        return Err((
            StatusCode::BAD_REQUEST,
            "Invalid credential request".to_string(),
        ));
    };

    let login_id = auth_state
        .opaque()
        .store_login_state(start_result.state, user_id)
        .await;
    let credential_response =
        base64::engine::general_purpose::STANDARD.encode(start_result.message.serialize());

    Ok(OpaqueLoginStartResponse {
        login_id: login_id.to_string(),
        credential_response,
    })
}

#[utoipa::path(
    post,
    path = "/v1/auth/opaque/login/finish",
    request_body = OpaqueLoginFinishRequest,
    params(
        ("X-Permesi-Zero-Token" = String, Header, description = "Genesis zero token")
    ),
    responses(
        (status = 204, description = "Login success"),
        (status = 400, description = "Validation error", body = String),
        (status = 401, description = "Unauthorized", body = String)
    ),
    tag = "auth"
)]
pub async fn opaque_login_finish(
    headers: HeaderMap,
    auth_state: Extension<Arc<AuthState>>,
    payload: Option<Json<OpaqueLoginFinishRequest>>,
) -> impl IntoResponse {
    let request: OpaqueLoginFinishRequest = match payload {
        Some(Json(payload)) => payload,
        None => return (StatusCode::BAD_REQUEST, "Missing payload".to_string()).into_response(),
    };

    if let Err(err) = require_zero_token(&headers, &auth_state).await {
        if let ZeroTokenError::Unavailable(ref inner) = err {
            error!("Zero token validation failed: {inner}");
        }
        let (status, message) = zero_token_error_response(&err);
        return (status, message).into_response();
    }

    let Ok(login_id) = Uuid::parse_str(request.login_id.trim()) else {
        return (StatusCode::BAD_REQUEST, "Invalid login id".to_string()).into_response();
    };

    let credential_bytes = match decode_base64_field(&request.credential_finalization) {
        Ok(bytes) => bytes,
        Err(err) => return (StatusCode::BAD_REQUEST, err).into_response(),
    };

    let Ok(credential_finalization) =
        CredentialFinalization::<OpaqueSuite>::deserialize(&credential_bytes)
    else {
        return (
            StatusCode::BAD_REQUEST,
            "Invalid credential finalization".to_string(),
        )
            .into_response();
    };

    let Some(login_state) = auth_state.opaque().take_login_state(login_id).await else {
        return (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()).into_response();
    };

    if login_state.user_id.is_none() {
        return (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()).into_response();
    }

    match login_state.state.finish(credential_finalization) {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(_) => (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()).into_response(),
    }
}

#[utoipa::path(
    post,
    path = "/v1/auth/verify-email",
    request_body = VerifyEmailRequest,
    params(
        ("X-Permesi-Zero-Token" = String, Header, description = "Genesis zero token")
    ),
    responses(
        (status = 204, description = "Email verified"),
        (status = 400, description = "Invalid/expired token", body = String),
        (status = 429, description = "Rate limited", body = String)
    ),
    tag = "auth"
)]
pub async fn verify_email(
    headers: HeaderMap,
    pool: Extension<PgPool>,
    auth_state: Extension<Arc<AuthState>>,
    payload: Option<Json<VerifyEmailRequest>>,
) -> impl IntoResponse {
    let request: VerifyEmailRequest = match payload {
        Some(Json(payload)) => payload,
        None => return (StatusCode::BAD_REQUEST, "Missing payload".to_string()).into_response(),
    };

    let token = request.token.trim();
    if token.is_empty() {
        return (StatusCode::BAD_REQUEST, "Missing token".to_string()).into_response();
    }

    let client_ip = extract_client_ip(&headers);
    if auth_state
        .rate_limiter
        .check_ip(client_ip.as_deref(), RateLimitAction::VerifyEmail)
        == RateLimitDecision::Limited
    {
        return (StatusCode::TOO_MANY_REQUESTS, "Rate limited".to_string()).into_response();
    }

    if let Err(err) = require_zero_token(&headers, &auth_state).await {
        if let ZeroTokenError::Unavailable(ref inner) = err {
            error!("Zero token validation failed: {inner}");
        }
        let (status, message) = zero_token_error_response(&err);
        return (status, message).into_response();
    }

    let token_hash = hash_verification_token(token);
    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(err) => {
            error!("Failed to start verify-email transaction: {err}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Verification failed".to_string(),
            )
                .into_response();
        }
    };

    if let Ok(Some(email_normalized)) = lookup_email_by_token_hash(&mut tx, &token_hash).await
        && auth_state
            .rate_limiter
            .check_email(&email_normalized, RateLimitAction::VerifyEmail)
            == RateLimitDecision::Limited
    {
        let _ = tx.rollback().await;
        return (StatusCode::TOO_MANY_REQUESTS, "Rate limited".to_string()).into_response();
    }

    match consume_verification_token(&mut tx, &token_hash).await {
        Ok(true) => {
            if let Err(err) = tx.commit().await {
                error!("Failed to commit verify-email transaction: {err}");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Verification failed".to_string(),
                )
                    .into_response();
            }
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => {
            let _ = tx.rollback().await;
            (StatusCode::BAD_REQUEST, "Invalid token".to_string()).into_response()
        }
        Err(err) => {
            error!("Failed to verify email: {err}");
            let _ = tx.rollback().await;
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Verification failed".to_string(),
            )
                .into_response()
        }
    }
}

#[utoipa::path(
    post,
    path = "/v1/auth/resend-verification",
    request_body = ResendVerificationRequest,
    params(
        ("X-Permesi-Zero-Token" = String, Header, description = "Genesis zero token")
    ),
    responses(
        (status = 204, description = "Resend accepted")
    ),
    tag = "auth"
)]
pub async fn resend_verification(
    headers: HeaderMap,
    pool: Extension<PgPool>,
    auth_state: Extension<Arc<AuthState>>,
    payload: Option<Json<ResendVerificationRequest>>,
) -> impl IntoResponse {
    let request: ResendVerificationRequest = match payload {
        Some(Json(payload)) => payload,
        None => return (StatusCode::BAD_REQUEST, "Missing payload".to_string()).into_response(),
    };

    let email = request.email.trim().to_string();
    let email_normalized = normalize_email(&email);
    if !valid_email(&email_normalized) {
        return StatusCode::NO_CONTENT.into_response();
    }

    let client_ip = extract_client_ip(&headers);
    if auth_state
        .rate_limiter
        .check_ip(client_ip.as_deref(), RateLimitAction::ResendVerification)
        == RateLimitDecision::Limited
    {
        return StatusCode::NO_CONTENT.into_response();
    }
    if auth_state
        .rate_limiter
        .check_email(&email_normalized, RateLimitAction::ResendVerification)
        == RateLimitDecision::Limited
    {
        return StatusCode::NO_CONTENT.into_response();
    }

    if let Err(err) = require_zero_token(&headers, &auth_state).await {
        if let ZeroTokenError::Unavailable(ref inner) = err {
            error!("Zero token validation failed: {inner}");
        }
        return StatusCode::NO_CONTENT.into_response();
    }

    match enqueue_resend_verification(&pool, &email_normalized, auth_state.config()).await {
        Ok(ResendOutcome::Queued | ResendOutcome::Cooldown | ResendOutcome::Noop) => {
            StatusCode::NO_CONTENT.into_response()
        }
        Err(err) => {
            error!("Failed to enqueue resend verification: {err}");
            StatusCode::NO_CONTENT.into_response()
        }
    }
}

enum ZeroTokenValidation {
    Valid,
    Invalid,
}

#[derive(Debug)]
enum ZeroTokenError {
    Missing,
    Invalid,
    Unavailable(anyhow::Error),
}

async fn validate_zero_token(
    client: &Client,
    config: &AuthConfig,
    token: &str,
) -> Result<ZeroTokenValidation> {
    #[derive(Serialize)]
    struct ValidateRequest<'a> {
        token: &'a str,
    }

    let span = info_span!(
        "zero_token.validate",
        http.method = "POST",
        url = %config.zero_token_validate_url
    );
    async {
        let response = client
            .post(&config.zero_token_validate_url)
            .json(&ValidateRequest { token })
            .send()
            .await
            .context("failed to send zero token validation request")?;

        if response.status().is_success() {
            return Ok(ZeroTokenValidation::Valid);
        }

        if response.status().is_client_error() {
            return Ok(ZeroTokenValidation::Invalid);
        }

        Err(anyhow!(
            "zero token validation failed with status {}",
            response.status()
        ))
    }
    .instrument(span)
    .await
}

async fn require_zero_token(
    headers: &HeaderMap,
    auth_state: &AuthState,
) -> Result<(), ZeroTokenError> {
    let Some(zero_token) = extract_zero_token(headers) else {
        return Err(ZeroTokenError::Missing);
    };

    match validate_zero_token(&auth_state.client, auth_state.config(), &zero_token).await {
        Ok(ZeroTokenValidation::Valid) => Ok(()),
        Ok(ZeroTokenValidation::Invalid) => Err(ZeroTokenError::Invalid),
        Err(err) => Err(ZeroTokenError::Unavailable(err)),
    }
}

fn zero_token_error_response(err: &ZeroTokenError) -> (StatusCode, String) {
    match err {
        ZeroTokenError::Missing => (StatusCode::BAD_REQUEST, "Missing zero token".to_string()),
        ZeroTokenError::Invalid => (StatusCode::BAD_REQUEST, "Invalid token".to_string()),
        ZeroTokenError::Unavailable(_) => (
            StatusCode::BAD_GATEWAY,
            "Zero token validation unavailable".to_string(),
        ),
    }
}

fn extract_zero_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get(ZERO_TOKEN_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(str::to_string)
}

fn normalize_username(username: &str) -> String {
    let normalized = username.nfkc().collect::<String>();
    normalized.trim().to_lowercase()
}

fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

fn valid_username(username_normalized: &str) -> bool {
    let length = username_normalized.len();
    if !(USERNAME_MIN_LENGTH..=USERNAME_MAX_LENGTH).contains(&length) {
        return false;
    }
    Regex::new(r"^[a-z0-9][a-z0-9_-]*$").is_ok_and(|regex| regex.is_match(username_normalized))
}

fn valid_email(email_normalized: &str) -> bool {
    Regex::new(r"^[^@\s]+@[^@\s]+\.[^@\s]+$").is_ok_and(|regex| regex.is_match(email_normalized))
}

fn generate_verification_token() -> Result<String> {
    let mut bytes = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut bytes)
        .context("failed to generate verification token")?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

fn hash_verification_token(token: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hasher.finalize().to_vec()
}

fn build_verify_url(frontend_base_url: &str, token: &str) -> String {
    let base = frontend_base_url.trim_end_matches('/');
    format!("{base}/verify-email#token={token}")
}

fn decode_base64_field(value: &str) -> Result<Vec<u8>, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err("Missing opaque payload".to_string());
    }
    base64::engine::general_purpose::STANDARD
        .decode(trimmed)
        .map_err(|_| "Invalid base64 payload".to_string())
}

struct LoginRecord {
    user_id: Uuid,
    status: String,
    opaque_record: Vec<u8>,
}

async fn lookup_login_record(pool: &PgPool, email_normalized: &str) -> Result<Option<LoginRecord>> {
    let query = "SELECT id, status::text AS status, opaque_registration_record FROM users WHERE email_normalized = $1";
    let span = info_span!(
        "db.query",
        db.system = "postgresql",
        db.operation = "SELECT",
        db.statement = query
    );
    let row = sqlx::query(query)
        .bind(email_normalized)
        .fetch_optional(pool)
        .instrument(span)
        .await
        .context("failed to lookup login record")?;

    Ok(row.map(|row| LoginRecord {
        user_id: row.get("id"),
        status: row.get("status"),
        opaque_record: row.get("opaque_registration_record"),
    }))
}

async fn insert_user_and_verification(
    pool: &PgPool,
    username: &str,
    username_normalized: &str,
    email: &str,
    email_normalized: &str,
    opaque_record: &[u8],
    config: &AuthConfig,
) -> Result<SignupOutcome> {
    let mut tx = pool.begin().await.context("begin signup transaction")?;

    let query = r"
        INSERT INTO users
            (username, username_normalized, email, email_normalized, opaque_registration_record)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id
    ";
    let span = info_span!(
        "db.query",
        db.system = "postgresql",
        db.operation = "INSERT",
        db.statement = query
    );
    let row = sqlx::query(query)
        .bind(username)
        .bind(username_normalized)
        .bind(email)
        .bind(email_normalized)
        .bind(opaque_record)
        .fetch_one(&mut *tx)
        .instrument(span)
        .await;

    let user_id: Uuid = match row {
        Ok(row) => row.get("id"),
        Err(err) => {
            if is_unique_violation(&err) {
                let _ = tx.rollback().await;
                return Ok(SignupOutcome::Conflict);
            }
            return Err(err).context("failed to insert user");
        }
    };

    let _token = insert_verification_records(&mut tx, user_id, email, username, config).await?;

    tx.commit().await.context("commit signup transaction")?;

    Ok(SignupOutcome::Created)
}

async fn insert_verification_records(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
    email: &str,
    username: &str,
    config: &AuthConfig,
) -> Result<String> {
    let token = generate_verification_token()?;
    let token_hash = hash_verification_token(&token);

    let query = r"
        INSERT INTO email_verification_tokens
            (user_id, token_hash, expires_at)
        VALUES ($1, $2, NOW() + ($3 * INTERVAL '1 second'))
    ";
    let span = info_span!(
        "db.query",
        db.system = "postgresql",
        db.operation = "INSERT",
        db.statement = query
    );
    sqlx::query(query)
        .bind(user_id)
        .bind(token_hash)
        .bind(config.email_token_ttl_seconds)
        .execute(&mut **tx)
        .instrument(span)
        .await
        .context("failed to insert email verification token")?;

    let verify_url = build_verify_url(&config.frontend_base_url, &token);
    let payload_json = json!({
        "username": username,
        "verify_url": verify_url,
    });
    let payload_text =
        serde_json::to_string(&payload_json).context("failed to serialize email payload")?;

    let query = r"
        INSERT INTO email_outbox (to_email, template, payload_json)
        VALUES ($1, $2, $3::jsonb)
    ";
    let span = info_span!(
        "db.query",
        db.system = "postgresql",
        db.operation = "INSERT",
        db.statement = query
    );
    sqlx::query(query)
        .bind(email)
        .bind("verify_email")
        .bind(payload_text)
        .execute(&mut **tx)
        .instrument(span)
        .await
        .context("failed to insert email outbox row")?;

    Ok(token)
}

async fn consume_verification_token(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    token_hash: &[u8],
) -> Result<bool> {
    let query = r"
        UPDATE email_verification_tokens
        SET consumed_at = NOW()
        WHERE token_hash = $1
          AND consumed_at IS NULL
          AND expires_at > NOW()
        RETURNING user_id
    ";
    let span = info_span!(
        "db.query",
        db.system = "postgresql",
        db.operation = "UPDATE",
        db.statement = query
    );
    let row = sqlx::query(query)
        .bind(token_hash)
        .fetch_optional(&mut **tx)
        .instrument(span)
        .await
        .context("failed to consume verification token")?;

    let Some(row) = row else {
        return Ok(false);
    };

    let user_id: Uuid = row.get("user_id");
    let query = r"
        UPDATE users
        SET email_verified_at = NOW(),
            status = 'active',
            updated_at = NOW()
        WHERE id = $1
    ";
    let span = info_span!(
        "db.query",
        db.system = "postgresql",
        db.operation = "UPDATE",
        db.statement = query
    );
    sqlx::query(query)
        .bind(user_id)
        .execute(&mut **tx)
        .instrument(span)
        .await
        .context("failed to update user status")?;

    Ok(true)
}

async fn lookup_email_by_token_hash(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    token_hash: &[u8],
) -> Result<Option<String>> {
    let query = r"
        SELECT users.email_normalized
        FROM email_verification_tokens
        JOIN users ON users.id = email_verification_tokens.user_id
        WHERE email_verification_tokens.token_hash = $1
        LIMIT 1
    ";
    let span = info_span!(
        "db.query",
        db.system = "postgresql",
        db.operation = "SELECT",
        db.statement = query
    );
    let row = sqlx::query(query)
        .bind(token_hash)
        .fetch_optional(&mut **tx)
        .instrument(span)
        .await
        .context("failed to lookup email for token")?;
    Ok(row.map(|row| row.get("email_normalized")))
}

async fn enqueue_resend_verification(
    pool: &PgPool,
    email_normalized: &str,
    config: &AuthConfig,
) -> Result<ResendOutcome> {
    let mut tx = pool.begin().await.context("begin resend transaction")?;

    let query = r"
        SELECT id, email, username, status::text AS status
        FROM users
        WHERE email_normalized = $1
        LIMIT 1
    ";
    let span = info_span!(
        "db.query",
        db.system = "postgresql",
        db.operation = "SELECT",
        db.statement = query
    );
    let row = sqlx::query(query)
        .bind(email_normalized)
        .fetch_optional(&mut *tx)
        .instrument(span)
        .await
        .context("failed to lookup user for resend")?;

    let Some(row) = row else {
        tx.commit().await.context("commit resend noop")?;
        return Ok(ResendOutcome::Noop);
    };

    let status: String = row.get("status");
    if status != "pending_verification" {
        tx.commit().await.context("commit resend noop")?;
        return Ok(ResendOutcome::Noop);
    }

    let user_id: Uuid = row.get("id");
    if resend_cooldown_active(&mut tx, user_id, config.resend_cooldown_seconds).await? {
        tx.commit().await.context("commit resend cooldown")?;
        return Ok(ResendOutcome::Cooldown);
    }

    let email: String = row.get("email");
    let username: String = row.get("username");
    let _ = insert_verification_records(&mut tx, user_id, &email, &username, config).await?;
    tx.commit().await.context("commit resend enqueue")?;
    Ok(ResendOutcome::Queued)
}

async fn resend_cooldown_active(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
    cooldown_seconds: i64,
) -> Result<bool> {
    let query = r"
        SELECT 1
        FROM email_verification_tokens
        WHERE user_id = $1
          AND created_at > NOW() - ($2 * INTERVAL '1 second')
        LIMIT 1
    ";
    let span = info_span!(
        "db.query",
        db.system = "postgresql",
        db.operation = "SELECT",
        db.statement = query
    );
    let row = sqlx::query(query)
        .bind(user_id)
        .bind(cooldown_seconds)
        .fetch_optional(&mut **tx)
        .instrument(span)
        .await
        .context("failed to check resend cooldown")?;
    Ok(row.is_some())
}

fn is_unique_violation(err: &sqlx::Error) -> bool {
    match err {
        sqlx::Error::Database(db_err) => db_err.code().is_some_and(|code| code.as_ref() == "23505"),
        _ => false,
    }
}

fn extract_client_ip(headers: &HeaderMap) -> Option<String> {
    let forwarded = headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if forwarded.is_some() {
        return forwarded.map(str::to_string);
    }
    headers
        .get("x-real-ip")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use opaque_ke::{ClientRegistration, ClientRegistrationFinishParameters};
    use sqlx::{Connection, PgConnection, PgPool, Row, postgres::PgPoolOptions};
    use test_support::{TestNetwork, postgres::PostgresContainer, runtime};

    const PERMESI_SCHEMA_SQL: &str =
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/sql/schema.sql"));

    struct TestDb {
        _postgres: PostgresContainer,
        pool: PgPool,
    }

    impl TestDb {
        async fn new() -> Result<Self> {
            if let Err(err) = runtime::ensure_container_runtime() {
                eprintln!("Skipping integration test: {err}");
                return Err(err);
            }

            let network = TestNetwork::new("permesi-auth");
            let postgres = PostgresContainer::start(network.name()).await?;
            postgres.wait_until_ready().await?;
            apply_schema(&postgres).await?;

            let pool = PgPoolOptions::new()
                .max_connections(5)
                .connect(&postgres.admin_dsn())
                .await
                .context("failed to connect test pool")?;

            Ok(Self {
                _postgres: postgres,
                pool,
            })
        }
    }

    async fn apply_schema(postgres: &PostgresContainer) -> Result<()> {
        let mut connection = PgConnection::connect(&postgres.admin_dsn())
            .await
            .context("failed to connect for schema setup")?;

        for (index, statement) in split_sql_statements(PERMESI_SCHEMA_SQL).iter().enumerate() {
            sqlx::query(statement)
                .execute(&mut connection)
                .await
                .with_context(|| format!("failed to execute schema statement {}", index + 1))?;
        }

        Ok(())
    }

    fn split_sql_statements(sql: &str) -> Vec<String> {
        let mut statements = Vec::new();
        let mut current = String::new();

        for line in sql.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("\\ir ") {
                continue;
            }
            current.push_str(line);
            current.push('\n');

            if trimmed.ends_with(';') {
                let statement = current.trim();
                if !statement.is_empty() {
                    statements.push(statement.to_string());
                }
                current.clear();
            }
        }

        let leftover = current.trim();
        if !leftover.is_empty() {
            statements.push(leftover.to_string());
        }

        statements
    }

    fn auth_config() -> AuthConfig {
        AuthConfig::new(
            "http://genesis.test/v1/zero-token/validate".to_string(),
            "https://permesi.dev".to_string(),
        )
        .with_email_token_ttl_seconds(60)
        .with_resend_cooldown_seconds(300)
    }

    fn opaque_test_record() -> Result<Vec<u8>> {
        let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
        let server_setup = ServerSetup::<OpaqueSuite>::new(&mut rng);
        let password = b"CorrectHorseBatteryStaple";
        let client_start = ClientRegistration::<OpaqueSuite>::start(&mut rng, password)?;
        let server_start =
            ServerRegistration::start(&server_setup, client_start.message, b"test@example.com")?;
        let ksf = argon2::Argon2::default();
        let params = ClientRegistrationFinishParameters::new(
            Identifiers {
                client: Some(b"test@example.com"),
                server: Some(b"api.permesi.dev"),
            },
            Some(&ksf),
        );
        let client_finish =
            client_start
                .state
                .finish(&mut rng, password, server_start.message, params)?;
        let record = ServerRegistration::finish(client_finish.message);
        Ok(record.serialize().to_vec())
    }

    async fn lookup_user_id(pool: &PgPool, email_normalized: &str) -> Result<Uuid> {
        let row = sqlx::query("SELECT id FROM users WHERE email_normalized = $1")
            .bind(email_normalized)
            .fetch_one(pool)
            .await
            .context("failed to lookup user id")?;
        Ok(row.get("id"))
    }

    async fn issue_verification_token(
        pool: &PgPool,
        user_id: Uuid,
        email: &str,
        username: &str,
        config: &AuthConfig,
    ) -> Result<String> {
        let mut tx = pool.begin().await.context("begin token transaction")?;
        let token = insert_verification_records(&mut tx, user_id, email, username, config).await?;
        tx.commit().await.context("commit token transaction")?;
        Ok(token)
    }

    #[tokio::test]
    async fn signup_concurrent_username_unique() -> Result<()> {
        let Ok(db) = TestDb::new().await else {
            return Ok(());
        };

        let config = auth_config();
        let opaque_record = opaque_test_record()?;
        let username = "alice";
        let username_normalized = normalize_username(username);
        let email_one = "alice@example.com";
        let email_two = "alice2@example.com";
        let email_one_normalized = normalize_email(email_one);
        let email_two_normalized = normalize_email(email_two);

        let task_one = insert_user_and_verification(
            &db.pool,
            username,
            &username_normalized,
            email_one,
            &email_one_normalized,
            &opaque_record,
            &config,
        );
        let task_two = insert_user_and_verification(
            &db.pool,
            username,
            &username_normalized,
            email_two,
            &email_two_normalized,
            &opaque_record,
            &config,
        );

        let (result_one, result_two) = tokio::join!(task_one, task_two);
        let outcomes = [result_one?, result_two?];
        let successes = outcomes
            .iter()
            .filter(|outcome| matches!(outcome, SignupOutcome::Created))
            .count();
        let conflicts = outcomes
            .iter()
            .filter(|outcome| matches!(outcome, SignupOutcome::Conflict))
            .count();

        assert_eq!(successes, 1);
        assert_eq!(conflicts, 1);

        Ok(())
    }

    #[tokio::test]
    async fn verify_token_reuse_rejected() -> Result<()> {
        let Ok(db) = TestDb::new().await else {
            return Ok(());
        };

        let config = auth_config();
        let opaque_record = opaque_test_record()?;
        let email_normalized = normalize_email("bob@example.com");
        let outcome = insert_user_and_verification(
            &db.pool,
            "bob",
            "bob",
            "bob@example.com",
            &email_normalized,
            &opaque_record,
            &config,
        )
        .await?;

        match outcome {
            SignupOutcome::Created => {}
            SignupOutcome::Conflict => return Err(anyhow!("unexpected conflict")),
        }
        let user_id = lookup_user_id(&db.pool, &email_normalized).await?;
        let token =
            issue_verification_token(&db.pool, user_id, "bob@example.com", "bob", &config).await?;
        let token_hash = hash_verification_token(&token);

        let mut tx = db.pool.begin().await?;
        let first = consume_verification_token(&mut tx, &token_hash).await?;
        tx.commit().await?;
        assert!(first);

        let mut tx = db.pool.begin().await?;
        let second = consume_verification_token(&mut tx, &token_hash).await?;
        tx.commit().await?;
        assert!(!second);

        Ok(())
    }

    #[tokio::test]
    async fn verify_token_expired_rejected() -> Result<()> {
        let Ok(db) = TestDb::new().await else {
            return Ok(());
        };

        let config = auth_config();
        let opaque_record = opaque_test_record()?;
        let email_normalized = normalize_email("carol@example.com");
        let outcome = insert_user_and_verification(
            &db.pool,
            "carol",
            "carol",
            "carol@example.com",
            &email_normalized,
            &opaque_record,
            &config,
        )
        .await?;
        match outcome {
            SignupOutcome::Created => {}
            SignupOutcome::Conflict => return Err(anyhow!("unexpected conflict")),
        }
        let user_id = lookup_user_id(&db.pool, &email_normalized).await?;
        let token =
            issue_verification_token(&db.pool, user_id, "carol@example.com", "carol", &config)
                .await?;
        let token_hash = hash_verification_token(&token);

        sqlx::query(
            "UPDATE email_verification_tokens SET expires_at = NOW() - INTERVAL '1 second' WHERE token_hash = $1",
        )
        .bind(&token_hash)
        .execute(&db.pool)
        .await
        .context("failed to expire token")?;

        let mut tx = db.pool.begin().await?;
        let verified = consume_verification_token(&mut tx, &token_hash).await?;
        tx.commit().await?;
        assert!(!verified);

        Ok(())
    }

    #[tokio::test]
    async fn resend_verification_respects_cooldown() -> Result<()> {
        let Ok(db) = TestDb::new().await else {
            return Ok(());
        };

        let config = auth_config();
        let opaque_record = opaque_test_record()?;
        let email_normalized = normalize_email("dora@example.com");
        let _ = insert_user_and_verification(
            &db.pool,
            "dora",
            "dora",
            "dora@example.com",
            &email_normalized,
            &opaque_record,
            &config,
        )
        .await?;

        let first = enqueue_resend_verification(&db.pool, "dora@example.com", &config).await?;
        assert!(matches!(
            first,
            ResendOutcome::Cooldown | ResendOutcome::Queued
        ));

        let second = enqueue_resend_verification(&db.pool, "dora@example.com", &config).await?;
        assert!(matches!(second, ResendOutcome::Cooldown));

        Ok(())
    }
}
