//! Unit and integration tests for the auth module.

use super::{
    AuthConfig, AuthState, OpaqueState,
    mfa::MfaConfig,
    rate_limit::NoopRateLimiter,
    state::OpaqueSuite,
    storage::{
        ResendOutcome, SignupOutcome, consume_verification_token, enqueue_resend_verification,
        insert_user_and_verification, insert_verification_records,
    },
    utils::{
        build_verify_url, decode_base64_field, generate_session_token, generate_verification_token,
        hash_session_token, hash_verification_token, normalize_email, valid_email,
    },
    zero_token::{ZeroTokenError, zero_token_error_response},
};
use anyhow::{Context, Result, anyhow};
use axum::{
    Extension, Router,
    body::{Body, to_bytes},
    http::{
        Request, StatusCode,
        header::{CONTENT_TYPE, COOKIE, SET_COOKIE},
    },
    routing::{delete, get, post},
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, Identifiers, RegistrationResponse,
    ServerRegistration, ServerSetup,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde_json::json;
use sqlx::{Connection, PgConnection, PgPool, Row, postgres::PgPoolOptions};
use std::sync::Arc;
use test_support::{postgres::PostgresContainer, runtime};
use tokio::time::Duration;
use tower::ServiceExt;
use uuid::Uuid;

const PERMESI_SCHEMA_SQL: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../db/sql/02_permesi.sql"
));

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| i64::try_from(duration.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or_default()
}

fn identifiers<'a>(client: &'a [u8], server: &'a [u8]) -> Identifiers<'a> {
    Identifiers {
        client: Some(client),
        server: Some(server),
    }
}

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

        let postgres = PostgresContainer::start("bridge").await?;
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
    AuthConfig::new("https://permesi.dev".to_string())
        .with_email_token_ttl_seconds(60)
        .with_resend_cooldown_seconds(300)
}

#[test]
fn normalize_email_trims_and_lowercases() {
    assert_eq!(normalize_email(" Alice@Example.COM "), "alice@example.com");
}

#[test]
fn valid_email_accepts_basic_format() {
    assert!(valid_email("a@example.com"));
    assert!(!valid_email("not-an-email"));
}

#[test]
fn build_verify_url_trims_trailing_slash() {
    let url = build_verify_url("https://permesi.dev/", "token");
    assert_eq!(url, "https://permesi.dev/verify-email#token=token");
}

#[test]
fn decode_base64_field_rejects_empty() {
    assert!(decode_base64_field(" ").is_err());
}

#[test]
fn decode_base64_field_rejects_invalid() {
    assert!(decode_base64_field("not-base64").is_err());
}

#[test]
fn decode_base64_field_accepts_valid() -> Result<()> {
    let payload = b"hello";
    let encoded = STANDARD.encode(payload);
    let decoded = decode_base64_field(&encoded).map_err(anyhow::Error::msg)?;
    assert_eq!(decoded, payload);
    Ok(())
}

#[test]
fn generate_verification_token_round_trip() -> Result<()> {
    let token = generate_verification_token()?;
    let decoded = URL_SAFE_NO_PAD
        .decode(token.as_bytes())
        .context("decode verification token")?;
    assert_eq!(decoded.len(), 32);
    Ok(())
}

#[test]
fn hash_verification_token_stable() {
    let first = hash_verification_token("token");
    let second = hash_verification_token("token");
    let different = hash_verification_token("other");
    assert_eq!(first, second);
    assert_ne!(first, different);
}

#[test]
fn zero_token_error_response_maps_status() {
    let (status, message) = zero_token_error_response(&ZeroTokenError::Missing);
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(message, "Missing zero token");

    let (status, message) = zero_token_error_response(&ZeroTokenError::Invalid);
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(message, "Invalid token");
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

async fn lookup_user_id(pool: &PgPool, email: &str) -> Result<Uuid> {
    let row = sqlx::query("SELECT id FROM users WHERE email = $1")
        .bind(email)
        .fetch_one(pool)
        .await
        .context("failed to lookup user id")?;
    Ok(row.get("id"))
}

async fn issue_verification_token(
    pool: &PgPool,
    user_id: Uuid,
    email: &str,
    config: &AuthConfig,
) -> Result<String> {
    let mut tx = pool.begin().await.context("begin token transaction")?;
    let token = insert_verification_records(&mut tx, user_id, email, config).await?;
    tx.commit().await.context("commit token transaction")?;
    Ok(token)
}

#[tokio::test]
async fn signup_concurrent_email_unique() -> Result<()> {
    let Ok(db) = TestDb::new().await else {
        return Ok(());
    };

    let config = auth_config();
    let opaque_record = opaque_test_record()?;
    let email = "alice@example.com";
    let email_normalized = normalize_email(email);

    let task_one =
        insert_user_and_verification(&db.pool, &email_normalized, &opaque_record, &config);
    let task_two =
        insert_user_and_verification(&db.pool, &email_normalized, &opaque_record, &config);

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
    let outcome =
        insert_user_and_verification(&db.pool, &email_normalized, &opaque_record, &config).await?;

    match outcome {
        SignupOutcome::Created => {}
        SignupOutcome::Conflict => return Err(anyhow!("unexpected conflict")),
    }
    let user_id = lookup_user_id(&db.pool, &email_normalized).await?;
    let token = issue_verification_token(&db.pool, user_id, &email_normalized, &config).await?;
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
    let outcome =
        insert_user_and_verification(&db.pool, &email_normalized, &opaque_record, &config).await?;
    match outcome {
        SignupOutcome::Created => {}
        SignupOutcome::Conflict => return Err(anyhow!("unexpected conflict")),
    }
    let user_id = lookup_user_id(&db.pool, &email_normalized).await?;
    let token = issue_verification_token(&db.pool, user_id, &email_normalized, &config).await?;
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
    let _ =
        insert_user_and_verification(&db.pool, &email_normalized, &opaque_record, &config).await?;

    let first = enqueue_resend_verification(&db.pool, "dora@example.com", &config).await?;
    assert!(matches!(
        first,
        ResendOutcome::Cooldown | ResendOutcome::Queued
    ));

    let second = enqueue_resend_verification(&db.pool, "dora@example.com", &config).await?;
    assert!(matches!(second, ResendOutcome::Cooldown));

    Ok(())
}

fn auth_state() -> Arc<AuthState> {
    let config = AuthConfig::new("https://permesi.dev".to_string())
        .with_email_token_ttl_seconds(60)
        .with_resend_cooldown_seconds(300);
    let opaque_state = OpaqueState::from_seed(
        [0u8; 32],
        "api.permesi.dev".to_string(),
        Duration::from_secs(300),
    );
    Arc::new(AuthState::new(
        config,
        opaque_state,
        Arc::new(NoopRateLimiter),
        MfaConfig::new(),
    ))
}

fn opaque_router(
    auth_state: Arc<AuthState>,
    admission: Arc<crate::api::handlers::AdmissionVerifier>,
    pool: PgPool,
) -> Router {
    Router::new()
        .route(
            "/v1/auth/opaque/signup/start",
            post(super::opaque::signup::opaque_signup_start),
        )
        .route(
            "/v1/auth/opaque/signup/finish",
            post(super::opaque::signup::opaque_signup_finish),
        )
        .route(
            "/v1/auth/opaque/login/start",
            post(super::opaque::login::opaque_login_start),
        )
        .route(
            "/v1/auth/opaque/login/finish",
            post(super::opaque::login::opaque_login_finish),
        )
        .layer(Extension(auth_state))
        .layer(Extension(admission))
        .layer(Extension(pool))
}

/// Build a verifier/signer pair so tests can mint valid zero-tokens accepted by handlers.
fn test_admission_context() -> Result<(
    Arc<crate::api::handlers::AdmissionVerifier>,
    ed25519_dalek::SigningKey,
    String,
)> {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    let verifying_key = signing_key.verifying_key();
    let key = admission_token::PaserkKey::from_ed25519_public_key_bytes(&verifying_key.to_bytes())?;
    let keyset = admission_token::PaserkKeySet {
        version: "v4".to_string(),
        purpose: "public".to_string(),
        active_kid: key.kid.clone(),
        keys: vec![key.clone()],
    };
    let verifier = Arc::new(crate::api::handlers::AdmissionVerifier::new(
        keyset,
        "https://genesis.test".to_string(),
        "permesi".to_string(),
    ));
    Ok((verifier, signing_key, key.kid))
}

/// Mint a short-lived zero-token used by OPAQUE endpoints in integration-style tests.
fn issue_zero_token(signing_key: &ed25519_dalek::SigningKey, kid: &str) -> Result<String> {
    use admission_token::{
        AdmissionTokenClaims, AdmissionTokenFooter, build_token, encode_signing_input,
        rfc3339_from_unix,
    };
    use ed25519_dalek::Signer;

    let now_unix = unix_now();
    let claims = AdmissionTokenClaims {
        iss: "https://genesis.test".to_string(),
        aud: "permesi".to_string(),
        iat: rfc3339_from_unix(now_unix)?,
        exp: rfc3339_from_unix(now_unix + 600)?,
        jti: Uuid::new_v4().to_string(),
        sub: None,
        action: "zero".to_string(),
    };
    let footer = AdmissionTokenFooter {
        kid: kid.to_string(),
    };
    let signing_input = encode_signing_input(&claims, &footer)?;
    let signature = signing_key.sign(&signing_input.pre_auth);
    Ok(build_token(
        &signing_input.payload,
        &signing_input.footer,
        &signature.to_bytes(),
    ))
}

/// Run OPAQUE signup start+finish through HTTP handlers to populate registration records.
async fn run_opaque_signup(
    app: &Router,
    email: &str,
    password: &[u8],
    zero_token: &str,
    seed: [u8; 32],
) -> Result<()> {
    let mut rng = ChaCha20Rng::from_seed(seed);
    let ksf = argon2::Argon2::default();
    let client_start = ClientRegistration::<OpaqueSuite>::start(&mut rng, password)?;

    let start_payload = json!({
        "email": email,
        "registration_request": STANDARD.encode(client_start.message.serialize())
    });
    let start_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/opaque/signup/start")
                .header(CONTENT_TYPE, "application/json")
                .header("X-Permesi-Zero-Token", zero_token)
                .body(Body::from(start_payload.to_string()))?,
        )
        .await?;
    assert_eq!(start_response.status(), StatusCode::OK);

    let start_body = to_bytes(start_response.into_body(), usize::MAX).await?;
    let start_json: serde_json::Value = serde_json::from_slice(&start_body)?;
    let registration_response = start_json
        .get("registration_response")
        .and_then(serde_json::Value::as_str)
        .context("missing registration_response")?;
    let response_bytes = STANDARD.decode(registration_response)?;
    let response = RegistrationResponse::<OpaqueSuite>::deserialize(&response_bytes)?;

    let finish_params = ClientRegistrationFinishParameters::new(
        identifiers(email.as_bytes(), b"api.permesi.dev"),
        Some(&ksf),
    );
    let client_finish = client_start
        .state
        .finish(&mut rng, password, response, finish_params)?;

    let finish_payload = json!({
        "email": email,
        "registration_record": STANDARD.encode(client_finish.message.serialize())
    });
    let finish_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/opaque/signup/finish")
                .header(CONTENT_TYPE, "application/json")
                .header("X-Permesi-Zero-Token", zero_token)
                .body(Body::from(finish_payload.to_string()))?,
        )
        .await?;

    assert_eq!(finish_response.status(), StatusCode::CREATED);
    Ok(())
}

fn extract_session_cookie_token(set_cookie: &str) -> Option<String> {
    let cookie_name = "permesi_session=";
    set_cookie
        .split(';')
        .next()
        .and_then(|part| part.trim().strip_prefix(cookie_name))
        .map(str::to_string)
}

async fn insert_active_user(pool: &PgPool, email: &str) -> Result<Uuid> {
    let user_id = Uuid::new_v4();
    let query = r"
        INSERT INTO users (id, email, opaque_registration_record, status)
        VALUES ($1, $2, $3, 'active')
    ";
    sqlx::query(query)
        .bind(user_id)
        .bind(email)
        .bind(vec![0u8; 16])
        .execute(pool)
        .await
        .context("insert active user")?;
    Ok(user_id)
}

async fn insert_session(pool: &PgPool, user_id: Uuid) -> Result<String> {
    let token = generate_session_token()?;
    let hash = hash_session_token(&token);
    let query = r"
        INSERT INTO user_sessions (user_id, session_hash, expires_at)
        VALUES ($1, $2, NOW() + INTERVAL '1 hour')
    ";
    sqlx::query(query)
        .bind(user_id)
        .bind(hash)
        .execute(pool)
        .await
        .context("insert session")?;
    Ok(token)
}

fn app_router(auth_state: Arc<AuthState>, pool: PgPool) -> Router {
    Router::new()
        .route(
            "/v1/me",
            get(crate::api::handlers::me::get_me).patch(crate::api::handlers::me::patch_me),
        )
        .route(
            "/v1/me/sessions",
            get(crate::api::handlers::me::list_sessions),
        )
        .route(
            "/v1/me/sessions/:sid",
            delete(crate::api::handlers::me::revoke_session),
        )
        .layer(Extension(auth_state))
        .layer(Extension(pool))
}

#[tokio::test]
async fn me_requires_auth() -> Result<()> {
    let Ok(db) = TestDb::new().await else {
        return Ok(());
    };
    let app = app_router(auth_state(), db.pool.clone());

    let response = app
        .oneshot(Request::builder().uri("/v1/me").body(Body::empty())?)
        .await?;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn me_returns_current_user() -> Result<()> {
    let Ok(db) = TestDb::new().await else {
        return Ok(());
    };

    let email = "me@example.com";
    let user_id = insert_active_user(&db.pool, email).await?;
    let token = insert_session(&db.pool, user_id).await?;

    let app = app_router(auth_state(), db.pool.clone());
    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/me")
                .header(COOKIE, format!("permesi_session={token}"))
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await?;
    let json: serde_json::Value = serde_json::from_slice(&body)?;
    let json_email = json
        .get("email")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    let json_id = json
        .get("id")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    assert_eq!(json_email, email);
    assert_eq!(json_id, user_id.to_string());
    Ok(())
}

#[tokio::test]
async fn me_patch_updates_allowed_fields() -> Result<()> {
    let Ok(db) = TestDb::new().await else {
        return Ok(());
    };

    let email = "patch@example.com";
    let user_id = insert_active_user(&db.pool, email).await?;
    let token = insert_session(&db.pool, user_id).await?;

    let app = app_router(auth_state(), db.pool.clone());
    let payload = json!({ "display_name": "Patchy" });
    let response = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/v1/me")
                .header(COOKIE, format!("permesi_session={token}"))
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(payload.to_string()))?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);

    let row = sqlx::query("SELECT display_name FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&db.pool)
        .await?;
    let display_name: Option<String> = row.get("display_name");
    assert_eq!(display_name.as_deref(), Some("Patchy"));
    Ok(())
}

#[tokio::test]
async fn me_ignores_other_user_ids() -> Result<()> {
    let Ok(db) = TestDb::new().await else {
        return Ok(());
    };

    let user_a = insert_active_user(&db.pool, "a@example.com").await?;
    let user_b = insert_active_user(&db.pool, "b@example.com").await?;
    let token = insert_session(&db.pool, user_a).await?;

    let app = app_router(auth_state(), db.pool.clone());
    let payload = json!({ "display_name": "User A" });
    let response = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/v1/me")
                .header(COOKIE, format!("permesi_session={token}"))
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(payload.to_string()))?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);

    let row_a = sqlx::query("SELECT display_name FROM users WHERE id = $1")
        .bind(user_a)
        .fetch_one(&db.pool)
        .await?;
    let row_b = sqlx::query("SELECT display_name FROM users WHERE id = $1")
        .bind(user_b)
        .fetch_one(&db.pool)
        .await?;
    let name_a: Option<String> = row_a.get("display_name");
    let name_b: Option<String> = row_b.get("display_name");
    assert_eq!(name_a.as_deref(), Some("User A"));
    assert_eq!(name_b.as_deref(), None);
    Ok(())
}

#[tokio::test]
async fn me_revoke_session_rejects_invalid_session_id() -> Result<()> {
    let Ok(db) = TestDb::new().await else {
        return Ok(());
    };

    let email = "revoke-invalid@example.com";
    let user_id = insert_active_user(&db.pool, email).await?;
    let token = insert_session(&db.pool, user_id).await?;

    let app = app_router(auth_state(), db.pool.clone());
    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/v1/me/sessions/0")
                .header(COOKIE, format!("permesi_session={token}"))
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
async fn opaque_signup_login_flow_success() -> Result<()> {
    let Ok(db) = TestDb::new().await else {
        return Ok(());
    };

    let (admission, signing_key, kid) = test_admission_context()?;
    let zero_token = issue_zero_token(&signing_key, &kid)?;
    let app = opaque_router(auth_state(), admission, db.pool.clone());

    let email = "opaque-flow@example.com";
    let password = b"OpaquePassword123!";
    run_opaque_signup(&app, email, password, &zero_token, [11u8; 32]).await?;

    let row = sqlx::query("SELECT id, status::text FROM users WHERE email = $1")
        .bind(email)
        .fetch_one(&db.pool)
        .await?;
    let user_id: Uuid = row.get("id");
    let status: String = row.get("status");
    assert_eq!(status, "pending_verification");

    sqlx::query("UPDATE users SET status = 'active', email_verified_at = NOW() WHERE id = $1")
        .bind(user_id)
        .execute(&db.pool)
        .await?;

    let mut rng = ChaCha20Rng::from_seed([12u8; 32]);
    let ksf = argon2::Argon2::default();
    let login_start = ClientLogin::<OpaqueSuite>::start(&mut rng, password)?;

    let login_start_payload = json!({
        "email": email,
        "credential_request": STANDARD.encode(login_start.message.serialize())
    });
    let start_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/opaque/login/start")
                .header(CONTENT_TYPE, "application/json")
                .header("X-Permesi-Zero-Token", &zero_token)
                .body(Body::from(login_start_payload.to_string()))?,
        )
        .await?;
    assert_eq!(start_response.status(), StatusCode::OK);

    let start_body = to_bytes(start_response.into_body(), usize::MAX).await?;
    let start_json: serde_json::Value = serde_json::from_slice(&start_body)?;
    let login_id = start_json
        .get("login_id")
        .and_then(serde_json::Value::as_str)
        .context("missing login_id")?
        .to_string();
    let credential_response = start_json
        .get("credential_response")
        .and_then(serde_json::Value::as_str)
        .context("missing credential_response")?;
    let credential_response_bytes = STANDARD.decode(credential_response)?;
    let credential_response =
        CredentialResponse::<OpaqueSuite>::deserialize(&credential_response_bytes)?;

    let login_finish_params = ClientLoginFinishParameters::new(
        None,
        identifiers(email.as_bytes(), b"api.permesi.dev"),
        Some(&ksf),
    );
    let login_finish =
        login_start
            .state
            .finish(password, credential_response, login_finish_params)?;

    let login_finish_payload = json!({
        "login_id": login_id,
        "credential_finalization": STANDARD.encode(login_finish.message.serialize())
    });
    let finish_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/opaque/login/finish")
                .header(CONTENT_TYPE, "application/json")
                .header("X-Permesi-Zero-Token", &zero_token)
                .body(Body::from(login_finish_payload.to_string()))?,
        )
        .await?;
    assert_eq!(finish_response.status(), StatusCode::NO_CONTENT);

    let set_cookie = finish_response
        .headers()
        .get(SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .context("missing set-cookie header")?;
    let session_token =
        extract_session_cookie_token(set_cookie).context("missing session token")?;

    let session_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM user_sessions WHERE user_id = $1 AND session_hash = $2)",
    )
    .bind(user_id)
    .bind(hash_session_token(&session_token))
    .fetch_one(&db.pool)
    .await?;
    assert!(session_exists);

    Ok(())
}

#[tokio::test]
async fn opaque_login_finish_rejects_wrong_password() -> Result<()> {
    let Ok(db) = TestDb::new().await else {
        return Ok(());
    };

    let (admission, signing_key, kid) = test_admission_context()?;
    let zero_token = issue_zero_token(&signing_key, &kid)?;
    let app = opaque_router(auth_state(), admission, db.pool.clone());

    let email = "opaque-wrong-password@example.com";
    let real_password = b"CorrectPassword123!";
    let wrong_password = b"WrongPassword123!";
    run_opaque_signup(&app, email, real_password, &zero_token, [13u8; 32]).await?;

    sqlx::query("UPDATE users SET status = 'active', email_verified_at = NOW() WHERE email = $1")
        .bind(email)
        .execute(&db.pool)
        .await?;

    let mut rng = ChaCha20Rng::from_seed([14u8; 32]);
    let ksf = argon2::Argon2::default();
    let login_start = ClientLogin::<OpaqueSuite>::start(&mut rng, wrong_password)?;

    let login_start_payload = json!({
        "email": email,
        "credential_request": STANDARD.encode(login_start.message.serialize())
    });
    let start_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/opaque/login/start")
                .header(CONTENT_TYPE, "application/json")
                .header("X-Permesi-Zero-Token", &zero_token)
                .body(Body::from(login_start_payload.to_string()))?,
        )
        .await?;
    assert_eq!(start_response.status(), StatusCode::OK);

    let start_body = to_bytes(start_response.into_body(), usize::MAX).await?;
    let start_json: serde_json::Value = serde_json::from_slice(&start_body)?;
    let login_id = start_json
        .get("login_id")
        .and_then(serde_json::Value::as_str)
        .context("missing login_id")?
        .to_string();
    let credential_response = start_json
        .get("credential_response")
        .and_then(serde_json::Value::as_str)
        .context("missing credential_response")?;
    let credential_response_bytes = STANDARD.decode(credential_response)?;
    let credential_response =
        CredentialResponse::<OpaqueSuite>::deserialize(&credential_response_bytes)?;

    let login_finish_params = ClientLoginFinishParameters::new(
        None,
        identifiers(email.as_bytes(), b"api.permesi.dev"),
        Some(&ksf),
    );
    let login_finish =
        login_start
            .state
            .finish(wrong_password, credential_response, login_finish_params)?;

    let login_finish_payload = json!({
        "login_id": login_id,
        "credential_finalization": STANDARD.encode(login_finish.message.serialize())
    });
    let finish_response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/opaque/login/finish")
                .header(CONTENT_TYPE, "application/json")
                .header("X-Permesi-Zero-Token", &zero_token)
                .body(Body::from(login_finish_payload.to_string()))?,
        )
        .await?;

    assert_eq!(finish_response.status(), StatusCode::UNAUTHORIZED);
    assert!(finish_response.headers().get(SET_COOKIE).is_none());
    Ok(())
}

/// Verifies the full OPAQUE password rotation flow.
///
/// This test executes the "4-step handshake" where the client:
/// 1. Proves knowledge of the old password via a secure re-auth flow.
/// 2. Performs a new OPAQUE registration using the new password.
/// 3. Commits the change, resulting in session revocation and a updated DB record.
#[tokio::test]
#[allow(clippy::too_many_lines, clippy::unwrap_used, clippy::indexing_slicing)]
async fn password_change_flow() -> Result<()> {
    use super::state::{AuthState, OpaqueSuite};
    use crate::api::handlers::AdmissionVerifier;
    use admission_token::{
        AdmissionTokenFooter, PaserkKey, PaserkKeySet, build_token, encode_signing_input,
    };
    use ed25519_dalek::Signer;
    use opaque_ke::{ClientRegistration, RegistrationResponse};

    let Ok(db) = TestDb::new().await else {
        return Ok(());
    };

    // 1. Setup user with known password
    let email = "change@example.com";
    let old_password = b"OldPassword123!";
    let new_password = b"NewPassword456!";

    let mut rng = ChaCha20Rng::from_seed([1u8; 32]);
    let server_setup = ServerSetup::<OpaqueSuite>::new(&mut rng);
    let client_reg_start = ClientRegistration::<OpaqueSuite>::start(&mut rng, old_password)?;
    let server_reg_start =
        ServerRegistration::start(&server_setup, client_reg_start.message, email.as_bytes())?;

    let ksf = argon2::Argon2::default();
    let reg_params = ClientRegistrationFinishParameters::new(
        Identifiers {
            client: Some(email.as_bytes()),
            server: Some(b"api.permesi.dev"),
        },
        Some(&ksf),
    );
    let client_reg_finish = client_reg_start.state.finish(
        &mut rng,
        old_password,
        server_reg_start.message,
        reg_params,
    )?;
    let record = ServerRegistration::finish(client_reg_finish.message);
    let record_bytes = record.serialize().to_vec();

    let user_id = Uuid::new_v4();
    sqlx::query("INSERT INTO users (id, email, opaque_registration_record, status) VALUES ($1, $2, $3, 'active')")
        .bind(user_id)
        .bind(email)
        .bind(&record_bytes)
        .execute(&db.pool)
        .await?;

    // 2. Create an elevated session (recent_auth_ok = true)
    let token = generate_session_token()?;
    let hash = hash_session_token(&token);
    let now_unix = unix_now();
    sqlx::query("INSERT INTO user_sessions (user_id, session_hash, expires_at, auth_time) VALUES ($1, $2, NOW() + INTERVAL '1 hour', $3)")
        .bind(user_id)
        .bind(hash)
        .bind(now_unix)
        .execute(&db.pool)
        .await?;

    let auth_state = Arc::new(AuthState::new(
        auth_config(),
        super::state::OpaqueState::from_seed(
            [0u8; 32],
            "api.permesi.dev".to_string(),
            Duration::from_secs(300),
        ),
        Arc::new(super::NoopRateLimiter),
        super::mfa::MfaConfig::new(),
    ));

    // Setup Admission Verifier for test
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let verifying_key = signing_key.verifying_key();
    let key = PaserkKey::from_ed25519_public_key_bytes(&verifying_key.to_bytes())?;
    let keyset = PaserkKeySet {
        version: "v4".to_string(),
        purpose: "public".to_string(),
        active_kid: key.kid.clone(),
        keys: vec![key.clone()],
    };
    let admission = Arc::new(AdmissionVerifier::new(
        keyset,
        "https://genesis.test".to_string(),
        "permesi".to_string(),
    ));

    let app = Router::new()
        .route(
            "/v1/auth/opaque/password/start",
            axum::routing::post(super::opaque::password::opaque_password_start),
        )
        .route(
            "/v1/auth/opaque/password/finish",
            axum::routing::post(super::opaque::password::opaque_password_finish),
        )
        .layer(Extension(auth_state.clone()))
        .layer(Extension(admission.clone()))
        .layer(Extension(db.pool.clone()));

    // 3. Start Password Change
    let client_reg_new = ClientRegistration::<OpaqueSuite>::start(&mut rng, new_password)?;
    let start_payload = json!({
        "registration_request": STANDARD.encode(client_reg_new.message.serialize())
    });

    // Generate a valid admission token for the test
    let admission_claims = admission_token::AdmissionTokenClaims {
        iss: "https://genesis.test".to_string(),
        aud: "permesi".to_string(),
        iat: admission_token::rfc3339_from_unix(now_unix)?,
        exp: admission_token::rfc3339_from_unix(now_unix + 600)?,
        jti: "test".to_string(),
        sub: None,
        action: "zero".to_string(),
    };
    let footer = AdmissionTokenFooter {
        kid: key.kid.clone(),
    };
    let si = encode_signing_input(&admission_claims, &footer)?;
    let signature = signing_key.sign(&si.pre_auth);
    let verified_token = build_token(&si.payload, &si.footer, &signature.to_bytes());

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/opaque/password/start")
                .header(COOKIE, format!("permesi_session={token}"))
                .header(CONTENT_TYPE, "application/json")
                .header("X-Permesi-Zero-Token", verified_token.clone())
                .body(Body::from(start_payload.to_string()))?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await?;
    let start_res: serde_json::Value = serde_json::from_slice(&body)?;
    let reg_res_bytes = STANDARD.decode(start_res["registration_response"].as_str().unwrap())?;
    let reg_res = RegistrationResponse::<OpaqueSuite>::deserialize(&reg_res_bytes)?;

    // 4. Finish Password Change
    let reg_finish_params = ClientRegistrationFinishParameters::new(
        Identifiers {
            client: Some(email.as_bytes()),
            server: Some(b"api.permesi.dev"),
        },
        Some(&ksf),
    );
    let client_reg_final =
        client_reg_new
            .state
            .finish(&mut rng, new_password, reg_res, reg_finish_params)?;
    let finish_payload = json!({
        "registration_record": STANDARD.encode(client_reg_final.message.serialize())
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/opaque/password/finish")
                .header(COOKIE, format!("permesi_session={token}"))
                .header(CONTENT_TYPE, "application/json")
                .header("X-Permesi-Zero-Token", verified_token)
                .body(Body::from(finish_payload.to_string()))?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // 5. Verify old password fails login (session was cleared)
    let session_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM user_sessions WHERE session_hash = $1)")
            .bind(hash_session_token(&token))
            .fetch_one(&db.pool)
            .await?;
    assert!(!session_exists);

    // 6. Verify record changed
    let new_record: Vec<u8> =
        sqlx::query_scalar("SELECT opaque_registration_record FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_one(&db.pool)
            .await?;
    assert_ne!(new_record, record_bytes);

    Ok(())
}

/// Verifies that the password change flow correctly rejects an invalid current password.
///
/// This reproduces the "Unable to complete secure re-auth" error by intentionally
/// providing an incorrect password during the re-authentication phase of the handshake.
#[tokio::test]
#[allow(clippy::too_many_lines, clippy::unwrap_used, clippy::indexing_slicing)]
async fn password_change_fails_with_invalid_reauth() -> Result<()> {
    use super::state::{AuthState, OpaqueSuite};
    use crate::api::handlers::AdmissionVerifier;
    use admission_token::{
        AdmissionTokenFooter, PaserkKey, PaserkKeySet, build_token, encode_signing_input,
    };
    use ed25519_dalek::Signer;
    use opaque_ke::{ClientLogin, ClientLoginFinishParameters, CredentialResponse};

    let Ok(db) = TestDb::new().await else {
        return Ok(());
    };

    // 1. Setup user
    let email = "fail@example.com";
    let real_password = b"CorrectPassword123!";
    let wrong_password = b"WrongPassword123!";

    let mut rng = ChaCha20Rng::from_seed([2u8; 32]);
    let server_setup = ServerSetup::<OpaqueSuite>::new(&mut rng);
    let client_reg_start = ClientRegistration::<OpaqueSuite>::start(&mut rng, real_password)?;
    let server_reg_start =
        ServerRegistration::start(&server_setup, client_reg_start.message, email.as_bytes())?;
    let ksf = argon2::Argon2::default();
    let reg_params = ClientRegistrationFinishParameters::new(
        Identifiers {
            client: Some(email.as_bytes()),
            server: Some(b"api.permesi.dev"),
        },
        Some(&ksf),
    );
    let client_reg_finish = client_reg_start.state.finish(
        &mut rng,
        real_password,
        server_reg_start.message,
        reg_params,
    )?;
    let record = ServerRegistration::finish(client_reg_finish.message);
    let record_bytes = record.serialize().to_vec();

    sqlx::query("INSERT INTO users (id, email, opaque_registration_record, status) VALUES ($1, $2, $3, 'active')")
        .bind(Uuid::new_v4())
        .bind(email)
        .bind(&record_bytes)
        .execute(&db.pool)
        .await?;

    // 2. Create session
    let token = generate_session_token()?;
    sqlx::query("INSERT INTO user_sessions (user_id, session_hash, expires_at) VALUES ((SELECT id FROM users WHERE email = $1), $2, NOW() + INTERVAL '1 hour')")
        .bind(email)
        .bind(hash_session_token(&token))
        .execute(&db.pool)
        .await?;

    let auth_state = Arc::new(AuthState::new(
        auth_config(),
        super::state::OpaqueState::from_seed(
            [0u8; 32],
            "api.permesi.dev".to_string(),
            Duration::from_secs(300),
        ),
        Arc::new(super::NoopRateLimiter),
        super::mfa::MfaConfig::new(),
    ));

    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let key = PaserkKey::from_ed25519_public_key_bytes(&signing_key.verifying_key().to_bytes())?;
    let keyset = PaserkKeySet {
        version: "v4".to_string(),
        purpose: "public".to_string(),
        active_kid: key.kid.clone(),
        keys: vec![key.clone()],
    };
    let admission = Arc::new(AdmissionVerifier::new(
        keyset,
        "https://genesis.test".to_string(),
        "permesi".to_string(),
    ));

    let app = Router::new()
        .route(
            "/v1/auth/opaque/reauth/start",
            axum::routing::post(super::opaque::reauth::opaque_reauth_start),
        )
        .route(
            "/v1/auth/opaque/reauth/finish",
            axum::routing::post(super::opaque::reauth::opaque_reauth_finish),
        )
        .layer(Extension(auth_state.clone()))
        .layer(Extension(admission.clone()))
        .layer(Extension(db.pool.clone()));

    // 3. Start Re-auth with WRONG password
    let client_login_start = ClientLogin::<OpaqueSuite>::start(&mut rng, wrong_password)?;
    let start_payload = json!({
        "credential_request": STANDARD.encode(client_login_start.message.serialize())
    });

    let now_unix = unix_now();
    let admission_claims = admission_token::AdmissionTokenClaims {
        iss: "https://genesis.test".to_string(),
        aud: "permesi".to_string(),
        iat: admission_token::rfc3339_from_unix(now_unix)?,
        exp: admission_token::rfc3339_from_unix(now_unix + 600)?,
        jti: "test".to_string(),
        sub: None,
        action: "zero".to_string(),
    };
    let si = encode_signing_input(
        &admission_claims,
        &AdmissionTokenFooter {
            kid: key.kid.clone(),
        },
    )?;
    let verified_token = build_token(
        &si.payload,
        &si.footer,
        &signing_key.sign(&si.pre_auth).to_bytes(),
    );

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/opaque/reauth/start")
                .header(COOKIE, format!("permesi_session={token}"))
                .header(CONTENT_TYPE, "application/json")
                .header("X-Permesi-Zero-Token", verified_token.clone())
                .body(Body::from(start_payload.to_string()))?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await?;
    let start_res: serde_json::Value = serde_json::from_slice(&body)?;
    let cred_res_bytes = STANDARD.decode(start_res["credential_response"].as_str().unwrap())?;
    let cred_res = CredentialResponse::<OpaqueSuite>::deserialize(&cred_res_bytes)?;

    // 4. Finish Re-auth (Generation of proof with wrong password should lead to failure at server)
    let login_params = ClientLoginFinishParameters::new(
        None,
        identifiers(email.as_bytes(), b"api.permesi.dev"),
        Some(&ksf),
    );

    // The OPAQUE client will produce a proof, but it won't match the server's expected proof
    // because the "wrong_password" was used to derive the client keys.
    let client_login_final =
        client_login_start
            .state
            .finish(wrong_password, cred_res, login_params)?;
    let finish_payload = json!({
        "login_id": start_res["login_id"],
        "credential_finalization": STANDARD.encode(client_login_final.message.serialize())
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/opaque/reauth/finish")
                .header(COOKIE, format!("permesi_session={token}"))
                .header(CONTENT_TYPE, "application/json")
                .header("X-Permesi-Zero-Token", verified_token)
                .body(Body::from(finish_payload.to_string()))?,
        )
        .await?;

    // Server should reject the invalid proof
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    Ok(())
}
