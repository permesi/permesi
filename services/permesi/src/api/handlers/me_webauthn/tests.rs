//! Real-dependency and request-validation regressions for passkey self-service.
//! Tests retain the handler boundary and verify the existing authentication policy.

use super::*;
use crate::api::handlers::auth::hash_session_token;
use crate::api::handlers::auth::{AuthConfig, AuthState, OpaqueState, RateLimiter};
use admission_token::{
    AdmissionTokenFooter, PaserkKey, PaserkKeySet, build_token, encode_signing_input,
};
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::FromRef,
    http::{Request, StatusCode, header::CONTENT_TYPE},
    routing::{delete, get, post},
};
use chrono::Utc;
use ed25519_dalek::Signer;
use service_utils::request_id::with_request_correlation;
use sqlx::{Connection, PgConnection, PgPool, postgres::PgPoolOptions};
use test_support::{postgres::PostgresContainer, runtime};
use tokio::time::Duration;
use tower::ServiceExt;

const PERMESI_SCHEMA_SQL: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../db/sql/02_permesi.sql"
));

struct TestDb {
    _postgres: PostgresContainer,
    pool: PgPool,
}

impl TestDb {
    async fn new() -> anyhow::Result<Option<Self>> {
        if let Err(err) = runtime::ensure_container_runtime() {
            eprintln!("Skipping integration test: {err}");
            return Ok(None);
        }

        let postgres = PostgresContainer::start("bridge").await?;
        postgres.wait_until_ready().await?;
        apply_schema(&postgres).await?;

        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&postgres.admin_dsn())
            .await?;

        Ok(Some(Self {
            _postgres: postgres,
            pool,
        }))
    }
}

async fn apply_schema(postgres: &PostgresContainer) -> anyhow::Result<()> {
    let mut connection = PgConnection::connect(&postgres.admin_dsn()).await?;

    test_support::sql::execute_script(&mut connection, "02_permesi.sql", PERMESI_SCHEMA_SQL)
        .await?;

    Ok(())
}

async fn insert_user(pool: &PgPool) -> anyhow::Result<(Uuid, String)> {
    let user_id = Uuid::new_v4();
    let email = format!("user-{}@example.com", user_id.simple());
    let mut record = vec![0u8; 32];
    getrandom::fill(&mut record)?;
    sqlx::query(
        "INSERT INTO users (id, email, opaque_registration_record, status, display_name) VALUES ($1, $2, $3, 'active', 'Example User')",
    )
    .bind(user_id)
    .bind(&email)
    .bind(record)
    .execute(pool)
    .await?;
    Ok((user_id, email))
}

async fn insert_session(pool: &PgPool, user_id: Uuid) -> anyhow::Result<String> {
    let token = crate::api::handlers::auth::generate_session_token()?;
    let hash = hash_session_token(&token);
    sqlx::query(
        "INSERT INTO user_sessions (user_id, session_hash, expires_at, auth_time) VALUES ($1, $2, NOW() + INTERVAL '1 hour', NOW())",
    )
    .bind(user_id)
    .bind(hash)
    .execute(pool)
    .await?;
    Ok(token)
}

/// Router state for the passkey handlers; `FromRef` hands each handler the parts
/// it extracts.
#[derive(Clone, FromRef)]
struct WebauthnTestState {
    auth: Arc<AuthState>,
    admission: Arc<AdmissionVerifier>,
    passkeys: Arc<PasskeyService>,
    pool: PgPool,
}

/// Router state for the credential listing handler.
#[derive(Clone, FromRef)]
struct CredentialListTestState {
    passkeys: Arc<PasskeyService>,
    pool: PgPool,
}

fn build_admission() -> anyhow::Result<(Arc<AdmissionVerifier>, String)> {
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

    let now_unix = Utc::now().timestamp();
    let admission_claims = admission_token::AdmissionTokenClaims {
        iss: "https://genesis.test".to_string(),
        aud: "permesi".to_string(),
        iat: admission_token::rfc3339_from_unix(now_unix)?,
        exp: admission_token::rfc3339_from_unix(now_unix + 120)?,
        jti: "test".to_string(),
        sub: None,
        action: "admission".to_string(),
    };
    let footer = AdmissionTokenFooter { kid: key.kid };
    let signing_input = encode_signing_input(&admission_claims, &footer)?;
    let signature = signing_key.sign(&signing_input.pre_auth);
    let token = build_token(
        &signing_input.payload,
        &signing_input.footer,
        &signature.to_bytes(),
    );

    Ok((admission, token))
}

#[tokio::test]
async fn register_options_returns_public_key() -> anyhow::Result<()> {
    let Some(db) = TestDb::new().await? else {
        return Ok(());
    };

    let (user_id, _email) = insert_user(&db.pool).await?;
    let session_token = insert_session(&db.pool, user_id).await?;
    sqlx::query("UPDATE user_sessions SET created_at=statement_timestamp()-INTERVAL '11 minutes', auth_time=statement_timestamp()-INTERVAL '11 minutes' WHERE user_id=$1")
        .bind(user_id)
        .execute(&db.pool)
        .await?;

    let auth_config = AuthConfig::new("https://permesi.dev".to_string());
    let auth_state = Arc::new(AuthState::new(
        auth_config.clone(),
        OpaqueState::from_seed(
            [0u8; 32],
            "api.permesi.dev".to_string(),
            Duration::from_mins(5),
            10_000,
        ),
        Arc::new(RateLimiter::noop()),
        crate::api::handlers::auth::mfa::MfaConfig::new(),
    ));

    let passkey_config = crate::webauthn::PasskeyConfig::new(
        auth_config.webauthn_rp_id().to_string(),
        "Permesi".to_string(),
        vec![auth_config.webauthn_rp_origin().to_string()],
        Duration::from_mins(5),
        true,
    )?;
    let passkey_service = Arc::new(PasskeyService::new(
        passkey_config,
        100,
        db.pool.clone(),
        &[1; 32],
        1000,
    )?);

    let (admission, zero_token) = build_admission()?;

    let app = with_request_correlation(
        Router::new()
            .route("/v1/me/webauthn/register/options", post(register_options))
            .with_state(WebauthnTestState {
                auth: auth_state,
                admission,
                passkeys: passkey_service,
                pool: db.pool.clone(),
            }),
    );

    let stale = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/me/webauthn/register/options")
                .header("Origin", "https://permesi.dev")
                .header("X-Permesi-Zero-Token", zero_token.clone())
                .header(CONTENT_TYPE, "application/json")
                .header("Cookie", format!("permesi_session={session_token}"))
                .body(Body::from("{}"))?,
        )
        .await?;
    assert_eq!(stale.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM webauthn_exchanges WHERE user_id=$1")
            .bind(user_id)
            .fetch_one(&db.pool)
            .await?,
        0
    );
    sqlx::query("UPDATE user_sessions SET auth_time=clock_timestamp() WHERE user_id=$1")
        .bind(user_id)
        .execute(&db.pool)
        .await?;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/me/webauthn/register/options")
                .header("Origin", "https://permesi.dev")
                .header("X-Permesi-Zero-Token", zero_token)
                .header(CONTENT_TYPE, "application/json")
                .header("Cookie", format!("permesi_session={session_token}"))
                .body(Body::from("{}"))?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await?;
    let payload: serde_json::Value = serde_json::from_slice(&body)?;
    assert!(payload.get("reg_id").and_then(|v| v.as_str()).is_some());
    assert!(
        payload
            .get("challenge")
            .and_then(|v| v.get("publicKey"))
            .is_some()
    );

    Ok(())
}

#[tokio::test]
async fn list_credentials_returns_empty_in_preview_mode() -> anyhow::Result<()> {
    let Some(db) = TestDb::new().await? else {
        return Ok(());
    };

    let (user_id, _email) = insert_user(&db.pool).await?;
    let session_token = insert_session(&db.pool, user_id).await?;

    let passkey_config = crate::webauthn::PasskeyConfig::new(
        "permesi.dev".to_string(),
        "Permesi".to_string(),
        vec!["https://permesi.dev".to_string()],
        Duration::from_mins(5),
        true,
    )?;
    let passkey_service = Arc::new(PasskeyService::new(
        passkey_config,
        100,
        db.pool.clone(),
        &[1; 32],
        1000,
    )?);

    let app = with_request_correlation(
        Router::new()
            .route("/v1/me/webauthn/credentials", get(list_credentials))
            .with_state(CredentialListTestState {
                passkeys: passkey_service,
                pool: db.pool,
            }),
    );

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/me/webauthn/credentials")
                .header("Cookie", format!("permesi_session={session_token}"))
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await?;
    let payload: serde_json::Value = serde_json::from_slice(&body)?;
    assert_eq!(
        payload
            .get("preview_mode")
            .and_then(serde_json::Value::as_bool),
        Some(true)
    );
    assert_eq!(
        payload
            .get("credentials")
            .and_then(|v| v.as_array())
            .map(Vec::len),
        Some(0)
    );

    Ok(())
}

#[tokio::test]
async fn delete_credential_requires_zero_token() -> anyhow::Result<()> {
    let Some(db) = TestDb::new().await? else {
        return Ok(());
    };

    let (user_id, _email) = insert_user(&db.pool).await?;
    let session_token = insert_session(&db.pool, user_id).await?;

    let auth_config = AuthConfig::new("https://permesi.dev".to_string());
    let auth_state = Arc::new(AuthState::new(
        auth_config.clone(),
        OpaqueState::from_seed(
            [0u8; 32],
            "api.permesi.dev".to_string(),
            Duration::from_mins(5),
            10_000,
        ),
        Arc::new(RateLimiter::noop()),
        crate::api::handlers::auth::mfa::MfaConfig::new(),
    ));

    let passkey_config = crate::webauthn::PasskeyConfig::new(
        auth_config.webauthn_rp_id().to_string(),
        "Permesi".to_string(),
        vec![auth_config.webauthn_rp_origin().to_string()],
        Duration::from_mins(5),
        false,
    )?;
    let passkey_service = Arc::new(PasskeyService::new(
        passkey_config,
        100,
        db.pool.clone(),
        &[1; 32],
        1000,
    )?);
    let (admission, _zero_token) = build_admission()?;

    let app = with_request_correlation(
        Router::new()
            .route(
                "/v1/me/webauthn/credentials/{credential_id}",
                delete(delete_credential),
            )
            .with_state(WebauthnTestState {
                auth: auth_state,
                admission,
                passkeys: passkey_service,
                pool: db.pool,
            }),
    );

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/v1/me/webauthn/credentials/AA")
                .header("Cookie", format!("permesi_session={session_token}"))
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), usize::MAX).await?;
    assert_eq!(std::str::from_utf8(&body)?, "Missing zero token");

    Ok(())
}

#[tokio::test]
async fn delete_credential_rejects_invalid_credential_id() -> anyhow::Result<()> {
    let Some(db) = TestDb::new().await? else {
        return Ok(());
    };

    let (user_id, _email) = insert_user(&db.pool).await?;
    let session_token = insert_session(&db.pool, user_id).await?;

    let auth_config = AuthConfig::new("https://permesi.dev".to_string());
    let auth_state = Arc::new(AuthState::new(
        auth_config.clone(),
        OpaqueState::from_seed(
            [0u8; 32],
            "api.permesi.dev".to_string(),
            Duration::from_mins(5),
            10_000,
        ),
        Arc::new(RateLimiter::noop()),
        crate::api::handlers::auth::mfa::MfaConfig::new(),
    ));

    let passkey_config = crate::webauthn::PasskeyConfig::new(
        auth_config.webauthn_rp_id().to_string(),
        "Permesi".to_string(),
        vec![auth_config.webauthn_rp_origin().to_string()],
        Duration::from_mins(5),
        false,
    )?;
    let passkey_service = Arc::new(PasskeyService::new(
        passkey_config,
        100,
        db.pool.clone(),
        &[1; 32],
        1000,
    )?);
    let (admission, zero_token) = build_admission()?;

    let app = with_request_correlation(
        Router::new()
            .route(
                "/v1/me/webauthn/credentials/{credential_id}",
                delete(delete_credential),
            )
            .with_state(WebauthnTestState {
                auth: auth_state,
                admission,
                passkeys: passkey_service,
                pool: db.pool,
            }),
    );

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/v1/me/webauthn/credentials/0")
                .header("Cookie", format!("permesi_session={session_token}"))
                .header("X-Permesi-Zero-Token", zero_token)
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), usize::MAX).await?;
    assert_eq!(std::str::from_utf8(&body)?, "Invalid credential id");

    Ok(())
}
