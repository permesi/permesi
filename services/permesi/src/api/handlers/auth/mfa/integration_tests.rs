use crate::{
    api::handlers::auth::{
        AuthConfig, AuthState, OpaqueState,
        mfa::{MfaConfig, MfaState},
        utils::{generate_session_token, hash_session_token},
    },
    cli::globals::GlobalArgs,
    totp::{DekManager, TotpService},
};
use anyhow::{Context, Result};
use axum::{
    Extension, Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header::COOKIE},
    routing::{delete, get, post},
};
use base64::Engine;
use secrecy::SecretString;
use serde_json::json;
use sqlx::{Connection, PgConnection, PgPool, postgres::PgPoolOptions};
use std::{sync::Arc, time::Duration};
use test_support::{TestNetwork, postgres::PostgresContainer, runtime, vault::VaultContainer};
use tower::ServiceExt;
use uuid::Uuid;

const PERMESI_SCHEMA_SQL: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../db/sql/02_permesi.sql"
));

struct TestContext {
    _postgres: PostgresContainer,
    _vault: VaultContainer,
    pool: PgPool,
    totp_service: TotpService,
}

impl TestContext {
    async fn new() -> Result<Self> {
        if let Err(err) = runtime::ensure_container_runtime() {
            eprintln!("Skipping integration test: {err}");
            return Err(err);
        }

        let network = TestNetwork::new("permesi-mfa");

        // Start Vault
        let vault = VaultContainer::start(network.name()).await?;
        vault
            .enable_secrets_engine("transit/permesi", "transit")
            .await?;
        vault
            .create_transit_key("transit/permesi", "totp", "chacha20-poly1305")
            .await?;

        vault
            .enable_secrets_engine("secret/permesi", "kv-v2")
            .await?;
        vault
            .write_kv_v2(
                "secret/permesi",
                "config",
                json!({
                    "opaque_server_seed": "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=",
                    "mfa_recovery_pepper": "YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI="
                }),
            )
            .await?;

        // Start Postgres
        let postgres = PostgresContainer::start(network.name()).await?;
        postgres.wait_until_ready().await?;
        apply_schema(&postgres).await?;

        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&postgres.admin_dsn())
            .await
            .context("failed to connect test pool")?;

        // Initialize DEK Manager
        let mut globals = GlobalArgs::new(vault.base_url().to_string());
        globals.set_token(SecretString::from("root-token".to_string()));

        let dek_manager = DekManager::new(globals);

        // Rotate DEK to generate initial key (since init() only loads existing)
        dek_manager.rotate(&pool).await?;

        let totp_service = TotpService::new(dek_manager, pool.clone(), "Permesi".to_string());

        Ok(Self {
            _postgres: postgres,
            _vault: vault,
            pool,
            totp_service,
        })
    }
}

async fn apply_schema(postgres: &PostgresContainer) -> Result<()> {
    let mut connection = PgConnection::connect(&postgres.admin_dsn())
        .await
        .context("failed to connect for schema setup")?;

    // Apply Base Schema
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
        if trimmed.starts_with(r"\ir ") {
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

fn auth_state() -> AuthState {
    let config = AuthConfig::new("https://permesi.dev".to_string())
        .with_email_token_ttl_seconds(60)
        .with_resend_cooldown_seconds(300);
    let opaque_state = OpaqueState::from_seed(
        [0u8; 32],
        "api.permesi.dev".to_string(),
        Duration::from_secs(300),
    );
    AuthState::new(
        config,
        opaque_state,
        std::sync::Arc::new(crate::api::handlers::auth::NoopRateLimiter),
        MfaConfig::new().with_recovery_pepper(Arc::from(vec![1, 2, 3, 4])),
    )
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

fn app_router(auth_state: AuthState, pool: PgPool, totp_service: TotpService) -> Router {
    Router::new()
        .route(
            "/v1/auth/mfa/totp/enroll/start",
            post(super::totp_enroll_start),
        )
        .route(
            "/v1/auth/mfa/totp/enroll/finish",
            post(super::totp_enroll_finish),
        )
        .route(
            "/v1/me/mfa/webauthn/{credential_id}",
            delete(super::webauthn::delete_key),
        )
        .route("/v1/me", get(crate::api::handlers::me::get_me))
        .layer(Extension(std::sync::Arc::new(auth_state)))
        .layer(Extension(pool))
        .layer(Extension(totp_service))
}

#[tokio::test]
async fn mfa_enrollment_flow() -> Result<()> {
    let Ok(ctx) = TestContext::new().await else {
        return Ok(());
    };

    let email = "mfa@example.com";
    let user_id = insert_active_user(&ctx.pool, email).await?;
    let token = insert_session(&ctx.pool, user_id).await?;

    let app = app_router(auth_state(), ctx.pool.clone(), ctx.totp_service.clone());

    // 1. Start Enrollment
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/mfa/totp/enroll/start")
                .header(COOKIE, format!("permesi_session={token}"))
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await?;
    let start_data: crate::api::handlers::auth::types::MfaTotpEnrollStartResponse =
        serde_json::from_slice(&body)?;

    // Note: secret is already plaintext base32 string
    let secret_bytes =
        if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(&start_data.secret) {
            bytes
        } else {
            use base32::Alphabet;
            base32::decode(Alphabet::Rfc4648 { padding: false }, &start_data.secret)
                .ok_or_else(|| anyhow::anyhow!("Invalid base32 secret"))?
        };

    // 2. Generate Code
    let totp = totp_rs::TOTP::new(
        totp_rs::Algorithm::SHA1,
        6,
        1,
        30,
        secret_bytes,
        Some("Permesi".to_string()),
        email.to_string(),
    )
    .map_err(|e| anyhow::anyhow!("Failed to create TOTP: {e}"))?;
    let code = totp
        .generate_current()
        .map_err(|e| anyhow::anyhow!("Failed to generate code: {e}"))?;

    // 3. Finish Enrollment
    let payload = serde_json::to_string(
        &crate::api::handlers::auth::types::MfaTotpEnrollFinishRequest {
            code,
            credential_id: start_data.credential_id.clone(),
        },
    )?;
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/mfa/totp/enroll/finish")
                .header(COOKIE, format!("permesi_session={token}"))
                .header("Content-Type", "application/json")
                .body(Body::from(payload))?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);

    // 4. Verify Profile State
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/me")
                .header(COOKIE, format!("permesi_session={token}"))
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await?;
    let me: crate::api::handlers::me::MeResponse = serde_json::from_slice(&body)?;
    assert!(me.mfa_enabled, "MFA should be enabled in profile");

    Ok(())
}

#[tokio::test]
async fn security_key_deletion_disables_mfa() -> Result<()> {
    let Ok(ctx) = TestContext::new().await else {
        return Ok(());
    };

    let email = "keyonly@example.com";
    let user_id = insert_active_user(&ctx.pool, email).await?;
    let token = insert_session(&ctx.pool, user_id).await?;

    // Insert fake security key
    let cred_id = vec![1, 2, 3, 4];
    let cred_id_hex = hex::encode(&cred_id);
    sqlx::query(
        "INSERT INTO security_keys (credential_id, user_id, label, public_key, sign_count) VALUES ($1, $2, 'test', $3, 0)"
    )
    .bind(&cred_id)
    .bind(user_id)
    .bind(vec![0u8; 32])
    .execute(&ctx.pool)
    .await?;

    // Enable MFA
    super::storage::upsert_mfa_state(&ctx.pool, user_id, MfaState::Enabled, None).await?;

    let app = app_router(auth_state(), ctx.pool.clone(), ctx.totp_service.clone());

    // Call Delete
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/v1/me/mfa/webauthn/{cred_id_hex}"))
                .header(COOKIE, format!("permesi_session={token}"))
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Verify MFA disabled
    let state = super::storage::load_mfa_state(&ctx.pool, user_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("MFA state not found"))?;
    assert_eq!(state.state, MfaState::Disabled);

    Ok(())
}

#[tokio::test]
async fn security_key_preserves_totp() -> Result<()> {
    let Ok(ctx) = TestContext::new().await else {
        return Ok(());
    };

    let email = "both@example.com";
    let user_id = insert_active_user(&ctx.pool, email).await?;
    let token = insert_session(&ctx.pool, user_id).await?;

    // Insert fake security key
    let cred_id = vec![5, 6, 7, 8];
    let cred_id_hex = hex::encode(&cred_id);
    sqlx::query(
        "INSERT INTO security_keys (credential_id, user_id, label, public_key, sign_count) VALUES ($1, $2, 'test', $3, 0)"
    )
    .bind(&cred_id)
    .bind(user_id)
    .bind(vec![0u8; 32])
    .execute(&ctx.pool)
    .await?;

    // Enable MFA WITH recovery batch (simulating TOTP)
    let batch_id = Uuid::new_v4();
    super::storage::upsert_mfa_state(&ctx.pool, user_id, MfaState::Enabled, Some(batch_id)).await?;

    let app = app_router(auth_state(), ctx.pool.clone(), ctx.totp_service.clone());

    // Call Delete
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/v1/me/mfa/webauthn/{cred_id_hex}"))
                .header(COOKIE, format!("permesi_session={token}"))
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Verify MFA STILL enabled
    let state = super::storage::load_mfa_state(&ctx.pool, user_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("MFA state not found"))?;
    assert_eq!(state.state, MfaState::Enabled);
    assert_eq!(state.recovery_batch_id, Some(batch_id));

    Ok(())
}
