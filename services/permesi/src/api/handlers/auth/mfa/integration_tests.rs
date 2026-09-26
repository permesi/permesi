#![allow(clippy::expect_used)]

use crate::{
    api::handlers::auth::{
        AuthConfig, AuthState, OpaqueState,
        mfa::{MfaConfig, MfaState},
        utils::{generate_session_token, hash_session_token},
    },
    cli::globals::GlobalArgs,
    totp::{DekManager, TotpService},
};
use anyhow::{Context, Result, anyhow};
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::FromRef,
    http::{Request, StatusCode, header::COOKIE},
    routing::{delete, get, post},
};
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
    /// Returns `None` only when no container runtime is available; any other setup
    /// failure is an error so a broken fixture fails the test instead of skipping it.
    async fn new() -> Result<Option<Self>> {
        if let Err(err) = runtime::ensure_container_runtime() {
            eprintln!("Skipping integration test: {err}");
            return Ok(None);
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

        // Vault dev mode already mounts KV v2 at `secret/`, so a nested `secret/permesi`
        // mount is rejected; store the config under the existing mount instead.
        vault
            .write_kv_v2(
                "secret",
                "permesi/config",
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
        let vurl = vault.base_url().to_string();
        let target = vault_client::VaultTarget::parse(&vurl).expect("test vault URL is valid");
        let transport = vault_client::VaultTransport::from_target("test", target)
            .expect("test transport built");
        let mut globals = GlobalArgs::new(vurl, transport);
        globals.set_token(SecretString::from("root-token".to_string()));
        globals.vault_transit_mount = "transit/permesi".to_string();

        let dek_manager = DekManager::new(globals);

        // Rotate DEK to generate initial key (since init() only loads existing)
        dek_manager.rotate(&pool).await?;

        let totp_service = TotpService::new(dek_manager, pool.clone(), "Permesi".to_string());

        Ok(Some(Self {
            _postgres: postgres,
            _vault: vault,
            pool,
            totp_service,
        }))
    }
}

async fn apply_schema(postgres: &PostgresContainer) -> Result<()> {
    let mut connection = PgConnection::connect(&postgres.admin_dsn())
        .await
        .context("failed to connect for schema setup")?;

    // Apply Base Schema
    test_support::sql::execute_script(&mut connection, "02_permesi.sql", PERMESI_SCHEMA_SQL)
        .await?;

    Ok(())
}

fn auth_state() -> AuthState {
    let config = AuthConfig::new("https://permesi.dev".to_string())
        .with_email_token_ttl_seconds(60)
        .with_resend_cooldown_seconds(300);
    let opaque_state = OpaqueState::from_seed(
        [0u8; 32],
        "api.permesi.dev".to_string(),
        Duration::from_mins(5),
        10_000,
    );
    AuthState::new(
        config,
        opaque_state,
        std::sync::Arc::new(crate::api::handlers::auth::RateLimiter::noop()),
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

/// Router state for the MFA handlers; `FromRef` hands each handler the parts it extracts.
#[derive(Clone, FromRef)]
struct MfaTestState {
    auth: std::sync::Arc<AuthState>,
    pool: PgPool,
    totp: TotpService,
}

/// Router state for the session handler.
#[derive(Clone, FromRef)]
struct SessionTestState {
    auth: std::sync::Arc<AuthState>,
    pool: PgPool,
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
        .route(
            "/v1/me/mfa/totp",
            delete(crate::api::handlers::me::disable_totp),
        )
        .route("/v1/me", get(crate::api::handlers::me::get_me))
        .with_state(MfaTestState {
            auth: std::sync::Arc::new(auth_state),
            pool,
            totp: totp_service,
        })
}

#[tokio::test]
async fn mfa_enrollment_flow() -> Result<()> {
    let Some(ctx) = TestContext::new().await? else {
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

    // The secret is unpadded RFC 4648 base32 (`TotpService::enroll_start`). Do not try
    // base64 first: base32 text is often valid base64 too and would decode to the wrong key.
    let secret_bytes = base32::decode(
        base32::Alphabet::Rfc4648 { padding: false },
        &start_data.secret,
    )
    .ok_or_else(|| anyhow!("Invalid base32 secret"))?;

    // 2. Generate Code
    let totp = totp_rs::Builder::new()
        .with_algorithm(totp_rs::Algorithm::SHA1)
        .with_digits(6)
        .with_skew(1)
        .with_step_duration(30)
        .with_secret(secret_bytes)
        .with_issuer(Some("Permesi"))
        .with_account_name(email)
        .build()
        .map_err(|e| anyhow!("Failed to create TOTP: {e}"))?;
    let code = totp.generate_current().to_string();

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
    let Some(ctx) = TestContext::new().await? else {
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
        .ok_or_else(|| anyhow!("MFA state not found"))?;
    assert_eq!(state.state, MfaState::Disabled);

    Ok(())
}

#[tokio::test]
async fn security_key_preserves_totp() -> Result<()> {
    let Some(ctx) = TestContext::new().await? else {
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
        .ok_or_else(|| anyhow!("MFA state not found"))?;
    assert_eq!(state.state, MfaState::Enabled);
    assert_eq!(state.recovery_batch_id, Some(batch_id));

    Ok(())
}

#[tokio::test]
async fn security_key_delete_rejects_invalid_hex_credential_id() -> Result<()> {
    let Some(ctx) = TestContext::new().await? else {
        return Ok(());
    };

    let email = "invalid-key-id@example.com";
    let user_id = insert_active_user(&ctx.pool, email).await?;
    let token = insert_session(&ctx.pool, user_id).await?;

    let app = app_router(auth_state(), ctx.pool.clone(), ctx.totp_service.clone());
    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/v1/me/mfa/webauthn/0")
                .header(COOKIE, format!("permesi_session={token}"))
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
async fn totp_deletion_preserves_security_key() -> Result<()> {
    let Some(ctx) = TestContext::new().await? else {
        return Ok(());
    };

    let email = "totp_del@example.com";
    let user_id = insert_active_user(&ctx.pool, email).await?;
    let token = insert_session(&ctx.pool, user_id).await?;

    // 1. Insert fake security key
    let cred_id = vec![9u8, 10, 11, 12];
    sqlx::query(
        "INSERT INTO security_keys (credential_id, user_id, label, public_key, sign_count) VALUES ($1, $2, 'test', $3, 0)"
    )
    .bind(&cred_id)
    .bind(user_id)
    .bind(vec![0u8; 32])
    .execute(&ctx.pool)
    .await?;

    // 2. Enable MFA with TOTP (recovery batch)
    let batch_id = Uuid::new_v4();
    super::storage::upsert_mfa_state(&ctx.pool, user_id, MfaState::Enabled, Some(batch_id)).await?;

    let app = app_router(auth_state(), ctx.pool.clone(), ctx.totp_service.clone());

    // 3. Call disable_totp
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/v1/me/mfa/totp")
                .header(COOKIE, format!("permesi_session={token}"))
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // 4. Verify MFA STILL enabled (because of security key)
    let state = super::storage::load_mfa_state(&ctx.pool, user_id)
        .await?
        .ok_or_else(|| anyhow!("MFA state not found"))?;
    assert_eq!(state.state, MfaState::Enabled);
    assert!(
        state.recovery_batch_id.is_none(),
        "Recovery batch should be cleared"
    );

    Ok(())
}

#[tokio::test]
async fn totp_deletion_disables_mfa_when_no_keys() -> Result<()> {
    let Some(ctx) = TestContext::new().await? else {
        return Ok(());
    };

    let email = "totp_only@example.com";
    let user_id = insert_active_user(&ctx.pool, email).await?;
    let token = insert_session(&ctx.pool, user_id).await?;

    // 1. Enable MFA with TOTP only
    let batch_id = Uuid::new_v4();
    super::storage::upsert_mfa_state(&ctx.pool, user_id, MfaState::Enabled, Some(batch_id)).await?;

    let app = app_router(auth_state(), ctx.pool.clone(), ctx.totp_service.clone());

    // 2. Call disable_totp
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/v1/me/mfa/totp")
                .header(COOKIE, format!("permesi_session={token}"))
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // 3. Verify MFA IS disabled
    let state = super::storage::load_mfa_state(&ctx.pool, user_id)
        .await?
        .ok_or_else(|| anyhow!("MFA state not found"))?;
    assert_eq!(state.state, MfaState::Disabled);

    Ok(())
}

#[tokio::test]
async fn session_response_includes_mfa_flags() -> Result<()> {
    let Some(ctx) = TestContext::new().await? else {
        return Ok(());
    };

    let email = "flags@example.com";
    let user_id = insert_active_user(&ctx.pool, email).await?;
    let token = insert_session(&ctx.pool, user_id).await?;

    // 1. Setup both factors
    let cred_id = vec![1u8, 3, 3, 7];
    sqlx::query(
        "INSERT INTO security_keys (credential_id, user_id, label, public_key, sign_count) VALUES ($1, $2, 'test', $3, 0)"
    )
    .bind(&cred_id)
    .bind(user_id)
    .bind(vec![0u8; 32])
    .execute(&ctx.pool)
    .await?;

    let batch_id = Uuid::new_v4();
    super::storage::upsert_mfa_state(&ctx.pool, user_id, MfaState::Enabled, Some(batch_id)).await?;

    // 2. Fetch session
    let app = Router::new()
        .route(
            "/v1/auth/session",
            get(crate::api::handlers::auth::session::session),
        )
        .with_state(SessionTestState {
            auth: std::sync::Arc::new(auth_state()),
            pool: ctx.pool.clone(),
        });

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/auth/session")
                .header(COOKIE, format!("permesi_session={token}"))
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await?;
    let session: crate::api::handlers::auth::types::SessionResponse =
        serde_json::from_slice(&body)?;

    assert!(session.totp_enabled);
    assert!(session.webauthn_enabled);

    Ok(())
}
