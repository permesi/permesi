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
    http::{
        Request, StatusCode,
        header::{COOKIE, SET_COOKIE},
    },
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
        Self::with_capacity(5).await
    }

    /// Exercises guarded factor SQL even on a single shared connection.
    async fn with_capacity(capacity: u32) -> Result<Option<Self>> {
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
            .max_connections(capacity)
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
        .route("/v1/auth/mfa/totp/verify", post(super::totp_verify))
        .route("/v1/auth/mfa/recovery", post(super::mfa_recovery))
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

/// Uses the real shared limiter while preserving the normal session, factor and Vault dependencies.
fn limited_auth(limiter: crate::api::handlers::auth::RateLimiter) -> AuthState {
    let base = auth_state();
    AuthState::new(
        base.config().clone(),
        OpaqueState::from_seed(
            [0; 32],
            "api.permesi.dev".into(),
            Duration::from_secs(300),
            10000,
        ),
        Arc::new(limiter),
        base.mfa().clone(),
    )
}

/// Both factor routes enforce independent account/IP budgets and distinguish dependency failures.
#[tokio::test]
async fn mfa_http_verification_and_enrollment_enforce_shared_admission() -> Result<()> {
    use crate::api::handlers::auth::{RateLimitConfig, RateLimiter, SubjectKey, storage};
    let ctx = TestContext::new()
        .await?
        .context("MFA admission integration requires a container runtime")?;
    for (ip_limit, account_limit) in [(100, 1), (1, 100)] {
        for enrolling in [false, true] {
            sqlx::query("TRUNCATE auth_rate_limits")
                .execute(&ctx.pool)
                .await?;
            let email = format!("{}@example.com", Uuid::new_v4());
            let user = insert_active_user(&ctx.pool, &email).await?;
            let token = if enrolling {
                insert_session(&ctx.pool, user).await?
            } else {
                super::storage::upsert_mfa_state(&ctx.pool, user, MfaState::Enabled, None).await?;
                storage::insert_mfa_challenge_session(&ctx.pool, user, 300).await?
            };
            let app = app_router(
                limited_auth(RateLimiter::postgres(
                    ctx.pool.clone(),
                    RateLimitConfig::new(600, ip_limit, account_limit),
                    SubjectKey::derive(&[1; 32])?,
                )),
                ctx.pool.clone(),
                ctx.totp_service.clone(),
            );
            let uri = if enrolling {
                "/v1/auth/mfa/totp/enroll/start"
            } else {
                "/v1/auth/mfa/totp/verify"
            };
            let request = || {
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header(COOKIE, format!("permesi_session={token}"))
                    .header("Content-Type", "application/json")
                    .body(Body::from(json!({"code":"bogus"}).to_string()))
            };
            let first = app.clone().oneshot(request()?).await?;
            assert_eq!(
                first.status(),
                if enrolling {
                    StatusCode::OK
                } else {
                    StatusCode::BAD_REQUEST
                }
            );
            let rejected = app.oneshot(request()?).await?;
            assert_eq!(rejected.status(), StatusCode::TOO_MANY_REQUESTS);
            assert!(rejected.headers().get(SET_COOKIE).is_none());
            let unavailable = PgPoolOptions::new()
                .max_connections(1)
                .connect_with(ctx.pool.connect_options().as_ref().clone())
                .await?;
            unavailable.close().await;
            let app = app_router(
                limited_auth(RateLimiter::postgres(
                    unavailable,
                    RateLimitConfig::new(600, 100, 100),
                    SubjectKey::derive(&[1; 32])?,
                )),
                ctx.pool.clone(),
                ctx.totp_service.clone(),
            );
            let response = app.oneshot(request()?).await?;
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert!(response.headers().get(SET_COOKIE).is_none());
        }
    }
    Ok(())
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

    let cookie = response
        .headers()
        .get(SET_COOKIE)
        .context("replacement session cookie")?
        .to_str()?
        .split(';')
        .next()
        .context("cookie pair")?
        .to_string();
    // Enrollment consumes the original authority; only the replacement can access the profile.
    let stale = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/me")
                .header(COOKIE, format!("permesi_session={token}"))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(stale.status(), StatusCode::UNAUTHORIZED);
    // 4. Verify Profile State
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/me")
                .header(COOKIE, &cookie)
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

    // A recovery batch alone is not a factor: persist an actual confirmed TOTP credential.
    let (_, _, totp_id) = ctx.totp_service.enroll_begin(user_id, email, None).await?;
    crate::totp::repo::TotpRepo::confirm_credential(&ctx.pool, user_id, totp_id).await?;
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

/// A stored confirmed credential is never accepted as new proof, even with a valid bootstrap cookie.
#[tokio::test]
async fn mfa_enrollment_rejects_confirmed_credential_without_fresh_proof() -> Result<()> {
    let Some(ctx) = TestContext::with_capacity(1).await? else {
        return Ok(());
    };
    let user = insert_active_user(&ctx.pool, "confirmed@example.com").await?;
    let (secret, _qr, credential) = ctx
        .totp_service
        .enroll_begin(user, "confirmed@example.com", None)
        .await?;
    crate::totp::repo::TotpRepo::confirm_credential(&ctx.pool, user, credential).await?;
    super::storage::upsert_mfa_state(&ctx.pool, user, MfaState::RequiredUnenrolled, None).await?;
    let bootstrap =
        crate::api::handlers::auth::storage::insert_mfa_bootstrap_session(&ctx.pool, user, 300)
            .await?;
    let app = app_router(auth_state(), ctx.pool.clone(), ctx.totp_service.clone());
    for code in [
        "bogus".to_owned(),
        current_totp(&secret, "confirmed@example.com")?,
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/auth/mfa/totp/enroll/finish")
                    .header(COOKIE, format!("permesi_session={bootstrap}"))
                    .header("Content-Type", "application/json")
                    .body(Body::from(serde_json::to_vec(
                        &json!({"credential_id":credential,"code":code}),
                    )?))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(response.headers().get(SET_COOKIE).is_none());
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM user_sessions WHERE user_id=$1")
                .bind(user)
                .fetch_one(&ctx.pool)
                .await?,
            0
        );
    }
    Ok(())
}

/// Rejected codes retain durable failure audit without consuming or upgrading the original session.
#[tokio::test]
async fn mfa_rejected_totp_proofs_commit_failure_audits_without_authority() -> Result<()> {
    let Some(ctx) = TestContext::with_capacity(1).await? else {
        return Ok(());
    };
    let user = insert_active_user(&ctx.pool, "audit@example.com").await?;
    let (_, _, credential) = ctx
        .totp_service
        .enroll_begin(user, "audit@example.com", None)
        .await?;
    super::storage::upsert_mfa_state(&ctx.pool, user, MfaState::RequiredUnenrolled, None).await?;
    let bootstrap =
        crate::api::handlers::auth::storage::insert_mfa_bootstrap_session(&ctx.pool, user, 300)
            .await?;
    let challenge =
        crate::api::handlers::auth::storage::insert_mfa_challenge_session(&ctx.pool, user, 300)
            .await?;
    let app = app_router(auth_state(), ctx.pool.clone(), ctx.totp_service.clone());
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/mfa/totp/enroll/finish")
                .header(COOKIE, format!("permesi_session={bootstrap}"))
                .header("Content-Type", "application/json")
                .body(Body::from(
                    json!({"credential_id":credential,"code":"bogus"}).to_string(),
                ))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(response.headers().get(SET_COOKIE).is_none());
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM totp_audit_log WHERE user_id=$1 AND action='confirm_fail'"
        )
        .bind(user)
        .fetch_one(&ctx.pool)
        .await?,
        1
    );
    crate::totp::repo::TotpRepo::confirm_credential(&ctx.pool, user, credential).await?;
    crate::api::handlers::auth::mfa::storage::upsert_mfa_state(
        &ctx.pool,
        user,
        crate::api::handlers::auth::mfa::MfaState::Enabled,
        None,
    )
    .await?;
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/mfa/totp/verify")
                .header(COOKIE, format!("permesi_session={challenge}"))
                .header("Content-Type", "application/json")
                .body(Body::from(json!({"code":"bogus"}).to_string()))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(response.headers().get(SET_COOKIE).is_none());
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM totp_audit_log WHERE user_id=$1 AND action='verify_failure'"
        )
        .bind(user)
        .fetch_one(&ctx.pool)
        .await?,
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM user_sessions WHERE user_id=$1")
            .bind(user)
            .fetch_one(&ctx.pool)
            .await?,
        0
    );
    Ok(())
}

#[tokio::test]
async fn password_rotation_blocks_revoked_mfa_routes_and_removes_unconfirmed_totp() -> Result<()> {
    let Some(ctx) = TestContext::with_capacity(1).await? else {
        return Ok(());
    };
    let user = insert_active_user(&ctx.pool, "rotation@example.com").await?;
    super::storage::upsert_mfa_state(&ctx.pool, user, MfaState::RequiredUnenrolled, None).await?;
    let bootstrap =
        crate::api::handlers::auth::storage::insert_mfa_bootstrap_session(&ctx.pool, user, 300)
            .await?;
    let challenge =
        crate::api::handlers::auth::storage::insert_mfa_challenge_session(&ctx.pool, user, 300)
            .await?;
    let (_secret, _qr, credential) = ctx
        .totp_service
        .enroll_begin(user, "rotation@example.com", None)
        .await?;
    let app = app_router(auth_state(), ctx.pool.clone(), ctx.totp_service.clone());
    crate::api::handlers::auth::storage::rotate_password_and_clear_sessions(
        &ctx.pool, user, &[2; 32],
    )
    .await?;
    for (path, token, body) in [
        ("/v1/auth/mfa/totp/enroll/start", &bootstrap, json!({})),
        (
            "/v1/auth/mfa/totp/enroll/finish",
            &bootstrap,
            json!({"credential_id":credential,"code":"123456"}),
        ),
        (
            "/v1/auth/mfa/totp/verify",
            &challenge,
            json!({"code":"123456"}),
        ),
        (
            "/v1/auth/mfa/recovery",
            &challenge,
            json!({"code":"old-code"}),
        ),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(path)
                    .header(COOKIE, format!("permesi_session={token}"))
                    .header("Content-Type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body)?))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{path}");
        assert!(response.headers().get(SET_COOKIE).is_none());
    }
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM totp_credentials WHERE user_id=$1")
            .bind(user)
            .fetch_one(&ctx.pool)
            .await?,
        0
    );
    Ok(())
}

/// Generates real proof from the server's returned enrollment secret, including confirmed-row probes.
fn current_totp(secret: &str, email: &str) -> Result<String> {
    let secret = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, secret)
        .ok_or_else(|| anyhow!("invalid TOTP secret"))?;
    Ok(totp_rs::Builder::new()
        .with_algorithm(totp_rs::Algorithm::SHA1)
        .with_digits(6)
        .with_skew(1)
        .with_step_duration(30)
        .with_secret(secret)
        .with_issuer(Some("Permesi"))
        .with_account_name(email)
        .build()
        .map_err(|_| anyhow!("invalid test TOTP"))?
        .generate_current()
        .to_string())
}

/// Completing one enrollment revokes every earlier bootstrap and its in-flight factor authority.
#[tokio::test]
async fn mfa_totp_completion_revokes_other_bootstraps_and_pending_enrollment() -> Result<()> {
    let Some(ctx) = TestContext::with_capacity(1).await? else {
        return Ok(());
    };
    let email = "bootstrap-revocation@example.com";
    let user = insert_active_user(&ctx.pool, email).await?;
    super::storage::upsert_mfa_state(&ctx.pool, user, MfaState::RequiredUnenrolled, None).await?;
    let first =
        crate::api::handlers::auth::storage::insert_mfa_bootstrap_session(&ctx.pool, user, 300)
            .await?;
    let stale =
        crate::api::handlers::auth::storage::insert_mfa_bootstrap_session(&ctx.pool, user, 300)
            .await?;
    let (secret, _, credential) = ctx.totp_service.enroll_begin(user, email, None).await?;
    let app = app_router(auth_state(), ctx.pool.clone(), ctx.totp_service.clone());
    let payload =
        json!({"credential_id":credential,"code":current_totp(&secret,email)?}).to_string();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/mfa/totp/enroll/finish")
                .header(COOKIE, format!("permesi_session={first}"))
                .header("Content-Type", "application/json")
                .body(Body::from(payload.clone()))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get(SET_COOKIE).is_some());
    for (method, path, body) in [
        (
            "POST",
            "/v1/auth/mfa/totp/enroll/start".to_owned(),
            "{}".to_owned(),
        ),
        (
            "POST",
            "/v1/auth/mfa/totp/enroll/finish".to_owned(),
            payload,
        ),
        (
            "DELETE",
            format!("/v1/me/mfa/webauthn/{}", Uuid::new_v4()),
            String::new(),
        ),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header(COOKIE, format!("permesi_session={stale}"))
                    .header("Content-Type", "application/json")
                    .body(Body::from(body))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response.headers().get(SET_COOKIE).is_none());
    }
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM user_mfa_bootstrap_sessions WHERE user_id=$1"
        )
        .bind(user)
        .fetch_one(&ctx.pool)
        .await?,
        0
    );
    Ok(())
}

/// Real recovery proof revokes full, challenge and previous bootstrap authority in one commit.
#[tokio::test]
async fn mfa_recovery_revokes_all_previous_sessions_and_consumes_its_code() -> Result<()> {
    let Some(ctx) = TestContext::with_capacity(1).await? else {
        return Ok(());
    };
    let user = insert_active_user(&ctx.pool, "recovery@example.com").await?;
    let auth = auth_state();
    let batch = super::recovery::RecoveryCodeBatch::generate(
        auth.mfa().recovery_pepper().context("pepper")?,
    )?;
    let mut tx = ctx.pool.begin().await?;
    super::storage::insert_recovery_codes_on(&mut tx, user, batch.batch_id, &batch.code_hashes)
        .await?;
    super::storage::upsert_mfa_state(&mut *tx, user, MfaState::Enabled, Some(batch.batch_id))
        .await?;
    tx.commit().await?;
    let _full = insert_session(&ctx.pool, user).await?;
    let challenge =
        crate::api::handlers::auth::storage::insert_mfa_challenge_session(&ctx.pool, user, 300)
            .await?;
    let _other =
        crate::api::handlers::auth::storage::insert_mfa_challenge_session(&ctx.pool, user, 300)
            .await?;
    let _bootstrap =
        crate::api::handlers::auth::storage::insert_mfa_bootstrap_session(&ctx.pool, user, 300)
            .await?;
    let app = app_router(auth, ctx.pool.clone(), ctx.totp_service.clone());
    let code = batch.codes.first().context("recovery code")?;
    let request = || {
        Request::builder()
            .method("POST")
            .uri("/v1/auth/mfa/recovery")
            .header(COOKIE, format!("permesi_session={challenge}"))
            .header("Content-Type", "application/json")
            .body(Body::from(json!({"code":code}).to_string()))
    };
    let response = app.clone().oneshot(request()?).await?;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let cookie = response
        .headers()
        .get(SET_COOKIE)
        .context("bootstrap cookie")?
        .to_str()?;
    let token = cookie
        .split(';')
        .next()
        .context("cookie pair")?
        .strip_prefix("permesi_session=")
        .context("cookie token")?;
    assert_eq!(
        crate::api::handlers::auth::session_kind::SessionKind::from_token(token),
        crate::api::handlers::auth::session_kind::SessionKind::MfaBootstrap
    );
    let row: (i64,i64,i64,i64) = sqlx::query_as("SELECT (SELECT COUNT(*) FROM user_sessions WHERE user_id=$1),(SELECT COUNT(*) FROM user_mfa_challenge_sessions WHERE user_id=$1),(SELECT COUNT(*) FROM user_mfa_bootstrap_sessions WHERE user_id=$1),(SELECT COUNT(*) FROM user_mfa_recovery_codes WHERE user_id=$1 AND used_at IS NOT NULL)").bind(user).fetch_one(&ctx.pool).await?;
    assert_eq!(row, (0, 0, 1, 1));
    assert_eq!(
        super::storage::load_mfa_state(&ctx.pool, user)
            .await?
            .context("state")?
            .state,
        MfaState::RequiredUnenrolled
    );
    assert_eq!(
        app.oneshot(request()?).await?.status(),
        StatusCode::UNAUTHORIZED
    );
    Ok(())
}
