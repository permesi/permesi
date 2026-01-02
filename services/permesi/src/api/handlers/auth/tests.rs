//! Auth module tests.

use super::AuthConfig;
use super::state::OpaqueSuite;
use super::storage::{
    ResendOutcome, SignupOutcome, consume_verification_token, enqueue_resend_verification,
    insert_user_and_verification, insert_verification_records,
};
use super::utils::{
    build_verify_url, decode_base64_field, generate_verification_token, hash_verification_token,
    normalize_email, valid_email,
};
use super::zero_token::{ZeroTokenError, zero_token_error_response};
use anyhow::{Context, Result, anyhow};
use axum::http::StatusCode;
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use opaque_ke::{ClientRegistration, ClientRegistrationFinishParameters, Identifiers};
use opaque_ke::{ServerRegistration, ServerSetup};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sqlx::{Connection, PgConnection, PgPool, Row, postgres::PgPoolOptions};
use test_support::{TestNetwork, postgres::PostgresContainer, runtime};
use uuid::Uuid;

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
