use admission_token::{PaserkKeySet, VerificationOptions, verify_v4_public};
use anyhow::{Context, Result, bail, ensure};
use reqwest::StatusCode;
use serde::Deserialize;
use sqlx::postgres::PgPoolOptions;
use std::{
    env,
    net::TcpListener,
    process::{Child, Command, Stdio},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::time::sleep;
use uuid::Uuid;

const DEFAULT_CLIENT_ID: &str = "00000000-0000-0000-0000-000000000000";

#[derive(Debug, Deserialize)]
struct TokenResponse {
    token: String,
}

struct TestConfig {
    dsn: String,
    vault_url: String,
    role_id: String,
    secret_id: String,
    client_id: String,
    port: u16,
}

struct ClaimsExpectations {
    issuer: String,
    audience: String,
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn env_fallback(primary: &str, fallback: &str) -> Result<String> {
    env::var(primary)
        .or_else(|_| env::var(fallback))
        .with_context(|| format!("Set {primary} or {fallback}"))
}

fn now_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| i64::try_from(duration.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

fn pick_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").context("Failed to bind a local port")?;
    Ok(listener
        .local_addr()
        .context("Failed to read local port")?
        .port())
}

fn claims_expectations() -> ClaimsExpectations {
    let issuer =
        env::var("GENESIS_ADMISSION_ISS").unwrap_or_else(|_| "https://genesis.permesi.dev".into());
    let audience = env::var("GENESIS_ADMISSION_AUD").unwrap_or_else(|_| "permesi".into());
    ClaimsExpectations { issuer, audience }
}

fn load_config() -> Result<TestConfig> {
    let dsn = env_fallback("GENESIS_TEST_DSN", "GENESIS_DSN")?;
    let vault_url = env_fallback("GENESIS_TEST_VAULT_URL", "GENESIS_VAULT_URL")?;
    let role_id = env_fallback("GENESIS_TEST_VAULT_ROLE_ID", "GENESIS_VAULT_ROLE_ID")?;
    let secret_id = env_fallback("GENESIS_TEST_VAULT_SECRET_ID", "GENESIS_VAULT_SECRET_ID")?;
    let client_id =
        env::var("GENESIS_TEST_CLIENT_ID").unwrap_or_else(|_| DEFAULT_CLIENT_ID.to_string());
    let port = env::var("GENESIS_TEST_PORT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(pick_port()?);
    Ok(TestConfig {
        dsn,
        vault_url,
        role_id,
        secret_id,
        client_id,
        port,
    })
}

fn spawn_genesis(config: &TestConfig) -> Result<ChildGuard> {
    let child = Command::new(env!("CARGO_BIN_EXE_genesis"))
        .args([
            "--port",
            &config.port.to_string(),
            "--dsn",
            &config.dsn,
            "--vault-url",
            &config.vault_url,
            "--vault-role-id",
            &config.role_id,
            "--vault-secret-id",
            &config.secret_id,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .context("Failed to spawn genesis binary")?;
    Ok(ChildGuard(child))
}

async fn wait_for_ready(client: &reqwest::Client, base: &str) -> Result<()> {
    for _ in 0..40 {
        match client.get(format!("{base}/health")).send().await {
            Ok(resp)
                if resp.status().is_success()
                    || resp.status() == StatusCode::SERVICE_UNAVAILABLE =>
            {
                return Ok(());
            }
            _ => sleep(Duration::from_millis(250)).await,
        }
    }
    bail!("genesis did not become ready at {base}");
}

async fn request_token(client: &reqwest::Client, base: &str, client_id: &str) -> Result<String> {
    let response = client
        .get(format!("{base}/token?client_id={client_id}"))
        .send()
        .await
        .context("Failed to request /token")?
        .error_for_status()
        .context("Genesis /token returned error")?;
    Ok(response
        .json::<TokenResponse>()
        .await
        .context("Failed to parse /token response")?
        .token)
}

async fn fetch_keyset(client: &reqwest::Client, base: &str) -> Result<PaserkKeySet> {
    let keyset_json = client
        .get(format!("{base}/paserk.json"))
        .send()
        .await
        .context("Failed to fetch /paserk.json")?
        .error_for_status()
        .context("Genesis /paserk.json returned error")?
        .text()
        .await
        .context("Failed to read /paserk.json body")?;
    let keyset = PaserkKeySet::from_json(&keyset_json).context("Invalid PASERK keyset JSON")?;
    keyset.validate().context("Invalid PASERK keyset")?;
    Ok(keyset)
}

fn verification_options(expectations: &ClaimsExpectations) -> VerificationOptions<'_> {
    VerificationOptions {
        expected_issuer: &expectations.issuer,
        expected_audience: &expectations.audience,
        expected_action: "admission",
        now_unix_seconds: now_unix_seconds(),
        min_ttl_seconds: 60,
        max_ttl_seconds: 180,
    }
}

#[tokio::test]
#[ignore = "requires Vault + Postgres 18; set GENESIS_TEST_* environment variables"]
async fn token_endpoint_mints_and_persists() -> Result<()> {
    let config = load_config()?;
    let base = format!("http://127.0.0.1:{}", config.port);

    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&config.dsn)
        .await
        .context("Failed to connect to GENESIS_TEST_DSN")?;
    let version: i32 = sqlx::query_scalar("SELECT current_setting('server_version_num')::int")
        .fetch_one(&pool)
        .await
        .context("Failed to read Postgres server_version_num")?;
    ensure!(
        version >= 180_000,
        "Postgres 18 required for integration test, got {version}"
    );

    let _child = spawn_genesis(&config)?;

    let client = reqwest::Client::new();
    wait_for_ready(&client, &base).await?;

    let token = request_token(&client, &base, &config.client_id).await?;
    let keyset = fetch_keyset(&client, &base).await?;
    let expectations = claims_expectations();
    let options = verification_options(&expectations);
    let claims =
        verify_v4_public(&token, &keyset, &options).context("Token verification failed")?;
    ensure!(
        claims.sub.as_deref() == Some(config.client_id.as_str()),
        "Token subject mismatch: expected {}, got {:?}",
        config.client_id,
        claims.sub
    );

    let token_id = Uuid::parse_str(&claims.jti).context("Token jti is not a UUID")?;
    let expected_uuid = Uuid::parse_str(&config.client_id).context("Client ID is not a UUID")?;
    let stored_uuid: Option<Uuid> = sqlx::query_scalar(
        "SELECT c.uuid FROM tokens t JOIN clients c ON t.client_id = c.id WHERE t.id = $1",
    )
    .bind(token_id)
    .fetch_optional(&pool)
    .await
    .context("Failed to query token row")?;
    ensure!(
        stored_uuid == Some(expected_uuid),
        "Token row missing or mismatched: {stored_uuid:?}"
    );

    let _ = sqlx::query("DELETE FROM tokens WHERE id = $1")
        .bind(token_id)
        .execute(&pool)
        .await;

    Ok(())
}
