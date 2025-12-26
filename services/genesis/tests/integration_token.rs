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
use test_support::{
    TestNetwork, genesis as genesis_support, postgres::PostgresContainer, runtime,
    vault::VaultContainer,
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
    wrapped_token: String,
    client_id: String,
    port: u16,
}

struct TestContext {
    postgres: PostgresContainer,
    _vault: VaultContainer,
    config: TestConfig,
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

impl TestContext {
    async fn new() -> Result<Self> {
        let network = TestNetwork::new("genesis-it");

        let postgres = PostgresContainer::start(network.name()).await?;
        postgres.wait_until_ready().await?;
        genesis_support::apply_genesis_schema(&postgres).await?;

        let vault = VaultContainer::start(network.name()).await?;
        let vault_config = genesis_support::configure_genesis_vault(&vault, &postgres).await?;

        let config = TestConfig {
            dsn: postgres.dsn(),
            vault_url: vault_config.login_url,
            role_id: vault_config.role_id,
            wrapped_token: vault_config.wrapped_secret_id,
            client_id: DEFAULT_CLIENT_ID.to_string(),
            port: pick_port()?,
        };

        Ok(Self {
            postgres,
            _vault: vault,
            config,
        })
    }
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

fn spawn_genesis(config: &TestConfig) -> Result<ChildGuard> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_genesis"));
    // Default to info logs so CI failures include useful context.
    if env::var("GENESIS_LOG_LEVEL").is_err() {
        command.env("GENESIS_LOG_LEVEL", "info");
    }
    let child = command
        .args([
            "--port",
            &config.port.to_string(),
            "--dsn",
            &config.dsn,
            "--vault-url",
            &config.vault_url,
            "--vault-role-id",
            &config.role_id,
            "--vault-wrapped-token",
            &config.wrapped_token,
        ])
        .stdout(Stdio::inherit())
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
async fn token_endpoint_mints_and_persists() -> Result<()> {
    if let Err(err) = runtime::ensure_container_runtime() {
        eprintln!("Skipping integration test: {err}");
        return Ok(());
    }

    let context = TestContext::new().await?;
    let config = &context.config;
    let base = format!("http://127.0.0.1:{}", config.port);

    let admin_dsn = context.postgres.admin_dsn();
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&admin_dsn)
        .await
        .context("Failed to connect to Postgres")?;

    let _child = spawn_genesis(config)?;

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
