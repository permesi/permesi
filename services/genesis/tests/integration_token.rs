use admission_token::{PaserkKeySet, VerificationOptions, verify_v4_public};
use anyhow::{Context, Result, bail, ensure};
use rcgen::{BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair};
use reqwest::StatusCode;
use serde::Deserialize;
use sqlx::postgres::PgPoolOptions;
use std::{
    env, fs,
    io::ErrorKind,
    net::TcpListener,
    net::{IpAddr, Ipv4Addr, SocketAddr},
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
    tls: TestTlsPaths,
    config: TestConfig,
}

struct ClaimsExpectations {
    issuer: String,
    audience: String,
}

struct ChildGuard(Child);

struct TestTlsPaths {
    ca: String,
    cert: String,
    key: String,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl TestContext {
    async fn new(tls: TestTlsPaths) -> Result<Self> {
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
            tls,
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

fn spawn_genesis(config: &TestConfig, tls: &TestTlsPaths) -> Result<ChildGuard> {
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
            "--tls-cert-path",
            &tls.cert,
            "--tls-key-path",
            &tls.key,
            "--tls-ca-path",
            &tls.ca,
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

fn prepare_tls_assets() -> Result<Option<TestTlsPaths>> {
    let tls_dir = env::temp_dir().join(format!("genesis-it-{}", Uuid::new_v4()));
    if let Err(err) = fs::create_dir_all(&tls_dir) {
        if err.kind() == ErrorKind::PermissionDenied {
            eprintln!("Skipping integration test: cannot write to temp TLS dir");
            return Ok(None);
        }
        return Err(err).context("Failed to create temp TLS directory");
    }
    let probe_path = tls_dir.join(".perm_check");
    match fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&probe_path)
    {
        Ok(_) => {
            let _ = fs::remove_file(&probe_path);
        }
        Err(err) if err.kind() == ErrorKind::PermissionDenied => {
            eprintln!("Skipping integration test: cannot write to temp TLS dir");
            return Ok(None);
        }
        Err(err) => return Err(err).context("Failed to probe temp TLS write access"),
    }

    let ca_key = KeyPair::generate().context("Failed to generate CA key")?;
    let mut ca_params = CertificateParams::new(vec!["genesis.permesi.localhost".to_string()])
        .context("Failed to build CA certificate params")?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "genesis-test-ca");
    let ca_cert = ca_params
        .self_signed(&ca_key)
        .context("Failed to build CA certificate")?;

    let leaf_key = KeyPair::generate().context("Failed to generate leaf key")?;
    let mut leaf_params = CertificateParams::new(vec!["genesis.permesi.localhost".to_string()])
        .context("Failed to build leaf certificate params")?;
    leaf_params.distinguished_name = DistinguishedName::new();
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "genesis.permesi.localhost");
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &ca_cert, &ca_key)
        .context("Failed to build leaf certificate")?;

    let ca_pem = ca_cert.pem();
    let leaf_pem = leaf_cert.pem();
    let leaf_key = leaf_key.serialize_pem();

    let ca_path = tls_dir.join("ca.pem");
    let cert_path = tls_dir.join("tls.crt");
    let key_path = tls_dir.join("tls.key");
    if let Err(err) = fs::write(&ca_path, ca_pem) {
        if err.kind() == ErrorKind::PermissionDenied {
            eprintln!("Skipping integration test: cannot write CA bundle");
            return Ok(None);
        }
        return Err(err).context("Failed to write CA bundle");
    }
    if let Err(err) = fs::write(&cert_path, leaf_pem) {
        if err.kind() == ErrorKind::PermissionDenied {
            eprintln!("Skipping integration test: cannot write TLS cert");
            return Ok(None);
        }
        return Err(err).context("Failed to write TLS cert");
    }
    if let Err(err) = fs::write(&key_path, leaf_key) {
        if err.kind() == ErrorKind::PermissionDenied {
            eprintln!("Skipping integration test: cannot write TLS key");
            return Ok(None);
        }
        return Err(err).context("Failed to write TLS key");
    }

    Ok(Some(TestTlsPaths {
        ca: ca_path.display().to_string(),
        cert: cert_path.display().to_string(),
        key: key_path.display().to_string(),
    }))
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

    let Some(tls) = prepare_tls_assets()? else {
        return Ok(());
    };

    let context = TestContext::new(tls).await?;
    let config = &context.config;
    let base = format!("https://genesis.permesi.localhost:{}", config.port);

    let admin_dsn = context.postgres.admin_dsn();
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&admin_dsn)
        .await
        .context("Failed to connect to Postgres")?;

    let _child = spawn_genesis(config, &context.tls)?;

    let ca_pem = fs::read(&context.tls.ca).context("Failed to read test CA bundle")?;
    let ca_cert = reqwest::Certificate::from_pem(&ca_pem).context("Failed to parse test CA")?;
    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .tls_certs_only(std::iter::once(ca_cert))
        .resolve(
            "genesis.permesi.localhost",
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), config.port),
        )
        .build()
        .context("Failed to build HTTPS client")?;
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
