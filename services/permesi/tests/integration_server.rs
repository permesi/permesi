//! Integration tests for the Permesi IAM service.
//!
//! This suite verifies the full startup and dependency integration of the
//! `permesi` binary by:
//! 1. Orchestrating transient infrastructure (Postgres and Vault containers).
//! 2. Providing a static PASERK keyset to the service.
//! 3. Provisioning Vault with required OPAQUE seeds and database engine.
//! 4. Spawning the actual `permesi` binary as a supervised child process.
//! 5. Executing real HTTPS requests against the running service.

use anyhow::{Context, Result, bail};
use rcgen::{CertificateParams, KeyPair};
use reqwest::StatusCode;
use serde_json::json;
use sqlx::{Connection, PgConnection};
use std::{
    env, fs,
    io::ErrorKind,
    net::TcpListener,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    process::{Child, Command, Stdio},
    time::Duration,
};
use test_support::{TestNetwork, postgres::PostgresContainer, runtime, vault::VaultContainer};
use tokio::time::sleep;
use uuid::Uuid;

const PERMESI_SCHEMA_SQL: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../db/sql/02_permesi.sql"
));

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct TestTlsPaths {
    _ca: String,
    bundle: String,
}

struct TestContext {
    _postgres: PostgresContainer,
    _vault: VaultContainer,
    tls: TestTlsPaths,
    port: u16,
    vault_url: String,
    role_id: String,
    secret_id: String,
    dsn: String,
}

impl TestContext {
    async fn new(tls: TestTlsPaths) -> Result<Self> {
        let network = TestNetwork::new("permesi-it");

        // 1. Setup Postgres
        let postgres = PostgresContainer::start(network.name()).await?;
        postgres.wait_until_ready().await?;

        let mut admin = PgConnection::connect(&postgres.admin_dsn())
            .await
            .context("Failed to connect to Postgres admin DB")?;

        sqlx::query("CREATE ROLE vault_permesi WITH LOGIN PASSWORD 'vault_permesi' CREATEROLE")
            .execute(&mut admin)
            .await?;
        sqlx::query("GRANT pg_signal_backend TO vault_permesi")
            .execute(&mut admin)
            .await?;
        sqlx::query("CREATE DATABASE permesi OWNER vault_permesi")
            .execute(&mut admin)
            .await?;

        let mut permesi_conn = PgConnection::connect(&postgres.admin_dsn_for_db("permesi"))
            .await
            .context("Failed to connect to permesi DB for schema setup")?;
        apply_schema(&mut permesi_conn, PERMESI_SCHEMA_SQL).await?;

        bootstrap_runtime_role(&mut permesi_conn).await?;

        // 2. Setup Vault
        let vault = VaultContainer::start(network.name()).await?;
        vault.enable_secrets_engine("database", "database").await?;

        // Setup Transit
        vault
            .enable_secrets_engine("transit/permesi", "transit")
            .await?;
        vault
            .create_transit_key("transit/permesi", "totp", "chacha20-poly1305")
            .await?;

        // Provision OPAQUE seed and pepper
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

        // 3. Configure Database Engine
        let db_config = test_support::vault::DatabaseConfig::new(
            postgres.vault_connection_url_for_db("permesi"),
            "vault_permesi",
            "vault_permesi",
            vec!["permesi".to_string()],
        );
        vault
            .configure_database_connection("permesi", &db_config)
            .await?;

        let creation = vec![
            r#"CREATE ROLE "{{name}}" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';"#.to_string(),
            r#"GRANT permesi_runtime TO "{{name}}";"#.to_string(),
        ];
        vault
            .create_database_role("permesi", "permesi", &creation, "1h", "4h")
            .await?;

        // 4. Configure AppRole
        vault.enable_auth("approle", "approle").await?;
        let policy = r#" 
path "database/creds/permesi" {
  capabilities = ["read"]
}
path "secret/data/permesi/config" {
  capabilities = ["read"]
}
path "auth/token/renew-self" {
  capabilities = ["update"]
}
path "sys/leases/renew" {
  capabilities = ["update"]
}
path "transit/permesi/datakey/plaintext/totp" {
  capabilities = ["update"]
}
path "transit/permesi/decrypt/totp" {
  capabilities = ["update"]
}
"#;
        vault.write_policy("permesi-runtime", policy).await?;

        vault
            .create_approle("approle", "permesi", &["permesi-runtime"])
            .await?;
        let role_id = vault.read_role_id("approle", "permesi").await?;
        let secret_id = vault.create_secret_id("approle", "permesi").await?;

        let vault_url = vault.login_url("approle");
        let dsn = format!(
            "postgres://127.0.0.1:{}/permesi?sslmode=disable",
            postgres.host_port()
        );

        Ok(Self {
            _postgres: postgres,
            _vault: vault,
            tls,
            port: pick_port()?,
            vault_url,
            role_id,
            secret_id,
            dsn,
        })
    }
}

async fn bootstrap_runtime_role(conn: &mut PgConnection) -> Result<()> {
    sqlx::query("CREATE ROLE permesi_runtime NOLOGIN")
        .execute(&mut *conn)
        .await?;
    sqlx::query("GRANT permesi_runtime TO vault_permesi WITH ADMIN OPTION")
        .execute(&mut *conn)
        .await?;
    sqlx::query("GRANT CONNECT, TEMPORARY ON DATABASE permesi TO permesi_runtime")
        .execute(&mut *conn)
        .await?;
    sqlx::query("GRANT USAGE ON SCHEMA public TO permesi_runtime")
        .execute(&mut *conn)
        .await?;
    sqlx::query("GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO permesi_runtime")
        .execute(&mut *conn)
        .await?;
    sqlx::query("GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO permesi_runtime")
        .execute(&mut *conn)
        .await?;
    Ok(())
}

async fn apply_schema(connection: &mut PgConnection, sql: &str) -> Result<()> {
    for (index, statement) in split_sql_statements(sql).iter().enumerate() {
        sqlx::query(statement)
            .execute(&mut *connection)
            .await
            .with_context(|| format!("Failed to execute schema statement {}", index + 1))?;
    }
    Ok(())
}

fn split_sql_statements(sql: &str) -> Vec<String> {
    let mut statements = Vec::new();
    let mut current = String::new();
    let mut in_dollar_quote = false;

    for line in sql.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with(r"\ir ") {
            continue;
        }
        current.push_str(line);
        current.push('\n');

        let dollar_markers = line.match_indices("$$").count();
        if dollar_markers % 2 == 1 {
            in_dollar_quote = !in_dollar_quote;
        }

        if !in_dollar_quote && trimmed.ends_with(';') {
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

fn pick_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").context("Failed to bind a local port")?;
    Ok(listener
        .local_addr()
        .context("Failed to read local port")?
        .port())
}

fn prepare_tls_assets() -> Result<Option<TestTlsPaths>> {
    let tls_dir = env::temp_dir().join(format!("permesi-it-{}", Uuid::new_v4()));
    if let Err(err) = fs::create_dir_all(&tls_dir) {
        if err.kind() == ErrorKind::PermissionDenied {
            return Ok(None);
        }
        return Err(err).context("Failed to create temp TLS directory");
    }

    let key_pair = KeyPair::generate()?;
    let params = CertificateParams::new(vec!["api.permesi.localhost".to_string()])
        .context("Failed to build certificate params")?;
    let cert = params
        .self_signed(&key_pair)
        .context("Failed to generate self-signed cert")?;

    let ca_path = tls_dir.join("ca.pem");
    let bundle_path = tls_dir.join("tls.bundle.pem");

    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    fs::write(&ca_path, &cert_pem)?;

    let mut bundle_content = String::new();
    bundle_content.push_str(&key_pem);
    bundle_content.push_str(&cert_pem);

    fs::write(&bundle_path, bundle_content)?;

    Ok(Some(TestTlsPaths {
        _ca: ca_path.display().to_string(),
        bundle: bundle_path.display().to_string(),
    }))
}

async fn wait_for_ready(client: &reqwest::Client, base: &str) -> Result<()> {
    for _ in 0..40 {
        match client.get(format!("{base}/health")).send().await {
            Ok(resp) if resp.status().is_success() => return Ok(()),
            _ => sleep(Duration::from_millis(250)).await,
        }
    }
    bail!("permesi did not become ready at {base}");
}

#[tokio::test]
async fn server_starts_and_connects_to_deps() -> Result<()> {
    if let Err(err) = runtime::ensure_container_runtime() {
        eprintln!("Skipping integration test: {err}");
        return Ok(());
    }

    let Some(tls) = prepare_tls_assets()? else {
        return Ok(());
    };

    let keyset_json = json!({
        "version": "v4",
        "purpose": "public",
        "active_kid": "k4.pid.9ShR3xc8-qVJ_di0tc9nx0IDIqbatdeM2mqLFBJsKRHs",
        "keys": [
            {
                "kid": "k4.pid.9ShR3xc8-qVJ_di0tc9nx0IDIqbatdeM2mqLFBJsKRHs",
                "paserk": "k4.public.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8"
            }
        ]
    })
    .to_string();

    let ctx = TestContext::new(tls).await?;
    let base = format!("https://api.permesi.localhost:{}", ctx.port);

    // 2. Spawn binary
    let mut command = Command::new(env!("CARGO_BIN_EXE_permesi"));
    command.env("PERMESI_LOG_LEVEL", "debug");
    // Clear conflicting env vars that might leak from the host
    command.env_remove("PERMESI_VAULT_SECRET_ID");
    command.env_remove("PERMESI_VAULT_WRAPPED_TOKEN");

    let _child = ChildGuard(
        command
            .args([
                "--port",
                &ctx.port.to_string(),
                "--dsn",
                &ctx.dsn,
                "--vault-url",
                &ctx.vault_url,
                "--vault-role-id",
                &ctx.role_id,
                "--vault-secret-id",
                &ctx.secret_id,
                "--tls-pem-bundle",
                &ctx.tls.bundle,
                "--admission-paserk-url",
                &keyset_json,
                "--vault-kv-mount",
                "secret",
                "--vault-kv-path",
                "permesi/config",
            ])
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .context("Failed to spawn permesi binary")?,
    );

    // 3. Verify connectivity
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .resolve(
            "api.permesi.localhost",
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), ctx.port),
        )
        .build()?;

    wait_for_ready(&client, &base).await?;

    let resp = client.get(format!("{base}/health")).send().await?;
    assert_eq!(resp.status(), StatusCode::OK);

    Ok(())
}
