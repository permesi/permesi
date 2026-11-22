//! Integration tests for the Permesi IAM service.
//!
//! This suite verifies the full startup and dependency integration of the
//! `permesi` binary by:
//! 1. Orchestrating transient infrastructure (Postgres and OpenBao containers).
//! 2. Publishing approved Ed25519 metadata in core OpenBao.
//! 3. Provisioning OpenBao with required OPAQUE seeds and database engine.
//! 4. Spawning the actual `permesi` binary as a supervised child process.
//! 5. Executing real HTTPS requests against the running service.

use anyhow::{Context, Result, bail};
use rcgen::{CertificateParams, KeyPair};
use reqwest::StatusCode;
use serde_json::json;
use sqlx::{Connection, PgConnection};
use std::{
    env, fs,
    io::{ErrorKind, Read},
    net::TcpListener,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    process::{Child, Command, Stdio},
    time::Duration,
};
use test_support::{TestNetwork, openbao::OpenBaoContainer, postgres::PostgresContainer, runtime};
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

/// HTTPS client that trusts only the test's self-signed certificate and resolves
/// `host` to loopback, so hostname and chain verification stay enabled.
fn test_https_client(ca_path: &str, host: &str, port: u16) -> Result<reqwest::Client> {
    let ca = reqwest::Certificate::from_pem(&fs::read(ca_path).context("Failed to read test CA")?)
        .context("Failed to parse test CA")?;
    reqwest::Client::builder()
        .tls_certs_only([ca])
        .resolve(host, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port))
        .build()
        .context("Failed to build HTTPS client")
}

struct TestTlsPaths {
    ca: String,
    bundle: String,
}

struct TestContext {
    postgres: PostgresContainer,
    openbao: OpenBaoContainer,
    tls: TestTlsPaths,
    port: u16,
    openbao_url: String,
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
        // Per-run password for OpenBao's root connection role; never a fixed literal.
        let openbao_db_password = Uuid::new_v4().simple().to_string();
        setup_permesi_database(&postgres, &openbao_db_password).await?;

        let (openbao, openbao_url, role_id, secret_id) =
            setup_permesi_openbao(network.name(), &postgres, &openbao_db_password).await?;
        let dsn = format!(
            "postgres://127.0.0.1:{}/permesi?sslmode=disable",
            postgres.host_port()
        );

        Ok(Self {
            postgres,
            openbao,
            tls,
            port: pick_port()?,
            openbao_url,
            role_id,
            secret_id,
            dsn,
        })
    }
}

async fn setup_permesi_database(
    postgres: &PostgresContainer,
    openbao_password: &str,
) -> Result<()> {
    let mut admin = PgConnection::connect(&postgres.admin_dsn())
        .await
        .context("Failed to connect to Postgres admin DB")?;

    // `openbao_password` is a hex UUID, so it cannot break out of the SQL literal.
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "CREATE ROLE openbao_permesi WITH LOGIN PASSWORD '{openbao_password}' CREATEROLE"
    )))
    .execute(&mut admin)
    .await?;
    sqlx::query("GRANT pg_signal_backend TO openbao_permesi")
        .execute(&mut admin)
        .await?;
    sqlx::query("CREATE DATABASE permesi OWNER openbao_permesi")
        .execute(&mut admin)
        .await?;

    let mut permesi_conn = PgConnection::connect(&postgres.admin_dsn_for_db("permesi"))
        .await
        .context("Failed to connect to permesi DB for schema setup")?;
    apply_schema(&mut permesi_conn, PERMESI_SCHEMA_SQL).await?;
    bootstrap_runtime_role(&mut permesi_conn).await?;
    Ok(())
}

async fn setup_permesi_openbao(
    network_name: &str,
    postgres: &PostgresContainer,
    openbao_db_password: &str,
) -> Result<(OpenBaoContainer, String, String, String)> {
    let openbao = OpenBaoContainer::start(network_name).await?;
    openbao
        .enable_secrets_engine("database", "database")
        .await?;

    openbao
        .enable_secrets_engine("transit/permesi", "transit")
        .await?;
    openbao
        .create_transit_key("transit/permesi", "totp", "chacha20-poly1305")
        .await?;

    openbao
        .write_kv_v2(
            "secret",
            "permesi/config",
            json!({
                "opaque_server_seed": "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=",
                "mfa_recovery_pepper": "YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI="
            }),
        )
        .await?;

    openbao.write_kv_v2("secret", "admission-authority", json!({"minimum_version":1,"keys":{"1":"cHFyc3R1dnd4eXp7fH1+f4CBgoOEhYaHiImKi4yNjo8="}})).await?;

    let db_config = test_support::openbao::DatabaseConfig::new(
        postgres.openbao_connection_url_for_db("permesi"),
        "openbao_permesi",
        openbao_db_password,
        vec!["permesi".to_string()],
    );
    openbao
        .configure_database_connection("permesi", &db_config)
        .await?;

    let creation = vec![
        r#"CREATE ROLE "{{name}}" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';"#.to_string(),
        r#"GRANT permesi_runtime TO "{{name}}";"#.to_string(),
    ];
    let revocation = vec![
        r"SELECT pg_terminate_backend(pg_stat_activity.pid) FROM pg_stat_activity WHERE pg_stat_activity.usename = '{{name}}';".to_string(),
        r#"REVOKE permesi_runtime FROM "{{name}}";"#.to_string(),
        r#"DROP ROLE IF EXISTS "{{name}}";"#.to_string(),
    ];
    openbao
        .create_database_role_with_revocation(
            "permesi",
            "permesi",
            &creation,
            &revocation,
            "1h",
            "4h",
        )
        .await?;

    openbao.enable_auth("approle", "approle").await?;
    let policy = r#" 
path "database/creds/permesi" {
  capabilities = ["read"]
}
path "secret/data/admission-authority" { capabilities = ["read"] }
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
    openbao.write_policy("permesi-runtime", policy).await?;

    openbao
        .create_approle("approle", "permesi", &["permesi-runtime"])
        .await?;
    let role_id = openbao.read_role_id("approle", "permesi").await?;
    let secret_id = openbao.create_secret_id("approle", "permesi").await?;
    let openbao_url = openbao.login_url("approle");
    Ok((openbao, openbao_url, role_id, secret_id))
}

async fn bootstrap_runtime_role(conn: &mut PgConnection) -> Result<()> {
    sqlx::query("CREATE ROLE permesi_runtime NOLOGIN")
        .execute(&mut *conn)
        .await?;
    sqlx::query("GRANT permesi_runtime TO openbao_permesi WITH ADMIN OPTION")
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
    test_support::sql::execute_script(&mut *connection, "schema", sql).await?;
    Ok(())
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
        ca: ca_path.display().to_string(),
        bundle: bundle_path.display().to_string(),
    }))
}

async fn wait_for_ready(client: &reqwest::Client, base: &str) -> Result<()> {
    for _ in 0..40 {
        match client.get(format!("{base}/health")).send().await {
            Ok(resp) if resp.status().is_success() => {
                if resp
                    .json::<serde_json::Value>()
                    .await?
                    .get("status")
                    .and_then(serde_json::Value::as_str)
                    == Some("ok")
                {
                    return Ok(());
                }
                sleep(Duration::from_millis(250)).await;
            }
            _ => sleep(Duration::from_millis(250)).await,
        }
    }
    bail!("permesi did not become ready at {base}");
}

async fn wait_for_exit(
    child: &mut ChildGuard,
    timeout: Duration,
) -> Result<std::process::ExitStatus> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Some(status) = child
            .0
            .try_wait()
            .context("Failed while waiting for child process")?
        {
            return Ok(status);
        }
        if tokio::time::Instant::now() >= deadline {
            bail!("permesi process did not exit within {timeout:?}");
        }
        sleep(Duration::from_millis(100)).await;
    }
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

    let ctx = TestContext::new(tls).await?;
    let base = format!("https://api.permesi.localhost:{}", ctx.port);

    // 2. Spawn binary
    let mut command = Command::new(env!("CARGO_BIN_EXE_permesi"));
    command.env("PERMESI_LOG_LEVEL", "debug");
    // Clear conflicting env vars that might leak from the host
    command.env_remove("PERMESI_OPENBAO_SECRET_ID");
    command.env_remove("PERMESI_OPENBAO_WRAPPED_TOKEN");

    let mut child = ChildGuard(
        command
            .args([
                "--port",
                &ctx.port.to_string(),
                "--dsn",
                &ctx.dsn,
                "--openbao-url",
                &ctx.openbao_url,
                "--openbao-role-id",
                &ctx.role_id,
                "--openbao-secret-id",
                &ctx.secret_id,
                "--tls-pem-bundle",
                &ctx.tls.bundle,
                "--openbao-kv-mount",
                "secret",
                "--openbao-kv-path",
                "permesi/config",
            ])
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .context("Failed to spawn permesi binary")?,
    );

    // 3. Verify connectivity
    let client = test_https_client(&ctx.tls.ca, "api.permesi.localhost", ctx.port)?;

    wait_for_ready(&client, &base).await?;

    let resp = client.get(format!("{base}/health")).send().await?;
    assert_eq!(resp.status(), StatusCode::OK);

    // 4. Pool connections are labelled for pg_stat_activity.
    let mut admin = PgConnection::connect(&ctx.postgres.admin_dsn_for_db("permesi")).await?;
    let labelled: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_stat_activity WHERE application_name = 'permesi'",
    )
    .fetch_one(&mut admin)
    .await?;
    assert!(
        labelled >= 1,
        "expected pooled connections labelled 'permesi'"
    );

    // 5. SIGTERM drains and exits cleanly (status 0), unlike a fail-closed stop.
    let pid = child.0.id().to_string();
    let status = std::process::Command::new("kill")
        .args(["-TERM", &pid])
        .status()?;
    assert!(status.success(), "failed to send SIGTERM");
    let exit = tokio::time::timeout(Duration::from_secs(45), async {
        loop {
            if let Some(exit) = child.0.try_wait()? {
                return Ok::<_, std::io::Error>(exit);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .context("permesi did not exit after SIGTERM")??;
    assert!(
        exit.success(),
        "SIGTERM must be a clean shutdown, got {exit}"
    );

    Ok(())
}

#[tokio::test]
async fn revoked_db_lease_forces_health_shutdown() -> Result<()> {
    if let Err(err) = runtime::ensure_container_runtime() {
        eprintln!("Skipping integration test: {err}");
        return Ok(());
    }

    let Some(tls) = prepare_tls_assets()? else {
        return Ok(());
    };

    let ctx = TestContext::new(tls).await?;
    let base = format!("https://api.permesi.localhost:{}", ctx.port);

    let mut command = Command::new(env!("CARGO_BIN_EXE_permesi"));
    command.env("PERMESI_LOG_LEVEL", "error");
    command.env_remove("PERMESI_OPENBAO_SECRET_ID");
    command.env_remove("PERMESI_OPENBAO_WRAPPED_TOKEN");

    let mut child = ChildGuard(
        command
            .args([
                "--port",
                &ctx.port.to_string(),
                "--dsn",
                &ctx.dsn,
                "--openbao-url",
                &ctx.openbao_url,
                "--openbao-role-id",
                &ctx.role_id,
                "--openbao-secret-id",
                &ctx.secret_id,
                "--tls-pem-bundle",
                &ctx.tls.bundle,
                "--openbao-kv-mount",
                "secret",
                "--openbao-kv-path",
                "permesi/config",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to spawn permesi binary")?,
    );

    let client = test_https_client(&ctx.tls.ca, "api.permesi.localhost", ctx.port)?;
    wait_for_ready(&client, &base).await?;

    ctx.openbao
        .revoke_lease_prefix("database/creds/permesi")
        .await
        .context("Failed to revoke permesi DB lease prefix")?;

    let mut observed_unhealthy = false;
    for _ in 0..30 {
        match client.get(format!("{base}/health")).send().await {
            Ok(response) if response.status() == StatusCode::SERVICE_UNAVAILABLE => {
                observed_unhealthy = true;
                break;
            }
            Ok(_) => sleep(Duration::from_millis(200)).await,
            Err(_) => {
                observed_unhealthy = true;
                break;
            }
        }
    }
    if !observed_unhealthy {
        bail!("Expected unhealthy health-check response after lease revocation");
    }

    let status = wait_for_exit(&mut child, Duration::from_secs(10)).await?;
    if status.success() {
        bail!("Expected non-zero exit after revoked DB lease, got {status:?}");
    }

    let mut stderr_output = String::new();
    if let Some(mut stderr) = child.0.stderr.take() {
        stderr
            .read_to_string(&mut stderr_output)
            .context("Failed to read permesi stderr output")?;
    }
    if !stderr_output.contains("database_healthcheck_failed") {
        bail!(
            "Expected shutdown reason in stderr, got: {}",
            stderr_output.trim()
        );
    }

    Ok(())
}
