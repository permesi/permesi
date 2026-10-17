//! Disposable PostgreSQL fixtures and canonical owner-authenticated bootstrap.
//!
//! Flow Overview: start an owned container, wait for PostgreSQL, then apply the
//! repository's psql includes. Administrator ownership checks and actual owner
//! schema sessions remain separate; setup errors never count as successful coverage.

use anyhow::{Context, Result, ensure};
use sqlx::{Connection, PgConnection};
use std::fmt::Write as _;
use testcontainers::{
    ContainerAsync, ContainerRequest, GenericImage, ImageExt,
    core::{ExecCommand, IntoContainerPort, WaitFor},
};
use tokio::time::{Duration, sleep};

use crate::container::{start_with_port_retry, with_loopback_port};

const POSTGRES_PORT: u16 = 5432;

/// A verified, sanitized rejection from the canonical role-policy SQL, never a setup failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapPolicyViolation {
    /// The service owner has unsafe role attributes.
    OwnerAttributes,
    /// The service owner has an unexpected role membership.
    OwnerMemberships,
    /// The runtime group has unsafe attributes or memberships.
    RuntimeRole,
}

impl BootstrapPolicyViolation {
    /// Matches only fixed messages emitted by the trusted role preflight.
    fn message(self) -> &'static str {
        match self {
            Self::OwnerAttributes => {
                "Vault database roles require non-superuser login and CREATEROLE attributes"
            }
            Self::OwnerMemberships => "Vault database owner has unexpected role memberships",
            Self::RuntimeRole => "Runtime role has unexpected attributes or role memberships",
        }
    }

    /// Requires the policy file, a real source line and P0001; raw diagnostics never leave this helper.
    fn from_stderr(stderr: &[u8]) -> Option<Self> {
        std::str::from_utf8(stderr).ok()?.lines().find_map(|line| {
            let line = line.strip_prefix("psql:/tmp/permesi-bootstrap/bootstrap_ownership.sql:")?;
            let (source_line, error) = line.split_once(": ERROR:")?;
            if source_line.parse::<usize>().ok()? == 0 {
                return None;
            }
            let message = error.trim().strip_prefix("P0001:")?.trim();
            [
                Self::OwnerAttributes,
                Self::OwnerMemberships,
                Self::RuntimeRole,
            ]
            .into_iter()
            .find(|kind| message == kind.message())
        })
    }
}

impl std::fmt::Display for BootstrapPolicyViolation {
    /// Displays a fixed policy message without SQL, identities or credentials.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.message())
    }
}

impl std::error::Error for BootstrapPolicyViolation {}

#[derive(Debug, Clone)]
pub struct PostgresConfig {
    image: String,
    tag: String,
    user: String,
    password: String,
    db_name: String,
}

impl PostgresConfig {
    #[must_use]
    pub fn new() -> Self {
        Self {
            image: "postgres".to_string(),
            tag: "18".to_string(),
            user: "postgres".to_string(),
            password: "postgres".to_string(),
            db_name: "postgres".to_string(),
        }
    }

    #[must_use]
    pub fn with_user(mut self, user: impl Into<String>) -> Self {
        self.user = user.into();
        self
    }

    #[must_use]
    pub fn with_password(mut self, password: impl Into<String>) -> Self {
        self.password = password.into();
        self
    }

    #[must_use]
    pub fn with_db_name(mut self, db_name: impl Into<String>) -> Self {
        self.db_name = db_name.into();
        self
    }
}

impl Default for PostgresConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct PostgresContainer {
    container: ContainerAsync<GenericImage>,
    host_port: u16,
    container_name: String,
    config: PostgresConfig,
}

impl PostgresContainer {
    /// Runs the canonical psql bootstrap inside this owned container, including relative includes.
    ///
    /// # Errors
    /// Fails on any schema, ownership or grant error; no database setup failure is a skip.
    pub async fn bootstrap(&self) -> Result<()> {
        let files = [
            ("00_init.sql", include_str!("../../../db/sql/00_init.sql")),
            (
                "01_genesis.sql",
                include_str!("../../../db/sql/01_genesis.sql"),
            ),
            (
                "02_permesi.sql",
                include_str!("../../../db/sql/02_permesi.sql"),
            ),
            (
                "bootstrap_ownership.sql",
                include_str!("../../../db/sql/bootstrap_ownership.sql"),
            ),
            (
                "partitioning.sql",
                include_str!("../../../db/sql/partitioning.sql"),
            ),
            (
                "seed_test_client.sql",
                include_str!("../../../db/sql/seed_test_client.sql"),
            ),
            (
                "verify_permesi.sql",
                include_str!("../../../db/sql/verify_permesi.sql"),
            ),
        ];
        let mut script = String::from("set -eu\numask 077\nmkdir -p /tmp/permesi-bootstrap\n");
        for (name, sql) in files {
            writeln!(
                script,
                "cat > /tmp/permesi-bootstrap/{name} <<'PERMESI_SQL_END'\n{sql}\nPERMESI_SQL_END"
            )?;
        }
        script.push_str("psql -X --no-password -U \"$BOOTSTRAP_USER\" -d postgres -v ON_ERROR_STOP=1 -v VERBOSITY=verbose -f /tmp/permesi-bootstrap/00_init.sql >/dev/null\n");
        let mut execution = self
            .container
            .exec(
                ExecCommand::new(["sh", "-c", script.as_str()]).with_env_vars([
                    ("BOOTSTRAP_USER", self.user()),
                    ("PGPASSWORD", self.password()),
                ]),
            )
            .await
            .context("Canonical database bootstrap failed")?;
        // An initial exec exit code does not establish that bootstrap completed.
        // Drain the attached stream before checking status; retain diagnostics privately.
        let _stdout = execution.stdout_to_vec().await?;
        let stderr = execution.stderr_to_vec().await?;
        let status = execution.exit_code().await?;
        if status == Some(3)
            && let Some(policy) = BootstrapPolicyViolation::from_stderr(&stderr)
        {
            return Err(policy.into());
        }
        ensure!(status == Some(0), "Canonical database bootstrap failed");
        Ok(())
    }

    /// Start a Postgres container in the specified network.
    ///
    /// # Errors
    /// Returns an error if the container fails to start or the port cannot be resolved.
    pub async fn start(network: &str) -> Result<Self> {
        Self::start_with_config(network, PostgresConfig::new()).await
    }

    /// Start a Postgres container with a custom config.
    ///
    /// # Errors
    /// Returns an error if the container fails to start or the port cannot be resolved.
    pub async fn start_with_config(network: &str, config: PostgresConfig) -> Result<Self> {
        crate::runtime::ensure_container_runtime()?;
        let (container, container_name) =
            start_with_port_retry("Postgres", "postgres", |container_name| {
                fixture_request(&config, container_name, network)
            })
            .await?;

        let mut host_port = None;
        let mut last_error = None;

        // Give the runtime a moment to initialize network mappings
        sleep(Duration::from_millis(500)).await;

        for i in 0..60 {
            if let Ok(ports) = container.ports().await {
                if let Some(port) = ports.map_to_host_port_ipv4(POSTGRES_PORT.tcp()) {
                    host_port = Some(port);
                    break;
                }
                if let Some(port) = ports.map_to_host_port_ipv6(POSTGRES_PORT.tcp()) {
                    host_port = Some(port);
                    break;
                }
            }

            match container.get_host_port_ipv4(POSTGRES_PORT.tcp()).await {
                Ok(port) => {
                    host_port = Some(port);
                    break;
                }
                Err(e) => {
                    last_error = Some(e);
                }
            }
            sleep(Duration::from_millis(250)).await;
            if i % 20 == 0 && i > 0 {
                eprintln!("Still waiting for Postgres port mapping (attempt {i})...");
            }
        }

        let host_port = host_port.ok_or_else(|| {
            anyhow::anyhow!(
                "Failed to resolve Postgres host port after 60 retries. Last error: {last_error:?}"
            )
        })?;

        Ok(Self {
            container,
            host_port,
            container_name,
            config,
        })
    }

    #[must_use]
    pub fn dsn(&self) -> String {
        format!(
            "postgres://127.0.0.1:{}/{}?sslmode=disable",
            self.host_port, self.config.db_name
        )
    }

    #[must_use]
    pub fn admin_dsn(&self) -> String {
        format!(
            "postgres://{}:{}@127.0.0.1:{}/{}?sslmode=disable",
            self.config.user, self.config.password, self.host_port, self.config.db_name
        )
    }

    #[must_use]
    pub fn vault_connection_url(&self) -> String {
        format!(
            "postgresql://{{{{username}}}}:{{{{password}}}}@{}:{}/{}?sslmode=disable",
            self.container_name, POSTGRES_PORT, self.config.db_name
        )
    }

    #[must_use]
    pub fn vault_connection_url_for_db(&self, db_name: &str) -> String {
        format!(
            "postgresql://{{{{username}}}}:{{{{password}}}}@{}:{}/{}?sslmode=disable",
            self.container_name, POSTGRES_PORT, db_name
        )
    }

    #[must_use]
    pub fn container_name(&self) -> &str {
        &self.container_name
    }

    #[must_use]
    pub fn host_port(&self) -> u16 {
        self.host_port
    }

    #[must_use]
    pub fn admin_dsn_for_db(&self, db_name: &str) -> String {
        format!(
            "postgres://{}:{}@127.0.0.1:{}/{}?sslmode=disable",
            self.config.user, self.config.password, self.host_port, db_name
        )
    }

    #[must_use]
    pub fn container(&self) -> &ContainerAsync<GenericImage> {
        &self.container
    }

    #[must_use]
    pub fn user(&self) -> &str {
        &self.config.user
    }

    #[must_use]
    pub fn password(&self) -> &str {
        &self.config.password
    }

    #[must_use]
    pub fn db_name(&self) -> &str {
        &self.config.db_name
    }

    /// Wait until Postgres accepts connections.
    ///
    /// # Errors
    /// Returns an error if Postgres does not become ready after retries.
    pub async fn wait_until_ready(&self) -> Result<()> {
        let dsn = self.admin_dsn();
        let mut attempts = 0;

        loop {
            match PgConnection::connect(&dsn).await {
                Ok(connection) => {
                    drop(connection);
                    return Ok(());
                }
                Err(err) => {
                    attempts += 1;
                    if attempts >= 20 {
                        return Err(err).context("Postgres did not become ready");
                    }
                    sleep(Duration::from_millis(250)).await;
                }
            }
        }
    }
}

/// Builds the exact request used by the live fixture, including loopback publication.
pub(crate) fn fixture_request(
    config: &PostgresConfig,
    container_name: &str,
    network: &str,
) -> ContainerRequest<GenericImage> {
    let image = GenericImage::new(&config.image, &config.tag)
        .with_exposed_port(POSTGRES_PORT.tcp())
        .with_wait_for(WaitFor::message_on_stdout(
            "database system is ready to accept connections",
        ))
        .with_env_var("POSTGRES_USER", &config.user)
        .with_env_var("POSTGRES_PASSWORD", &config.password)
        .with_env_var("POSTGRES_DB", &config.db_name)
        .with_container_name(container_name);
    let image = with_loopback_port(image, POSTGRES_PORT);
    if network != "bridge" && network != "default" {
        image.with_network(network)
    } else {
        image
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY_ERROR: &str = "psql:/tmp/permesi-bootstrap/bootstrap_ownership.sql:21: ERROR:  P0001: Vault database owner has unexpected role memberships\nprivate diagnostic context\n";

    #[test]
    fn bootstrap_policy_rejection_requires_exact_diagnostic_and_sanitizes_context() {
        let violation = BootstrapPolicyViolation::from_stderr(POLICY_ERROR.as_bytes());
        assert_eq!(violation, Some(BootstrapPolicyViolation::OwnerMemberships));
        assert!(
            !BootstrapPolicyViolation::OwnerMemberships
                .to_string()
                .contains("private diagnostic")
        );
    }

    #[test]
    fn bootstrap_policy_rejection_rejects_setup_and_unrelated_sql_failures() {
        for diagnostic in [
            "connection failed".to_owned(),
            POLICY_ERROR.replace("bootstrap_ownership.sql", "02_permesi.sql"),
            POLICY_ERROR.replace("P0001:", "42501:"),
            POLICY_ERROR.replace(":21:", ":unknown:"),
            POLICY_ERROR.replace(":21:", ":0:"),
            POLICY_ERROR.replace("ERROR:", "NOTICE:"),
        ] {
            assert!(BootstrapPolicyViolation::from_stderr(diagnostic.as_bytes()).is_none());
        }
    }

    #[test]
    fn postgres_config_defaults_are_expected() {
        let config = PostgresConfig::new();
        assert_eq!(config.image, "postgres");
        assert_eq!(config.tag, "18");
        assert_eq!(config.user, "postgres");
        assert_eq!(config.password, "postgres");
        assert_eq!(config.db_name, "postgres");
    }

    #[test]
    fn postgres_config_overrides_fields() {
        let password = uuid::Uuid::new_v4().to_string();
        let config = PostgresConfig::new()
            .with_user("app")
            .with_password(password.as_str())
            .with_db_name("appdb");
        assert_eq!(config.user, "app");
        assert_eq!(config.password, password);
        assert_eq!(config.db_name, "appdb");
    }
}
