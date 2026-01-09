use anyhow::{Context, Result};
use sqlx::{Connection, PgConnection};
use testcontainers::{
    ContainerAsync, GenericImage, ImageExt,
    core::{IntoContainerPort, WaitFor},
    runners::AsyncRunner,
};
use tokio::time::{Duration, sleep};

use crate::unique_name;

const POSTGRES_PORT: u16 = 5432;

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
        let container_name = unique_name("postgres");
        let image = GenericImage::new(&config.image, &config.tag)
            .with_exposed_port(POSTGRES_PORT.tcp())
            .with_wait_for(WaitFor::message_on_stdout(
                "database system is ready to accept connections",
            ))
            .with_env_var("POSTGRES_USER", &config.user)
            .with_env_var("POSTGRES_PASSWORD", &config.password)
            .with_env_var("POSTGRES_DB", &config.db_name)
            .with_network(network)
            .with_container_name(&container_name);

        let container = image
            .start()
            .await
            .context("Failed to start Postgres container")?;
        let host_port = container
            .get_host_port_ipv4(POSTGRES_PORT.tcp())
            .await
            .context("Failed to resolve Postgres host port")?;

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

#[cfg(test)]
mod tests {
    use super::*;

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
        let config = PostgresConfig::new()
            .with_user("app")
            .with_password("secret")
            .with_db_name("appdb");
        assert_eq!(config.user, "app");
        assert_eq!(config.password, "secret");
        assert_eq!(config.db_name, "appdb");
    }
}
