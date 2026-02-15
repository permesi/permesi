use anyhow::{Context, Result, bail};
use reqwest::Method;
use serde_json::{Value, json};
use testcontainers::core::wait::HttpWaitStrategy;
use testcontainers::{
    ContainerAsync, GenericImage, ImageExt,
    core::{IntoContainerPort, WaitFor},
    runners::AsyncRunner,
};
use tokio::time::{Duration, sleep};

use crate::unique_name;

const VAULT_PORT: u16 = 8200;

#[derive(Debug, Clone)]
pub struct VaultConfig {
    image: String,
    tag: String,
    root_token: String,
}

impl VaultConfig {
    #[must_use]
    pub fn new() -> Self {
        Self {
            image: "hashicorp/vault".to_string(),
            tag: "1.17.3".to_string(),
            root_token: "root-token".to_string(),
        }
    }

    #[must_use]
    pub fn with_root_token(mut self, token: impl Into<String>) -> Self {
        self.root_token = token.into();
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_config_defaults_are_expected() {
        let config = VaultConfig::new();
        assert_eq!(config.image, "hashicorp/vault");
        assert_eq!(config.tag, "1.17.3");
        assert_eq!(config.root_token, "root-token");
    }

    #[test]
    fn vault_config_overrides_root_token() {
        let config = VaultConfig::new().with_root_token("custom-token");
        assert_eq!(config.root_token, "custom-token");
    }

    #[test]
    fn database_config_as_value_includes_roles() {
        let config = DatabaseConfig::new(
            "postgresql://localhost/db",
            "user",
            "pass",
            vec!["role1".to_string(), "role2".to_string()],
        );
        let value = config.as_value();
        assert_eq!(
            value.get("allowed_roles").and_then(Value::as_str),
            Some("role1,role2")
        );
        assert_eq!(
            value.get("plugin_name").and_then(Value::as_str),
            Some("postgresql-database-plugin")
        );
    }
}

impl Default for VaultConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    pub plugin_name: String,
    pub allowed_roles: Vec<String>,
    pub connection_url: String,
    pub username: String,
    pub password: String,
}

impl DatabaseConfig {
    #[must_use]
    pub fn new(
        connection_url: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
        allowed_roles: Vec<String>,
    ) -> Self {
        Self {
            plugin_name: "postgresql-database-plugin".to_string(),
            allowed_roles,
            connection_url: connection_url.into(),
            username: username.into(),
            password: password.into(),
        }
    }

    fn as_value(&self) -> Value {
        let roles = self.allowed_roles.join(",");
        json!({
            "plugin_name": self.plugin_name,
            "allowed_roles": roles,
            "connection_url": self.connection_url,
            "username": self.username,
            "password": self.password,
        })
    }
}

#[derive(Debug)]
pub struct VaultContainer {
    container: ContainerAsync<GenericImage>,
    base_url: String,
    root_token: String,
    client: reqwest::Client,
}

#[derive(Debug, Clone)]
pub struct DatabaseCredentials {
    pub lease_id: String,
    pub username: String,
    pub password: String,
}

impl VaultContainer {
    /// Start a Vault dev-mode container in the specified network.
    ///
    /// # Errors
    /// Returns an error if the container fails to start or the port cannot be resolved.
    pub async fn start(network: &str) -> Result<Self> {
        Self::start_with_config(network, VaultConfig::new()).await
    }

    /// Start a Vault dev-mode container with a custom config.
    ///
    /// # Errors
    /// Returns an error if the container fails to start or the port cannot be resolved.
    pub async fn start_with_config(network: &str, config: VaultConfig) -> Result<Self> {
        crate::runtime::ensure_container_runtime()?;
        let container_name = unique_name("vault");
        let command = vec![
            "server".to_string(),
            "-dev".to_string(),
            format!("-dev-root-token-id={}", config.root_token),
            "-dev-listen-address=0.0.0.0:8200".to_string(),
        ];

        let mut image = GenericImage::new(&config.image, &config.tag)
            .with_exposed_port(VAULT_PORT.tcp())
            .with_wait_for(WaitFor::http(
                HttpWaitStrategy::new("/v1/sys/health")
                    .with_port(VAULT_PORT.tcp())
                    // testcontainers requires an explicit response matcher; Vault dev-mode returns 200.
                    .with_expected_status_code(200_u16),
            ))
            .with_cmd(command)
            .with_container_name(&container_name);

        if network != "bridge" && network != "default" {
            image = image.with_network(network);
        }

        let container = image
            .start()
            .await
            .context("Failed to start Vault container")?;

        let mut host_port = None;
        let mut last_error = None;

        // Give the runtime a moment to initialize network mappings
        sleep(Duration::from_millis(500)).await;

        for i in 0..60 {
            if let Ok(ports) = container.ports().await {
                if let Some(port) = ports.map_to_host_port_ipv4(VAULT_PORT.tcp()) {
                    host_port = Some(port);
                    break;
                }
                if let Some(port) = ports.map_to_host_port_ipv6(VAULT_PORT.tcp()) {
                    host_port = Some(port);
                    break;
                }
            }

            match container.get_host_port_ipv4(VAULT_PORT.tcp()).await {
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
                eprintln!("Still waiting for Vault port mapping (attempt {i})...");
            }
        }

        let host_port = host_port.ok_or_else(|| {
            anyhow::anyhow!(
                "Failed to resolve Vault host port after 60 retries. Last error: {last_error:?}"
            )
        })?;

        let base_url = format!("http://127.0.0.1:{host_port}");
        let client = reqwest::Client::new();

        Ok(Self {
            container,
            base_url,
            root_token: config.root_token,
            client,
        })
    }

    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    #[must_use]
    pub fn container(&self) -> &ContainerAsync<GenericImage> {
        &self.container
    }

    #[must_use]
    pub fn login_url(&self, approle_mount: &str) -> String {
        let mount = approle_mount.trim_matches('/');
        format!("{}/v1/auth/{mount}/login", self.base_url)
    }

    /// Enable an auth method at the requested mount path.
    ///
    /// # Errors
    /// Returns an error if the Vault API request fails.
    pub async fn enable_auth(&self, mount: &str, auth_type: &str) -> Result<()> {
        let mount = mount.trim_matches('/');
        self.request(
            Method::POST,
            &format!("/v1/sys/auth/{mount}"),
            Some(json!({ "type": auth_type })),
            None,
        )
        .await
        .context("Failed to enable auth method")?;
        Ok(())
    }

    /// Enable a secrets engine at the requested mount path.
    ///
    /// # Errors
    /// Returns an error if the Vault API request fails.
    pub async fn enable_secrets_engine(&self, mount: &str, engine_type: &str) -> Result<()> {
        let mount = mount.trim_matches('/');
        self.request(
            Method::POST,
            &format!("/v1/sys/mounts/{mount}"),
            Some(json!({ "type": engine_type })),
            None,
        )
        .await
        .context("Failed to enable secrets engine")?;
        Ok(())
    }

    /// Write an ACL policy definition.
    ///
    /// # Errors
    /// Returns an error if the Vault API request fails.
    pub async fn write_policy(&self, name: &str, policy: &str) -> Result<()> {
        self.request(
            Method::PUT,
            &format!("/v1/sys/policies/acl/{name}"),
            Some(json!({ "policy": policy })),
            None,
        )
        .await
        .context("Failed to write policy")?;
        Ok(())
    }

    /// Create an `AppRole` with the provided policies.
    ///
    /// # Errors
    /// Returns an error if the Vault API request fails.
    pub async fn create_approle(
        &self,
        mount: &str,
        role_name: &str,
        token_policies: &[&str],
    ) -> Result<()> {
        let mount = mount.trim_matches('/');
        let policies: Vec<String> = token_policies
            .iter()
            .map(|policy| (*policy).to_string())
            .collect();
        self.request(
            Method::POST,
            &format!("/v1/auth/{mount}/role/{role_name}"),
            Some(json!({
                "token_policies": policies,
                "secret_id_ttl": "1h",
                "token_ttl": "1h",
                "token_max_ttl": "4h"
            })),
            None,
        )
        .await
        .context("Failed to create AppRole")?;
        Ok(())
    }

    /// Read the `role_id` for an `AppRole`.
    ///
    /// # Errors
    /// Returns an error if the Vault API request fails or the response is missing data.
    pub async fn read_role_id(&self, mount: &str, role_name: &str) -> Result<String> {
        let mount = mount.trim_matches('/');
        let response = self
            .request(
                Method::GET,
                &format!("/v1/auth/{mount}/role/{role_name}/role-id"),
                None,
                None,
            )
            .await
            .context("Failed to read AppRole role_id")?;
        read_response_str(&response, &["data", "role_id"])
            .context("Missing role_id in AppRole response")
    }

    /// Create an unwrapped `secret_id` for an `AppRole`.
    ///
    /// # Errors
    /// Returns an error if the Vault API request fails or the response is missing data.
    pub async fn create_secret_id(&self, mount: &str, role_name: &str) -> Result<String> {
        let mount = mount.trim_matches('/');
        let response = self
            .request(
                Method::POST,
                &format!("/v1/auth/{mount}/role/{role_name}/secret-id"),
                Some(json!({})),
                None,
            )
            .await
            .context("Failed to create AppRole secret_id")?;
        read_response_str(&response, &["data", "secret_id"])
            .context("Missing secret_id in AppRole response")
    }

    /// Create a wrapped `secret_id` for an `AppRole`.
    ///
    /// # Errors
    /// Returns an error if the Vault API request fails or the response is missing data.
    pub async fn create_wrapped_secret_id(
        &self,
        mount: &str,
        role_name: &str,
        wrap_ttl: &str,
    ) -> Result<String> {
        let mount = mount.trim_matches('/');
        let response = self
            .request(
                Method::POST,
                &format!("/v1/auth/{mount}/role/{role_name}/secret-id"),
                Some(json!({})),
                Some(wrap_ttl),
            )
            .await
            .context("Failed to create wrapped AppRole secret_id")?;
        read_response_str(&response, &["wrap_info", "token"])
            .context("Missing wrap_info.token in AppRole response")
    }

    /// Create a transit key at the specified mount.
    ///
    /// # Errors
    /// Returns an error if the Vault API request fails.
    pub async fn create_transit_key(
        &self,
        mount: &str,
        key_name: &str,
        key_type: &str,
    ) -> Result<()> {
        let mount = mount.trim_matches('/');
        self.request(
            Method::POST,
            &format!("/v1/{mount}/keys/{key_name}"),
            Some(json!({ "type": key_type })),
            None,
        )
        .await
        .context("Failed to create transit key")?;
        Ok(())
    }

    /// Configure a database connection for the database secrets engine.
    ///
    /// # Errors
    /// Returns an error if the Vault API request fails.
    pub async fn configure_database_connection(
        &self,
        name: &str,
        config: &DatabaseConfig,
    ) -> Result<()> {
        self.request(
            Method::POST,
            &format!("/v1/database/config/{name}"),
            Some(config.as_value()),
            None,
        )
        .await
        .context("Failed to configure database connection")?;
        Ok(())
    }

    /// Create a database role for dynamic credentials.
    ///
    /// # Errors
    /// Returns an error if the Vault API request fails.
    pub async fn create_database_role(
        &self,
        role_name: &str,
        db_name: &str,
        creation_statements: &[String],
        default_ttl: &str,
        max_ttl: &str,
    ) -> Result<()> {
        self.request(
            Method::POST,
            &format!("/v1/database/roles/{role_name}"),
            Some(json!({
                "db_name": db_name,
                "creation_statements": creation_statements,
                "default_ttl": default_ttl,
                "max_ttl": max_ttl
            })),
            None,
        )
        .await
        .context("Failed to create database role")?;
        Ok(())
    }

    /// Create a database role with explicit revocation statements.
    ///
    /// # Errors
    /// Returns an error if the Vault API request fails.
    pub async fn create_database_role_with_revocation(
        &self,
        role_name: &str,
        db_name: &str,
        creation_statements: &[String],
        revocation_statements: &[String],
        default_ttl: &str,
        max_ttl: &str,
    ) -> Result<()> {
        self.request(
            Method::POST,
            &format!("/v1/database/roles/{role_name}"),
            Some(json!({
                "db_name": db_name,
                "creation_statements": creation_statements,
                "revocation_statements": revocation_statements,
                "default_ttl": default_ttl,
                "max_ttl": max_ttl
            })),
            None,
        )
        .await
        .context("Failed to create database role with revocation statements")?;
        Ok(())
    }

    /// Read dynamic database credentials for the given role.
    ///
    /// # Errors
    /// Returns an error if the Vault API request fails or the response is missing fields.
    pub async fn read_database_creds(&self, role_name: &str) -> Result<DatabaseCredentials> {
        let response = self
            .request(
                Method::GET,
                &format!("/v1/database/creds/{role_name}"),
                None,
                None,
            )
            .await
            .context("Failed to read database creds")?;

        let lease_id = read_response_str(&response, &["lease_id"])
            .context("Missing lease_id in database creds response")?;
        let username = read_response_str(&response, &["data", "username"])
            .context("Missing username in database creds response")?;
        let password = read_response_str(&response, &["data", "password"])
            .context("Missing password in database creds response")?;

        Ok(DatabaseCredentials {
            lease_id,
            username,
            password,
        })
    }

    /// Revoke a Vault lease by ID.
    ///
    /// # Errors
    /// Returns an error if the Vault API request fails.
    pub async fn revoke_lease(&self, lease_id: &str) -> Result<()> {
        self.request(
            Method::POST,
            "/v1/sys/leases/revoke",
            Some(json!({ "lease_id": lease_id })),
            None,
        )
        .await
        .context("Failed to revoke lease")?;
        Ok(())
    }

    /// Revoke all Vault leases matching a prefix.
    ///
    /// # Errors
    /// Returns an error if the Vault API request fails.
    pub async fn revoke_lease_prefix(&self, prefix: &str) -> Result<()> {
        let prefix = prefix.trim_matches('/');
        self.request(
            Method::POST,
            &format!("/v1/sys/leases/revoke-prefix/{prefix}"),
            Some(json!({})),
            None,
        )
        .await
        .context("Failed to revoke lease prefix")?;
        Ok(())
    }

    /// Write a secret to a KV-v2 mount.
    ///
    /// # Errors
    /// Returns an error if the Vault API request fails.
    pub async fn write_kv_v2(&self, mount: &str, path: &str, data: Value) -> Result<()> {
        let mount = mount.trim_matches('/');
        let path = path.trim_matches('/');
        self.request(
            Method::POST,
            &format!("/v1/{mount}/data/{path}"),
            Some(json!({ "data": data })),
            None,
        )
        .await
        .context("Failed to write KV-v2 secret")?;
        Ok(())
    }

    async fn request(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
        wrap_ttl: Option<&str>,
    ) -> Result<Value> {
        let url = format!("{}{}", self.base_url, path);
        let mut request = self
            .client
            .request(method.clone(), &url)
            .header("X-Vault-Token", &self.root_token);

        if let Some(wrap_ttl) = wrap_ttl {
            request = request.header("X-Vault-Wrap-TTL", wrap_ttl);
        }

        if let Some(body) = body {
            request = request.json(&body);
        }

        let response = request
            .send()
            .await
            .with_context(|| format!("Vault request failed: {url}"))?;
        let status = response.status();
        let body = response
            .text()
            .await
            .context("Failed to read Vault response body")?;

        if !status.is_success() {
            let error_message = vault_error_message(&body);
            bail!("Vault {method} {url} failed: {status} {error_message}");
        }

        if body.trim().is_empty() {
            return Ok(Value::Null);
        }

        let json_body =
            serde_json::from_str(&body).context("Failed to parse Vault JSON response")?;
        Ok(json_body)
    }
}

fn read_response_str(response: &Value, path: &[&str]) -> Result<String> {
    let mut current = response;
    for key in path {
        current = current
            .get(*key)
            .ok_or_else(|| anyhow::anyhow!("Missing {key} in Vault response"))?;
    }
    current
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("Expected string value at {path:?}"))
}

fn vault_error_message(body: &str) -> String {
    if body.trim().is_empty() {
        return "empty response body".to_string();
    }
    if let Ok(json) = serde_json::from_str::<Value>(body)
        && let Some(message) = json
            .get("errors")
            .and_then(|errors| errors.get(0))
            .and_then(Value::as_str)
    {
        return message.to_string();
    }
    let truncated: String = body.chars().take(200).collect();
    if truncated.len() == body.len() {
        truncated
    } else {
        format!("{truncated}...")
    }
}
