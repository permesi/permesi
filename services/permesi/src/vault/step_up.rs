use anyhow::{Context, Result};
use reqwest::Client;
use serde_json::Value;
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct VaultTokenInfo {
    pub policies: Vec<String>,
    pub ttl: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum LookupSelfError {
    #[error("Unauthorized")]
    Unauthorized,
    #[error("Unavailable")]
    Unavailable,
    #[error("Invalid response")]
    InvalidResponse,
}

#[derive(Debug)]
pub struct StepUpClient {
    client: Client,
    lookup_url: String,
    namespace: Option<String>,
}

impl StepUpClient {
    /// Build a new step-up client for Vault lookups.
    ///
    /// # Errors
    /// Returns an error if the Vault address is invalid or the HTTP client cannot be built.
    pub fn new(vault_addr: &str, namespace: Option<String>) -> Result<Self> {
        let client = Client::builder()
            .user_agent(crate::APP_USER_AGENT)
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(5))
            .build()
            .context("failed to build Vault client")?;

        let lookup_url = vault_client::endpoint_url(vault_addr, "/v1/auth/token/lookup-self")
            .context("invalid Vault address")?;

        Ok(Self {
            client,
            lookup_url,
            namespace,
        })
    }

    /// Perform a token lookup-self to verify policies.
    ///
    /// # Errors
    /// Returns `LookupSelfError` if Vault is unavailable, unauthorized, or returns an invalid response.
    pub async fn lookup_self(&self, token: &str) -> Result<VaultTokenInfo, LookupSelfError> {
        let mut request = self
            .client
            .get(&self.lookup_url)
            .header("X-Vault-Token", token);
        if let Some(namespace) = &self.namespace {
            request = request.header("X-Vault-Namespace", namespace);
        }

        let response = request
            .send()
            .await
            .map_err(|_| LookupSelfError::Unavailable)?;

        if !response.status().is_success() {
            return if response.status().is_client_error() {
                Err(LookupSelfError::Unauthorized)
            } else {
                Err(LookupSelfError::Unavailable)
            };
        }

        let json: Value = response
            .json()
            .await
            .map_err(|_| LookupSelfError::InvalidResponse)?;
        let policies = parse_policies(&json).ok_or(LookupSelfError::InvalidResponse)?;
        let ttl = json
            .get("data")
            .and_then(|data| data.get("ttl"))
            .and_then(Value::as_i64)
            .unwrap_or(0);

        Ok(VaultTokenInfo { policies, ttl })
    }

    /// Check Vault health status.
    ///
    /// # Errors
    /// Returns an error if the request fails or the response is invalid.
    pub async fn health(&self) -> Result<crate::api::handlers::auth::types::VaultStatus> {
        let url = self
            .lookup_url
            .replace("/v1/auth/token/lookup-self", "/v1/sys/health");
        let response = self.client.get(url).send().await?;
        let status_code = response.status();
        let json: Value = response.json().await?;

        let version = json
            .get("version")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        let sealed = json.get("sealed").and_then(Value::as_bool).unwrap_or(true);

        Ok(crate::api::handlers::auth::types::VaultStatus {
            status: if status_code.is_success() {
                "ok".to_string()
            } else {
                "unhealthy".to_string()
            },
            version,
            sealed,
        })
    }
}

fn parse_policies(json: &Value) -> Option<Vec<String>> {
    let data = json.get("data")?;
    let mut policies = Vec::new();
    if let Some(list) = data.get("policies").and_then(Value::as_array) {
        policies.extend(list.iter().filter_map(Value::as_str).map(str::to_string));
    }
    if let Some(list) = data.get("token_policies").and_then(Value::as_array) {
        policies.extend(list.iter().filter_map(Value::as_str).map(str::to_string));
    }
    if let Some(list) = data.get("identity_policies").and_then(Value::as_array) {
        policies.extend(list.iter().filter_map(Value::as_str).map(str::to_string));
    }
    if policies.is_empty() {
        None
    } else {
        Some(policies)
    }
}

#[cfg(test)]
mod tests {
    use super::{LookupSelfError, StepUpClient};
    use anyhow::Result;
    use serde_json::json;
    use std::net::TcpListener;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn can_bind_localhost() -> bool {
        TcpListener::bind("127.0.0.1:0").is_ok()
    }

    #[tokio::test]
    async fn lookup_self_parses_policies() -> Result<()> {
        if !can_bind_localhost() {
            eprintln!("Skipping test: cannot bind localhost");
            return Ok(());
        }
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/auth/token/lookup-self"))
            .and(header("X-Vault-Token", "token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": {
                    "policies": ["default", "permesi-operators"],
                    "ttl": 43200
                }
            })))
            .mount(&server)
            .await;

        let client = StepUpClient::new(&server.uri(), None)?;
        let info = client.lookup_self("token").await?;
        assert!(
            info.policies
                .iter()
                .any(|policy| policy == "permesi-operators")
        );
        Ok(())
    }

    #[tokio::test]
    async fn lookup_self_rejects_invalid_token() -> Result<()> {
        if !can_bind_localhost() {
            eprintln!("Skipping test: cannot bind localhost");
            return Ok(());
        }
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/auth/token/lookup-self"))
            .respond_with(ResponseTemplate::new(403).set_body_json(json!({
                "errors": ["denied"]
            })))
            .mount(&server)
            .await;

        let client = StepUpClient::new(&server.uri(), None)?;
        let result = client.lookup_self("token").await;
        assert!(matches!(result, Err(LookupSelfError::Unauthorized)));
        Ok(())
    }
}
