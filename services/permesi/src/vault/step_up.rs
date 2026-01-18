use anyhow::Result;
use http::{HeaderMap, HeaderValue, Method};
use serde_json::Value;
use thiserror::Error;
use vault_client::VaultTransport;

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

#[derive(Debug, Clone)]
pub struct StepUpClient {
    transport: VaultTransport,
    namespace: Option<String>,
}

impl StepUpClient {
    /// Build a new step-up client for Vault lookups.
    ///
    /// # Errors
    /// This function returns a `Result` for consistency with other builders, though currently
    /// it always returns `Ok`.
    pub fn new(transport: VaultTransport, namespace: Option<String>) -> Result<Self> {
        Ok(Self {
            transport,
            namespace,
        })
    }

    /// Perform a token lookup-self to verify policies.
    ///
    /// # Errors
    /// Returns `LookupSelfError` if Vault is unavailable, unauthorized, or returns an invalid response.
    pub async fn lookup_self(&self, token: &str) -> Result<VaultTokenInfo, LookupSelfError> {
        let mut headers = HeaderMap::new();
        if let Some(ns) = &self.namespace
            && let Ok(val) = HeaderValue::from_str(ns)
        {
            headers.insert("X-Vault-Namespace", val);
        }

        let response = self
            .transport
            .request_json_with_headers(
                Method::GET,
                "/v1/auth/token/lookup-self",
                Some(token),
                None,
                Some(headers),
            )
            .await
            .map_err(|_| LookupSelfError::Unavailable)?;

        if !response.status.is_success() {
            return if response.status.is_client_error() {
                Err(LookupSelfError::Unauthorized)
            } else {
                Err(LookupSelfError::Unavailable)
            };
        }

        let policies = parse_policies(&response.body).ok_or(LookupSelfError::InvalidResponse)?;
        let ttl = response
            .body
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
        let response = self
            .transport
            .request_json(Method::GET, "/v1/sys/health", None, None)
            .await?;

        let version = response
            .body
            .get("version")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        let sealed = response
            .body
            .get("sealed")
            .and_then(Value::as_bool)
            .unwrap_or(true);

        Ok(crate::api::handlers::auth::types::VaultStatus {
            status: if response.status.is_success() {
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
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{LookupSelfError, StepUpClient};
    use anyhow::Result;
    use serde_json::json;
    use std::net::TcpListener;
    use vault_client::{VaultTarget, VaultTransport};
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

        let target = VaultTarget::parse(&server.uri()).unwrap();
        let transport = VaultTransport::from_target("test", target).unwrap();
        let client = StepUpClient::new(transport, None)?;
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

        let target = VaultTarget::parse(&server.uri()).unwrap();
        let transport = VaultTransport::from_target("test", target).unwrap();
        let client = StepUpClient::new(transport, None)?;
        let result = client.lookup_self("token").await;
        assert!(matches!(result, Err(LookupSelfError::Unauthorized)));
        Ok(())
    }
}
