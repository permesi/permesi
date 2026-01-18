//! Vault transport selection for TCP vs Vault Agent unix sockets.
//!
//! This module keeps Vault connectivity logic in one place so API calls can share
//! request construction, timeouts, and error handling. TCP mode talks directly
//! to Vault over HTTP(S). Agent proxy mode sends requests over a unix socket and
//! relies on the Vault Agent to inject and renew auth tokens.
//!
//! Flow Overview:
//! - Parse `GENESIS_VAULT_URL` (or equivalent) into a `VaultTarget` (TCP base URL or unix socket path).
//! - Build a `VaultTransport` with the appropriate client.
//! - Call `request_json` with `/v1/...` paths; it returns status + JSON body.
//! - Token headers are optional and must be omitted in agent proxy mode.
//!
//! Security boundary: the unix socket path is treated as a trusted local channel
//! to the Vault Agent. When using it, the application never handles Vault tokens.

use anyhow::{Result, anyhow};
use bytes::Bytes;
use http::{HeaderMap, Method, Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::Client as HyperClient;
use hyper_util::rt::TokioExecutor;
use hyperlocal::{UnixConnector, Uri};
use serde_json::Value;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::time::timeout;
use tracing::debug;

const VAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const VAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultMode {
    Tcp,
    AgentProxy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultTarget {
    Tcp { base_url: String },
    AgentProxy { socket_path: PathBuf },
}

impl VaultTarget {
    /// Parse `VAULT_URL` into a TCP base URL or unix socket path.
    /// # Errors
    /// Returns an error if the value does not start with http(s)://, unix://, or /.
    pub fn parse(raw: &str) -> Result<Self> {
        if raw.starts_with("http://") || raw.starts_with("https://") {
            return Ok(Self::Tcp {
                base_url: raw.to_string(),
            });
        }

        if let Some(path) = raw.strip_prefix("unix://") {
            return Self::parse_unix_path(path);
        }

        if raw.starts_with('/') {
            return Self::parse_unix_path(raw);
        }

        Err(anyhow!(
            "invalid VAULT_URL: expected http(s)://..., unix:///path, or /path"
        ))
    }

    fn parse_unix_path(path: &str) -> Result<Self> {
        let trimmed = path.trim();
        if trimmed.is_empty() {
            return Err(anyhow!("invalid VAULT_URL: unix socket path is empty"));
        }
        if !trimmed.starts_with('/') {
            return Err(anyhow!(
                "invalid VAULT_URL: unix socket path must be absolute"
            ));
        }
        Ok(Self::AgentProxy {
            socket_path: PathBuf::from(trimmed),
        })
    }

    #[must_use]
    pub fn mode(&self) -> VaultMode {
        match self {
            Self::Tcp { .. } => VaultMode::Tcp,
            Self::AgentProxy { .. } => VaultMode::AgentProxy,
        }
    }

    #[must_use]
    pub fn is_tcp(&self) -> bool {
        matches!(self.mode(), VaultMode::Tcp)
    }

    #[must_use]
    pub fn is_agent_proxy(&self) -> bool {
        matches!(self.mode(), VaultMode::AgentProxy)
    }
}

#[derive(Clone)]
pub struct VaultTransport {
    inner: Arc<VaultTransportInner>,
    user_agent: String,
}

enum VaultTransportInner {
    Tcp {
        client: reqwest::Client,
        base_url: String,
    },
    AgentProxy {
        client: Box<HyperClient<UnixConnector, Full<Bytes>>>,
        socket_path: PathBuf,
    },
}

impl VaultTransport {
    /// Build a transport from the parsed Vault target.
    /// # Errors
    /// Returns an error if the HTTP client cannot be constructed.
    pub fn from_target(user_agent: &str, target: VaultTarget) -> Result<Self> {
        let inner = match target {
            VaultTarget::Tcp { base_url } => {
                let client = reqwest::Client::builder()
                    .user_agent(user_agent)
                    .connect_timeout(VAULT_CONNECT_TIMEOUT)
                    .timeout(VAULT_REQUEST_TIMEOUT)
                    .build()?;
                VaultTransportInner::Tcp { client, base_url }
            }
            VaultTarget::AgentProxy { socket_path } => {
                let client =
                    Box::new(HyperClient::builder(TokioExecutor::new()).build(UnixConnector));
                VaultTransportInner::AgentProxy {
                    client,
                    socket_path,
                }
            }
        };

        Ok(Self {
            inner: Arc::new(inner),
            user_agent: user_agent.to_string(),
        })
    }

    #[must_use]
    pub fn mode(&self) -> VaultMode {
        match &*self.inner {
            VaultTransportInner::Tcp { .. } => VaultMode::Tcp,
            VaultTransportInner::AgentProxy { .. } => VaultMode::AgentProxy,
        }
    }

    #[must_use]
    pub fn is_tcp(&self) -> bool {
        matches!(self.mode(), VaultMode::Tcp)
    }

    #[must_use]
    pub fn is_agent_proxy(&self) -> bool {
        matches!(self.mode(), VaultMode::AgentProxy)
    }

    #[must_use]
    pub fn socket_path(&self) -> Option<&Path> {
        match &*self.inner {
            VaultTransportInner::AgentProxy { socket_path, .. } => Some(socket_path.as_path()),
            VaultTransportInner::Tcp { .. } => None,
        }
    }

    /// Build a display URL for logging and error messages.
    /// # Errors
    /// Returns an error if the path is invalid or the base URL cannot be parsed.
    pub fn endpoint_url(&self, path: &str) -> Result<String> {
        if !path.starts_with('/') {
            return Err(anyhow!("vault path must start with /"));
        }
        match &*self.inner {
            VaultTransportInner::Tcp { base_url, .. } => crate::endpoint_url(base_url, path),
            VaultTransportInner::AgentProxy { socket_path, .. } => {
                Ok(format!("unix://{}{}", socket_path.display(), path))
            }
        }
    }

    /// Execute a JSON request against Vault.
    /// # Errors
    /// Returns an error if the request fails or the response body is not JSON.
    pub async fn request_json(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<&Value>,
    ) -> Result<VaultResponse> {
        self.request_json_with_headers(method, path, token, body, None)
            .await
    }

    /// Execute a JSON request against Vault with custom headers.
    /// # Errors
    /// Returns an error if the request fails or the response body is not JSON.
    pub async fn request_json_with_headers(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<&Value>,
        headers: Option<HeaderMap>,
    ) -> Result<VaultResponse> {
        let url = self.endpoint_url(path)?;
        debug!("vault request: {} {}", method, url);

        match &*self.inner {
            VaultTransportInner::Tcp { client, .. } => {
                let mut request = client
                    .request(method, &url)
                    .header("Accept", "application/json")
                    .header("Content-Type", "application/json");
                if let Some(token) = token {
                    request = request.header("X-Vault-Token", token);
                }
                if let Some(h) = headers {
                    request = request.headers(h);
                }
                if let Some(body) = body {
                    request = request.json(body);
                }
                let response = request.send().await?;
                let status = response.status();
                let json_body: Value = response.json().await?;
                Ok(VaultResponse {
                    url,
                    status,
                    body: json_body,
                })
            }
            VaultTransportInner::AgentProxy {
                client,
                socket_path,
            } => {
                let uri = Uri::new(socket_path, path);
                let mut builder = Request::builder()
                    .method(method)
                    .uri(uri)
                    .header("Accept", "application/json")
                    .header("Content-Type", "application/json")
                    .header("User-Agent", &self.user_agent)
                    .header("Host", "localhost");
                if let Some(token) = token {
                    builder = builder.header("X-Vault-Token", token);
                }
                if let (Some(h), Some(headers_map)) = (headers, builder.headers_mut()) {
                    headers_map.extend(h);
                }
                let body_bytes = if let Some(body) = body {
                    serde_json::to_vec(body)?
                } else {
                    Vec::new()
                };
                let request = builder.body(Full::from(body_bytes))?;
                let response = timeout(VAULT_REQUEST_TIMEOUT, client.request(request))
                    .await
                    .map_err(|_| anyhow!("vault request timed out"))?
                    .map_err(|e| anyhow!("hyper request error: {e}"))?;
                let status = response.status();
                let collected = response
                    .into_body()
                    .collect()
                    .await
                    .map_err(|e| anyhow!("body collection error: {e}"))?;
                let json_body: Value = serde_json::from_slice(&collected.to_bytes())?;
                Ok(VaultResponse {
                    url,
                    status,
                    body: json_body,
                })
            }
        }
    }
}

/// Response wrapper for Vault requests.
pub struct VaultResponse {
    pub url: String,
    pub status: StatusCode,
    pub body: Value,
}

impl std::fmt::Debug for VaultTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &*self.inner {
            VaultTransportInner::Tcp { base_url, .. } => f
                .debug_struct("VaultTransport")
                .field("mode", &VaultMode::Tcp)
                .field("base_url", base_url)
                .field("user_agent", &self.user_agent)
                .finish(),
            VaultTransportInner::AgentProxy { socket_path, .. } => f
                .debug_struct("VaultTransport")
                .field("mode", &VaultMode::AgentProxy)
                .field("socket_path", &socket_path.display().to_string())
                .field("user_agent", &self.user_agent)
                .finish(),
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::{VaultMode, VaultTarget};

    #[test]
    fn vault_target_parses_tcp() {
        let target =
            VaultTarget::parse("https://vault.example.com:8200").expect("should parse TCP URL");
        assert!(matches!(target, VaultTarget::Tcp { .. }));
        assert_eq!(target.mode(), VaultMode::Tcp);
    }

    #[test]
    fn vault_target_parses_unix_path() {
        let target =
            VaultTarget::parse("/run/vault/proxy.sock").expect("should parse absolute path");
        assert!(matches!(target, VaultTarget::AgentProxy { .. }));
        assert_eq!(target.mode(), VaultMode::AgentProxy);
    }

    #[test]
    fn vault_target_parses_unix_scheme() {
        let target = VaultTarget::parse("unix:///run/vault/proxy.sock")
            .expect("should parse unix:// scheme");
        assert!(matches!(target, VaultTarget::AgentProxy { .. }));
        assert_eq!(target.mode(), VaultMode::AgentProxy);
    }

    #[test]
    fn vault_target_rejects_invalid_format() {
        let err =
            VaultTarget::parse("vault.example.com").expect_err("should reject invalid format");
        assert!(err.to_string().contains("invalid VAULT_URL"));
    }
}
