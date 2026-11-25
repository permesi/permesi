//! OpenBao transport selection for TCP vs OpenBao Agent unix sockets.
//!
//! This module keeps OpenBao connectivity logic in one place so API calls can share
//! request construction, timeouts, and error handling. TCP mode talks directly
//! to OpenBao over HTTP(S). Agent proxy mode sends requests over a unix socket and
//! relies on the OpenBao Agent to inject and renew auth tokens.
//!
//! Flow Overview:
//! - Parse `GENESIS_OPENBAO_URL` (or equivalent) into a `OpenBaoTarget` (TCP base URL or unix socket path).
//! - Build a `OpenBaoTransport` with the appropriate client.
//! - Call `request_json` with `/v1/...` paths; it returns status + JSON body.
//! - Token headers are optional and must be omitted in agent proxy mode.
//!
//! Security boundary: the unix socket path is treated as a trusted local channel
//! to the OpenBao Agent. When using it, the application never handles OpenBao tokens.

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

pub(crate) const OPENBAO_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
pub(crate) const OPENBAO_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenBaoMode {
    Tcp,
    AgentProxy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenBaoTarget {
    Tcp { base_url: String },
    AgentProxy { socket_path: PathBuf },
}

impl OpenBaoTarget {
    /// Parse `OPENBAO_URL` into a TCP base URL or unix socket path.
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
            "invalid OPENBAO_URL: expected http(s)://..., unix:///path, or /path"
        ))
    }

    fn parse_unix_path(path: &str) -> Result<Self> {
        let trimmed = path.trim();
        if trimmed.is_empty() {
            return Err(anyhow!("invalid OPENBAO_URL: unix socket path is empty"));
        }
        if !trimmed.starts_with('/') {
            return Err(anyhow!(
                "invalid OPENBAO_URL: unix socket path must be absolute"
            ));
        }
        Ok(Self::AgentProxy {
            socket_path: PathBuf::from(trimmed),
        })
    }

    #[must_use]
    pub fn mode(&self) -> OpenBaoMode {
        match self {
            Self::Tcp { .. } => OpenBaoMode::Tcp,
            Self::AgentProxy { .. } => OpenBaoMode::AgentProxy,
        }
    }

    #[must_use]
    pub fn is_tcp(&self) -> bool {
        matches!(self.mode(), OpenBaoMode::Tcp)
    }

    #[must_use]
    pub fn is_agent_proxy(&self) -> bool {
        matches!(self.mode(), OpenBaoMode::AgentProxy)
    }
}

#[derive(Clone)]
pub struct OpenBaoTransport {
    inner: Arc<OpenBaoTransportInner>,
    user_agent: String,
}

enum OpenBaoTransportInner {
    Tcp {
        client: reqwest::Client,
        base_url: String,
    },
    AgentProxy {
        client: Box<HyperClient<UnixConnector, Full<Bytes>>>,
        socket_path: PathBuf,
    },
}

/// Redirect policy of every token-bearing OpenBao client: the request fails instead of
/// following a 3xx. `reqwest` keeps `X-Vault-Token` and, on 307/308, the request body
/// across origins, so a followed redirect would hand the token, a wrapping token or an
/// `AppRole` `SecretID` to whatever host the answer names. OpenBao standbys forward
/// requests to the active node by default and do not need client redirects.
pub(crate) fn refuse_redirects() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        attempt.error("OpenBao answered with a redirect; redirects are refused")
    })
}

impl OpenBaoTransport {
    /// Build a transport from the parsed OpenBao target.
    /// # Errors
    /// Returns an error if the HTTP client cannot be constructed.
    pub fn from_target(user_agent: &str, target: OpenBaoTarget) -> Result<Self> {
        let inner = match target {
            OpenBaoTarget::Tcp { base_url } => {
                let client = reqwest::Client::builder()
                    .user_agent(user_agent)
                    .connect_timeout(OPENBAO_CONNECT_TIMEOUT)
                    .timeout(OPENBAO_REQUEST_TIMEOUT)
                    .redirect(refuse_redirects())
                    .build()?;
                OpenBaoTransportInner::Tcp { client, base_url }
            }
            OpenBaoTarget::AgentProxy { socket_path } => {
                check_socket_accessibility(&socket_path)?;
                let client =
                    Box::new(HyperClient::builder(TokioExecutor::new()).build(UnixConnector));
                OpenBaoTransportInner::AgentProxy {
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
    pub fn mode(&self) -> OpenBaoMode {
        match &*self.inner {
            OpenBaoTransportInner::Tcp { .. } => OpenBaoMode::Tcp,
            OpenBaoTransportInner::AgentProxy { .. } => OpenBaoMode::AgentProxy,
        }
    }

    #[must_use]
    pub fn is_tcp(&self) -> bool {
        matches!(self.mode(), OpenBaoMode::Tcp)
    }

    #[must_use]
    pub fn is_agent_proxy(&self) -> bool {
        matches!(self.mode(), OpenBaoMode::AgentProxy)
    }

    #[must_use]
    pub fn socket_path(&self) -> Option<&Path> {
        match &*self.inner {
            OpenBaoTransportInner::AgentProxy { socket_path, .. } => Some(socket_path.as_path()),
            OpenBaoTransportInner::Tcp { .. } => None,
        }
    }

    /// Build a display URL for logging and error messages.
    /// # Errors
    /// Returns an error if the path is invalid or the base URL cannot be parsed.
    pub fn endpoint_url(&self, path: &str) -> Result<String> {
        if !path.starts_with('/') {
            return Err(anyhow!("openbao path must start with /"));
        }
        match &*self.inner {
            OpenBaoTransportInner::Tcp { base_url, .. } => crate::endpoint_url(base_url, path),
            OpenBaoTransportInner::AgentProxy { socket_path, .. } => {
                Ok(format!("unix://{}{}", socket_path.display(), path))
            }
        }
    }

    /// Execute a JSON request against OpenBao.
    /// # Errors
    /// Returns an error if the request fails or the response body is not JSON.
    pub async fn request_json(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<&Value>,
    ) -> Result<OpenBaoResponse> {
        self.request_json_with_headers(method, path, token, body, None)
            .await
    }

    /// Execute a JSON request against OpenBao with custom headers.
    /// # Errors
    /// Returns an error if the request fails or the response body is not JSON.
    pub async fn request_json_with_headers(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<&Value>,
        headers: Option<HeaderMap>,
    ) -> Result<OpenBaoResponse> {
        self.request_json_inner(method, path, token, body, headers, None)
            .await
    }

    /// Read trusted public metadata with a hard response body budget on both transports.
    /// # Errors
    /// Rejects transport failures, oversized responses and invalid JSON.
    pub async fn read_bounded(
        &self,
        path: &str,
        token: Option<&str>,
        limit: usize,
    ) -> Result<OpenBaoResponse> {
        self.request_json_inner(Method::GET, path, token, None, None, Some(limit))
            .await
    }

    async fn request_json_inner(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<&Value>,
        headers: Option<HeaderMap>,
        limit: Option<usize>,
    ) -> Result<OpenBaoResponse> {
        let url = self.endpoint_url(path)?;
        debug!("openbao request: {} {}", method, url);

        match &*self.inner {
            OpenBaoTransportInner::Tcp { client, .. } => {
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
                let mut response = request.send().await?;
                let status = response.status();
                let json_body = if let Some(limit) = limit {
                    let mut bytes = Vec::new();
                    while let Some(chunk) = response.chunk().await? {
                        anyhow::ensure!(
                            chunk.len() <= limit - bytes.len(),
                            "OpenBao response too large"
                        );
                        bytes.extend_from_slice(&chunk);
                    }
                    serde_json::from_slice(&bytes)?
                } else {
                    response.json().await?
                };
                Ok(OpenBaoResponse {
                    url,
                    status,
                    body: json_body,
                })
            }
            OpenBaoTransportInner::AgentProxy {
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
                // One deadline covers the headers and the body, so an Agent that
                // answers and then stalls cannot hold a renewal loop open.
                let (status, collected) = timeout(OPENBAO_REQUEST_TIMEOUT, async {
                    let response = client.request(request).await.map_err(|e| {
                        anyhow!(
                            "hyper request error: {e}. Check permissions for socket: {}",
                            socket_path.display()
                        )
                    })?;
                    let status = response.status();
                    let collected = http_body_util::Limited::new(
                        response.into_body(),
                        limit.unwrap_or(usize::MAX),
                    )
                    .collect()
                    .await
                    .map_err(|e| anyhow!("body collection error: {e}"))?;
                    Ok::<_, anyhow::Error>((status, collected))
                })
                .await
                .map_err(|_| anyhow!("openbao request timed out"))??;
                let json_body: Value = serde_json::from_slice(&collected.to_bytes())?;
                Ok(OpenBaoResponse {
                    url,
                    status,
                    body: json_body,
                })
            }
        }
    }

    /// Renew the current OpenBao authentication token.
    ///
    /// This follows the `/v1/auth/token/renew-self` protocol. If `token` is `None`,
    /// the request is sent without a token header, allowing the OpenBao Agent to
    /// inject it transparently.
    ///
    /// # Errors
    /// Returns an error if the request fails or OpenBao returns a non-success status.
    pub async fn renew_token(&self, token: Option<&str>, increment: Option<u64>) -> Result<u64> {
        let payload = serde_json::json!({
            "increment": increment.unwrap_or(0)
        });

        let response = self
            .request_json(
                Method::POST,
                "/v1/auth/token/renew-self",
                token,
                Some(&payload),
            )
            .await?;

        if !response.status.is_success() {
            return Err(anyhow!(
                "{} - {}, {}",
                response.url,
                response.status,
                crate::openbao_error_message(&response.body)
            ));
        }

        response
            .body
            .get("auth")
            .and_then(|v| v.get("lease_duration"))
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow!("Error parsing JSON response: no lease_duration found"))
    }

    /// Renew an OpenBao database secret lease.
    ///
    /// Extends the validity of a dynamic database credential. The `token` parameter
    /// follows the same optionality rules as `renew_token`.
    ///
    /// # Errors
    /// Returns an error if the request fails or OpenBao returns a non-success status.
    pub async fn renew_db_lease(
        &self,
        token: Option<&str>,
        lease_id: &str,
        increment: u64,
    ) -> Result<u64> {
        let payload = serde_json::json!({
            "increment": increment,
            "lease_id": lease_id
        });

        let response = self
            .request_json(Method::POST, "/v1/sys/leases/renew", token, Some(&payload))
            .await?;

        if !response.status.is_success() {
            return Err(anyhow!(
                "{} - {}, {}",
                response.url,
                response.status,
                crate::openbao_error_message(&response.body)
            ));
        }

        response
            .body
            .get("lease_duration")
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow!("Error parsing JSON response: no lease_duration found"))
    }
}

/// Response wrapper for OpenBao requests.
pub struct OpenBaoResponse {
    pub url: String,
    pub status: StatusCode,
    pub body: Value,
}

impl std::fmt::Debug for OpenBaoTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &*self.inner {
            OpenBaoTransportInner::Tcp { base_url, .. } => f
                .debug_struct("OpenBaoTransport")
                .field("mode", &OpenBaoMode::Tcp)
                .field("base_url", base_url)
                .field("user_agent", &self.user_agent)
                .finish(),
            OpenBaoTransportInner::AgentProxy { socket_path, .. } => f
                .debug_struct("OpenBaoTransport")
                .field("mode", &OpenBaoMode::AgentProxy)
                .field("socket_path", &socket_path.display().to_string())
                .field("user_agent", &self.user_agent)
                .finish(),
        }
    }
}

fn check_socket_accessibility(path: &Path) -> Result<()> {
    match std::fs::metadata(path) {
        Ok(metadata) => {
            // Check if it is a socket? (std::os::unix::fs::MetadataExt required)
            // For now, just existence is enough to rule out "missing file".
            // We can add more checks if needed.
            // Note: We cannot easily check for read/write access without trying to open it or parsing ACLs,
            // which is overkill here. Metadata success implies we can stat it.
            if !metadata.permissions().readonly() {
                // It is not readonly, so might be writable.
            }
            Ok(())
        }
        Err(e) => Err(anyhow!(
            "OpenBao Agent socket not accessible at {}: {e}",
            path.display()
        )),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::{OpenBaoMode, OpenBaoTarget};

    #[test]
    fn openbao_target_parses_tcp() {
        let target =
            OpenBaoTarget::parse("https://openbao.example.com:8200").expect("should parse TCP URL");
        assert!(matches!(target, OpenBaoTarget::Tcp { .. }));
        assert_eq!(target.mode(), OpenBaoMode::Tcp);
    }

    #[test]
    fn openbao_target_parses_unix_path() {
        let target =
            OpenBaoTarget::parse("/run/openbao/proxy.sock").expect("should parse absolute path");
        assert!(matches!(target, OpenBaoTarget::AgentProxy { .. }));
        assert_eq!(target.mode(), OpenBaoMode::AgentProxy);
    }

    #[test]
    fn openbao_target_parses_unix_scheme() {
        let target = OpenBaoTarget::parse("unix:///run/openbao/proxy.sock")
            .expect("should parse unix:// scheme");
        assert!(matches!(target, OpenBaoTarget::AgentProxy { .. }));
        assert_eq!(target.mode(), OpenBaoMode::AgentProxy);
    }

    #[test]
    fn openbao_target_rejects_invalid_format() {
        let err =
            OpenBaoTarget::parse("openbao.example.com").expect_err("should reject invalid format");
        assert!(err.to_string().contains("invalid OPENBAO_URL"));
    }
}
