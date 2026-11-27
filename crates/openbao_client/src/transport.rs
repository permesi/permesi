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
    net::{SocketAddr, ToSocketAddrs},
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

#[derive(Clone, PartialEq, Eq)]
pub enum OpenBaoTarget {
    Tcp { base_url: String },
    AgentProxy { socket_path: PathBuf },
}

/// The base URL is operator-supplied and can carry userinfo or a query string, so it is
/// formatted without them.
impl std::fmt::Debug for OpenBaoTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp { base_url } => f
                .debug_struct("Tcp")
                .field("base_url", &crate::loggable_url(base_url))
                .finish(),
            Self::AgentProxy { socket_path } => f
                .debug_struct("AgentProxy")
                .field("socket_path", &loggable_socket(socket_path))
                .finish(),
        }
    }
}

impl OpenBaoTarget {
    /// Parse `OPENBAO_URL` into a TCP base URL or unix socket path.
    /// # Errors
    /// Returns an error if the value does not start with http(s)://, unix://, or /, or
    /// if an http(s) address has no usable host or holds whitespace inside it.
    pub fn parse(raw: &str) -> Result<Self> {
        if raw.starts_with("http://") || raw.starts_with("https://") {
            crate::parse_http_address(raw)?;
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

    /// Refuse an address that would send tokens and secrets over the network in clear
    /// text.
    ///
    /// An Agent socket and an `https` address pass. A plain `http` address passes only
    /// when it stays on this machine (see [`Reach`]), or when `allow_plain_http` says the
    /// operator accepted the risk, as a development cluster with an in-cluster OpenBao
    /// does. The decision has no side effects; for `localhost` names it asks the
    /// resolver.
    ///
    /// # Errors
    /// Returns an error for a plain `http` address to any other host. The message does
    /// not repeat the address.
    pub fn require_encrypted_transport(&self, allow_plain_http: bool) -> Result<()> {
        let Self::Tcp { base_url } = self else {
            return Ok(());
        };
        match Reach::of(base_url)? {
            Reach::Encrypted | Reach::LocalPlain(_) => Ok(()),
            Reach::RemotePlain if allow_plain_http => Ok(()),
            Reach::RemotePlain => Err(anyhow!(
                "OpenBao address uses plain http to a host that is not loopback; use https, \
                 or accept clear-text tokens explicitly with --openbao-allow-insecure-http"
            )),
        }
    }
}

/// How requests to a TCP OpenBao address travel.
///
/// A plain `http` address is local when its host is a loopback IP, or `localhost` or a
/// name under it that resolves, at the time of asking, to loopback addresses only. The
/// spelling of such a name proves nothing, since a resolver can map it anywhere, so the
/// addresses found are kept and the client is pinned to them. A `localhost` name that
/// does not resolve to loopback only is an error, not a remote address: every client is
/// built from the address separately, and an answer that changed between the startup
/// check and a later client must stop that client, not reroute it.
pub(crate) enum Reach {
    /// `https`: the connection is encrypted and the server verified wherever it goes.
    Encrypted,
    /// Plain `http` that does not leave the machine, with the name and the loopback
    /// addresses to pin when the host is a name.
    LocalPlain(Option<(String, Vec<SocketAddr>)>),
    /// Plain `http` to another host, acceptable only by explicit opt-in.
    RemotePlain,
}

impl Reach {
    /// Classify a base URL that passed `parse_http_address`.
    pub(crate) fn of(base_url: &str) -> Result<Self> {
        Self::of_with(base_url, |name, port| {
            (name, port)
                .to_socket_addrs()
                .map_or_default(Iterator::collect)
        })
    }

    /// [`Reach::of`] with the resolver passed in, so the rule can be tested against
    /// answers this machine's resolver would never give.
    fn of_with(base_url: &str, resolve: impl Fn(&str, u16) -> Vec<SocketAddr>) -> Result<Self> {
        let (parsed, _) = crate::parse_http_address(base_url)?;
        if parsed.scheme() == "https" {
            return Ok(Self::Encrypted);
        }
        Ok(match parsed.host() {
            Some(url::Host::Ipv4(address)) if address.is_loopback() => Self::LocalPlain(None),
            Some(url::Host::Ipv6(address)) if address.is_loopback() => Self::LocalPlain(None),
            Some(url::Host::Domain(name)) => {
                let name = name.trim_end_matches('.').to_ascii_lowercase();
                let port = parsed.port_or_known_default().unwrap_or(80);
                let addresses: Vec<SocketAddr> =
                    if name == "localhost" || name.ends_with(".localhost") {
                        resolve(&name, port)
                    } else {
                        Vec::new()
                    };
                let local_name = name == "localhost" || name.ends_with(".localhost");
                if !addresses.is_empty() && addresses.iter().all(|a| a.ip().is_loopback()) {
                    // The pin is keyed by the host as the client will look it up.
                    let host = parsed.host_str().unwrap_or(&name).to_string();
                    Self::LocalPlain(Some((host, addresses)))
                } else if local_name {
                    return Err(anyhow!(
                        "OpenBao address names a localhost host that does not resolve to \
                         loopback addresses only"
                    ));
                } else {
                    Self::RemotePlain
                }
            }
            _ => Self::RemotePlain,
        })
    }
}

/// The HTTP client builder every request to a TCP OpenBao address starts from.
///
/// On the local plain-`http` path the client ignores the proxy settings of the
/// environment and connects only to the loopback addresses found by [`Reach::of`].
/// Without that, `HTTP_PROXY` would carry a login or a token to the proxy in clear
/// text although the address says loopback. An `https` address keeps the environment's
/// proxy, which only tunnels the encrypted connection, and a plain address the operator
/// opted into is theirs to route.
///
/// # Errors
/// Returns an error if the address is not a valid OpenBao address.
pub(crate) fn client_builder(base_url: &str) -> Result<reqwest::ClientBuilder> {
    let builder = reqwest::Client::builder()
        .connect_timeout(OPENBAO_CONNECT_TIMEOUT)
        .timeout(OPENBAO_REQUEST_TIMEOUT);
    Ok(match Reach::of(base_url)? {
        Reach::LocalPlain(Some((host, addresses))) => {
            builder.no_proxy().resolve_to_addrs(&host, &addresses)
        }
        Reach::LocalPlain(None) => builder.no_proxy(),
        Reach::Encrypted | Reach::RemotePlain => builder,
    })
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
                let client = client_builder(&base_url)?
                    .user_agent(user_agent)
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
    ///
    /// In Agent mode the request is addressed by the socket path itself, so the socket
    /// is shown here only as [`loggable_socket`] allows.
    /// # Errors
    /// Returns an error if the path is invalid or the base URL cannot be parsed.
    pub fn endpoint_url(&self, path: &str) -> Result<String> {
        if !path.starts_with('/') {
            return Err(anyhow!("openbao path must start with /"));
        }
        match &*self.inner {
            OpenBaoTransportInner::Tcp { base_url, .. } => crate::endpoint_url(base_url, path),
            OpenBaoTransportInner::AgentProxy { socket_path, .. } => {
                Ok(format!("unix://{}{}", loggable_socket(socket_path), path))
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
                            loggable_socket(socket_path)
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
                .field("base_url", &crate::loggable_url(base_url))
                .field("user_agent", &self.user_agent)
                .finish(),
            OpenBaoTransportInner::AgentProxy { socket_path, .. } => f
                .debug_struct("OpenBaoTransport")
                .field("mode", &OpenBaoMode::AgentProxy)
                .field("socket_path", &loggable_socket(socket_path))
                .field("user_agent", &self.user_agent)
                .finish(),
        }
    }
}

/// A socket path as diagnostics show it. The setting it comes from is free text, so a
/// query string or fragment appended to it is part of the stored path; it is cut off here
/// the same way [`crate::loggable_url`] cuts it from an address.
fn loggable_socket(path: &Path) -> String {
    crate::loggable_url(&path.display().to_string())
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
            loggable_socket(path)
        )),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::{OpenBaoMode, OpenBaoTarget, OpenBaoTransport};

    /// A target and a transport are formatted in startup diagnostics; the operator-supplied
    /// base URL must appear without its userinfo and query string.
    #[test]
    fn target_and_transport_debug_output_drop_address_credentials() -> anyhow::Result<()> {
        let url = "https://proxy-user:proxy-password@openbao.internal:8200/?proxy_token=query-token-value";
        let target = OpenBaoTarget::parse(url)?;
        let transport = OpenBaoTransport::from_target("test", target.clone())?;
        let shown = format!("{target:?} {target:#?} {transport:?} {transport:#?}");
        assert!(shown.contains("https://openbao.internal:8200/"));
        for secret in [
            "proxy-user",
            "proxy-password",
            "query-token-value",
            "proxy_token",
        ] {
            assert!(!shown.contains(secret), "{secret}");
        }
        let socket = OpenBaoTarget::parse("unix:///run/openbao/agent.sock")?;
        assert!(format!("{socket:?}").contains("/run/openbao/agent.sock"));
        // Whatever follows the socket path is kept as part of the path, and never shown:
        // not by `Debug`, and not by the error for a socket that is not there.
        let trailing =
            OpenBaoTarget::parse("unix:///run/openbao/absent.sock?proxy_token=query-token-value")?;
        let refused = OpenBaoTransport::from_target("test", trailing.clone())
            .err()
            .map_or_else(String::new, |error| format!("{error:#}"));
        let shown = format!("{trailing:?} {trailing:#?} {refused}");
        assert!(shown.contains("/run/openbao/absent.sock") && refused.contains("not accessible"));
        assert!(!shown.contains("query-token-value") && !shown.contains("proxy_token"));
        Ok(())
    }

    /// A file can exist under a name that carries a query string, and the transport then
    /// starts. Its display URL and the error for a request that cannot connect show the
    /// socket path only as far as it is shown anywhere else.
    #[tokio::test]
    async fn agent_transport_shows_no_text_appended_to_the_socket_path() -> anyhow::Result<()> {
        let directory =
            std::env::temp_dir().join(format!("permesi-socket-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory)?;
        let named = directory.join("agent.sock?proxy_token=query-token-value");
        std::fs::write(&named, b"")?;
        let outcome = async {
            let target = OpenBaoTarget::parse(&format!("unix://{}", named.display()))?;
            let transport = OpenBaoTransport::from_target("test", target)?;
            let display = transport.endpoint_url("/v1/sys/health")?;
            let refused = transport
                .request_json(reqwest::Method::GET, "/v1/sys/health", None, None)
                .await
                .err()
                .map_or_else(String::new, |error| format!("{error:#}"));
            anyhow::Ok(format!("{display} {refused}"))
        }
        .await;
        std::fs::remove_dir_all(&directory)?;
        let shown = outcome?;
        assert!(shown.contains("agent.sock/v1/sys/health"), "{shown}");
        assert!(shown.contains("Check permissions for socket"), "{shown}");
        assert!(
            !shown.contains("query-token-value") && !shown.contains("proxy_token"),
            "{shown}"
        );
        Ok(())
    }

    /// Tokens and secrets cross the network in clear text over plain `http`, so only a
    /// loopback host may use it unless the operator opted in.
    #[test]
    fn plain_http_is_refused_off_loopback_unless_allowed() -> anyhow::Result<()> {
        for address in [
            "https://openbao.internal:8200",
            "https://10.0.0.5:8200/v1/auth/approle/login",
            "http://127.0.0.1:8200",
            "http://127.8.9.10:8200",
            "http://[::1]:8200",
            "http://localhost:8200",
            "http://LOCALHOST.:8200",
            "unix:///run/openbao/agent.sock",
            "/run/openbao/agent.sock",
        ] {
            OpenBaoTarget::parse(address)?
                .require_encrypted_transport(false)
                .map_err(|error| anyhow::anyhow!("{address}: {error}"))?;
        }
        for address in [
            "http://openbao.internal:8200",
            "http://openbao:8200",
            "http://10.0.0.5:8200",
            "http://[2001:db8::5]:8200",
            "http://0.0.0.0:8200",
            // Names that only look local.
            "http://localhost.example.com:8200",
            "http://notlocalhost:8200",
            "http://127.0.0.1.example.com:8200",
            "http://proxy-user:proxy-secret@openbao.internal:8200/?token=query-secret",
        ] {
            let target = OpenBaoTarget::parse(address)?;
            let refused = target
                .require_encrypted_transport(false)
                .err()
                .map(|error| format!("{error:#}"));
            assert!(
                refused
                    .as_ref()
                    .is_some_and(|error| error.contains("plain http") && !error.contains("secret")),
                "{address}: {refused:?}"
            );
            // The opt-in is the only way through, and it is explicit.
            assert!(
                target.require_encrypted_transport(true).is_ok(),
                "{address}"
            );
        }
        Ok(())
    }

    /// A plain `localhost` name counts as local only when every address it resolves to is
    /// loopback, and the client is then pinned to exactly those. This machine's resolver
    /// maps every `.localhost` name to loopback, so a hostile answer is supplied here.
    #[test]
    fn localhost_name_is_local_only_when_it_resolves_to_loopback() -> anyhow::Result<()> {
        use super::Reach;
        use std::net::SocketAddr;
        let answers = |answer: &'static [&'static str]| {
            move |_: &str, port: u16| {
                answer
                    .iter()
                    .filter_map(|ip| ip.parse::<std::net::IpAddr>().ok())
                    .map(|ip| SocketAddr::new(ip, port))
                    .collect::<Vec<_>>()
            }
        };
        let pinned = Reach::of_with(
            "http://openbao.localhost:8200",
            answers(&["127.0.0.1", "::1"]),
        )?;
        let Reach::LocalPlain(Some((host, addresses))) = pinned else {
            anyhow::bail!("a name resolving to loopback is local");
        };
        assert_eq!(host, "openbao.localhost");
        assert_eq!(addresses.len(), 2);
        assert!(addresses.iter().all(|address| address.port() == 8200));
        // Not reclassified as a remote address, which an opt-out or a proxy could then
        // carry: refused, so a client built after the answer changed fails closed.
        for answer in [&["198.51.100.9"][..], &["127.0.0.1", "198.51.100.9"], &[]] {
            assert!(
                Reach::of_with("http://openbao.localhost:8200", answers(answer)).is_err(),
                "{answer:?}"
            );
        }
        assert!(matches!(
            Reach::of_with("http://openbao.internal:8200", answers(&["127.0.0.1"]))?,
            Reach::RemotePlain
        ));
        assert!(matches!(
            Reach::of_with("https://openbao.localhost:8200", answers(&["198.51.100.9"]))?,
            Reach::Encrypted
        ));
        Ok(())
    }

    /// An http(s) address is checked when the setting is parsed, so one that would join
    /// text into the host stops the service at startup and is never logged in pieces.
    #[test]
    fn openbao_target_refuses_an_address_with_whitespace_inside_or_a_host_that_is_none() {
        for address in [
            "https://openbao.internal\nnext-line-secret",
            "https://openbao.internal;token=host-secret",
            "https://openbao.internal\u{200b}host-secret:8200",
            "https://openbao.internal%EF%BB%BFhost-secret:8200",
            "https://",
        ] {
            let refused = OpenBaoTarget::parse(address)
                .err()
                .map(|error| format!("{error:#}"));
            assert!(
                refused
                    .as_ref()
                    .is_some_and(|error| !error.contains("secret")),
                "{address:?}: {refused:?}"
            );
        }
        assert!(OpenBaoTarget::parse("https://openbao.internal:8200\n").is_ok());
    }

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
