//! OpenBao client library for Permesi and Genesis.
//!
//! This crate provides low-level connectivity to OpenBao, supporting
//! both direct TCP (HTTP/S) and OpenBao Agent Sidecar (Unix Socket) modes.
//! It handles `AppRole` and opt-in Kubernetes authentication, secret unwrapping,
//! and dynamic database credential retrieval.
//!
//! OpenBao kept the wire protocol of the project it forked from, so two names
//! on the wire still say "vault": the `X-Vault-Token` request header and the
//! `vault:v<N>:` prefix on Transit signatures and ciphertexts. They are protocol
//! constants of the OpenBao HTTP API, not leftovers, and must not be renamed.

use anyhow::{Result, anyhow};
use reqwest::Client;
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Value, json};
use tracing::{Instrument, debug, info_span};
use url::Url;

pub mod kubernetes;
pub mod transport;
pub use transport::{OpenBaoMode, OpenBaoTarget, OpenBaoTransport};

/// Database credentials and lease information returned from OpenBao.
pub struct DatabaseCreds {
    /// Unique identifier for the credential lease.
    pub lease_id: String,
    /// Validity period of the lease in seconds.
    pub lease_duration: u64,
    /// Generated database username.
    pub username: String,
    /// Generated database password.
    pub password: SecretString,
}

fn openbao_error_message(json_response: &Value) -> &str {
    json_response
        .get("errors")
        .and_then(|v| v.get(0))
        .and_then(Value::as_str)
        .unwrap_or("")
}

/// The part of an OpenBao address that is safe in diagnostics.
///
/// Only the two forms an address can take are shown, and each is rebuilt from parts that
/// passed a check, never copied. An `http` or `https` URL with a host is reduced to
/// scheme, host and port, followed by its path only when the path is made of plain path
/// characters. Userinfo, query and fragment are dropped, because an operator-supplied
/// address can carry proxy credentials or a token there, and a path holding anything
/// else is dropped too: a `/` or `\` typed before the `@` ends the authority early and
/// moves the credentials into the path. An Agent socket, written as an absolute path or
/// as `unix://` and an absolute path, is shown up to the first `?`, `#` or `;`. Anything
/// else is not echoed at all: a mistyped address or a secret pasted into the wrong
/// setting still parses as a URL of some scheme. Every log line, span field, `Debug`
/// output and error that names an OpenBao address goes through this function.
///
/// What stands where a host belongs is shown as the host; no check can tell a host name
/// from other text placed there.
#[must_use]
pub fn loggable_url(url: &str) -> String {
    const UNSHOWN: &str = "<unparseable URL>";
    let socket = url.strip_prefix("unix://").unwrap_or(url);
    if socket.starts_with('/') && !socket.starts_with("//") {
        let path = socket.split(['?', '#', ';']).next().unwrap_or_default();
        let shown = url.len() - socket.len() + path.len();
        return url.get(..shown).unwrap_or(UNSHOWN).to_string();
    }
    let Ok(parsed) = Url::parse(url) else {
        return UNSHOWN.to_string();
    };
    let host = parsed.host_str().unwrap_or_default();
    if !matches!(parsed.scheme(), "http" | "https") || host.is_empty() {
        return UNSHOWN.to_string();
    }
    let port = parsed
        .port()
        .map_or_else(String::new, |port| format!(":{port}"));
    let plain = |byte: u8| byte.is_ascii_alphanumeric() || b"/-_.~".contains(&byte);
    let path = Some(parsed.path())
        .filter(|path| path.bytes().all(plain))
        .unwrap_or_default();
    format!("{}://{host}{port}{path}", parsed.scheme())
}

/// Bounded like the transport so a stalled OpenBao cannot hang startup login.
fn client(user_agent: &str) -> Result<Client> {
    Ok(Client::builder()
        .user_agent(user_agent)
        .connect_timeout(transport::OPENBAO_CONNECT_TIMEOUT)
        .timeout(transport::OPENBAO_REQUEST_TIMEOUT)
        .redirect(transport::refuse_redirects())
        .build()?)
}

/// Construct a full OpenBao endpoint URL from a base URL and path.
///
/// # Errors
/// Returns an error if `url` cannot be parsed, has no host, or uses an unsupported scheme.
pub fn endpoint_url(url: &str, path: &str) -> Result<String> {
    let url = Url::parse(url)?;

    let scheme = url.scheme();

    let host = url
        .host()
        .ok_or_else(|| anyhow!("Error parsing URL: no host specified"))?
        .to_owned();

    let port = match url.port() {
        Some(p) => p,
        None => match scheme {
            "http" => 80,
            "https" => 443,
            _ => return Err(anyhow!("Error parsing URL: unsupported scheme {scheme}")),
        },
    };

    let endpoint_url = format!("{scheme}://{host}:{port}{path}");

    debug!("endpoint URL: {}", endpoint_url);

    Ok(endpoint_url)
}

/// Resolve the `AppRole` login URL from an OpenBao origin or an explicit login URL.
///
/// An origin (an HTTP(S) URL whose path is empty or `/` and which carries no
/// query) is completed to the standard `AppRole` login path
/// (`/v1/auth/approle/login`). Every other HTTP(S) URL is used verbatim, with its
/// path and query preserved, so reverse-proxy-prefixed or custom-auth-mount login
/// URLs are never rewritten.
///
/// # Errors
/// Returns an error if the URL cannot be parsed, has no host, or uses an unsupported scheme.
pub fn approle_login_url(url: &str) -> Result<String> {
    let parsed = Url::parse(url)?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(anyhow!(
            "Error parsing URL: unsupported scheme {}",
            parsed.scheme()
        ));
    }
    if parsed.host_str().is_none_or(str::is_empty) {
        return Err(anyhow!("Error parsing URL: no host specified"));
    }
    let path = parsed.path();
    let is_origin = (path.is_empty() || path == "/") && parsed.query().is_none();
    if is_origin {
        return endpoint_url(url, "/v1/auth/approle/login");
    }
    Ok(url.to_string())
}

/// Unwrap a wrapped OpenBao response (typically containing a secret-id).
///
/// # Errors
/// Returns an error if the OpenBao request fails or the response is missing expected fields.
pub async fn unwrap(user_agent: &str, url: &str, token: &str) -> Result<String> {
    let client = client(user_agent)?;

    let unwrap_url = endpoint_url(url, "/v1/sys/wrapping/unwrap")?;

    let span = info_span!(
        "openbao.unwrap",
        http.method = "POST",
        url = %unwrap_url
    );
    let response = client
        .post(&unwrap_url)
        .header("X-Vault-Token", token)
        .send()
        .instrument(span)
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let json_response: Value = response.json().await?;

        return Err(anyhow!(
            "{} - {}, {}",
            unwrap_url,
            status,
            openbao_error_message(&json_response)
        ));
    }

    let json_response: Value = response.json().await?;
    let sid = json_response
        .get("data")
        .and_then(|v| v.get("secret_id"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("Error parsing JSON response: no secret_id found"))?;

    Ok(sid.to_string())
}

/// Login to OpenBao using the `AppRole` auth method.
///
/// # Errors
/// Returns an error if login fails or the response is invalid.
pub async fn approle_login(
    user_agent: &str,
    url: &str,
    sid: &str,
    rid: &str,
) -> Result<(String, u64)> {
    let client = client(user_agent)?;

    let login_payload = json!({
        "role_id": rid,
        "secret_id": sid
    });

    // The login URL is operator-supplied and may carry userinfo or a query string, and the
    // RoleID is half of the credential: neither goes into a log line, a span or an error.
    // A transport error would name the full request URL, so it is stripped of it.
    let span = info_span!(
        "openbao.approle_login",
        http.method = "POST",
        url = %loggable_url(url)
    );
    let response = client
        .post(url)
        .json(&login_payload)
        .send()
        .instrument(span)
        .await
        .map_err(reqwest::Error::without_url)?;

    if !response.status().is_success() {
        let status = response.status();
        let json_response: Value = response.json().await.map_err(reqwest::Error::without_url)?;

        return Err(anyhow!(
            "{} - {}, {}",
            loggable_url(url),
            status,
            openbao_error_message(&json_response)
        ));
    }

    let json_response: Value = response.json().await.map_err(reqwest::Error::without_url)?;
    let token = json_response
        .get("auth")
        .and_then(|v| v.get("client_token"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("Error parsing JSON response: no client_token found"))?;
    let lease_duration = json_response
        .get("auth")
        .and_then(|v| v.get("lease_duration"))
        .and_then(Value::as_u64)
        .unwrap_or(1800);

    Ok((token.to_string(), lease_duration))
}

/// Renew the validity of an OpenBao authentication token.
///
/// # Errors
/// Returns an error if renewal fails or the response is invalid.
pub async fn renew_token(
    user_agent: &str,
    url: &str,
    token: &SecretString,
    increment: Option<u64>,
) -> Result<u64> {
    let client = client(user_agent)?;

    let payload = json!({
        "increment": increment.unwrap_or(0)
    });

    let renew_url = endpoint_url(url, "/v1/auth/token/renew-self")?;

    let span = info_span!(
        "openbao.renew_token",
        http.method = "POST",
        url = %renew_url
    );
    let response = client
        .post(&renew_url)
        .json(&payload)
        .header("X-Vault-Token", token.expose_secret())
        .send()
        .instrument(span)
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let json_response: Value = response.json().await?;

        return Err(anyhow!(
            "{} - {}, {}",
            renew_url,
            status,
            openbao_error_message(&json_response)
        ));
    }

    let json_response: Value = response.json().await?;

    json_response
        .get("auth")
        .and_then(|v| v.get("lease_duration"))
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("Error parsing JSON response: no lease_duration found"))
}

/// Renew a dynamic database credential lease.
///
/// # Errors
/// Returns an error if renewal fails or the response is invalid.
pub async fn renew_db_token(
    user_agent: &str,
    url: &str,
    token: &SecretString,
    lease_id: &str,
    increment: u64,
) -> Result<u64> {
    let client = client(user_agent)?;

    let payload = json!({
        "increment": increment,
        "lease_id": lease_id
    });

    let renew_url = endpoint_url(url, "/v1/sys/leases/renew")?;

    let span = info_span!(
        "openbao.renew_db_token",
        http.method = "POST",
        url = %renew_url
    );
    let response = client
        .post(&renew_url)
        .json(&payload)
        .header("X-Vault-Token", token.expose_secret())
        .send()
        .instrument(span)
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let json_response: Value = response.json().await?;

        return Err(anyhow!(
            "{} - {}, {}",
            renew_url,
            status,
            openbao_error_message(&json_response)
        ));
    }

    let json_response: Value = response.json().await?;

    json_response
        .get("lease_duration")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("Error parsing JSON response: no lease_duration found"))
}

/// Fetch new dynamic database credentials from OpenBao.
///
/// # Errors
/// Returns an error if the request fails or the response is missing required fields.
pub async fn database_creds(
    user_agent: &str,
    openbao_url: &str,
    openbao_token: &SecretString,
    db_path: &str,
) -> Result<DatabaseCreds> {
    let client = client(user_agent)?;

    let db_creds = endpoint_url(openbao_url, db_path)?;

    let span = info_span!(
        "openbao.database_creds",
        http.method = "GET",
        url = %db_creds
    );
    let response = client
        .get(&db_creds)
        .header("X-Vault-Token", openbao_token.expose_secret())
        .send()
        .instrument(span)
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let json_response: Value = response.json().await?;

        return Err(anyhow!(
            "{} - {}, {}",
            db_creds,
            status,
            openbao_error_message(&json_response)
        ));
    }

    let json_response: Value = response.json().await?;

    let lease_id = json_response
        .get("lease_id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("Error parsing JSON response: no lease_id found"))?;
    let lease_duration = json_response
        .get("lease_duration")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("Error parsing JSON response: no lease_duration found"))?;
    let username = json_response
        .get("data")
        .and_then(|v| v.get("username"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("Error parsing JSON response: no username found"))?;
    let password = json_response
        .get("data")
        .and_then(|v| v.get("password"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("Error parsing JSON response: no password found"))?;

    Ok(DatabaseCreds {
        lease_id: lease_id.to_string(),
        lease_duration,
        username: username.to_string(),
        password: SecretString::from(password.to_string()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Result, anyhow};
    use secrecy::ExposeSecret;
    use serde_json::json;
    use std::net::TcpListener;
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const USER_AGENT: &str = "openbao-client-test/0.1";

    fn can_bind_localhost() -> bool {
        TcpListener::bind("127.0.0.1:0").is_ok()
    }

    #[test]
    fn loggable_url_keeps_only_scheme_host_port_and_path() {
        assert_eq!(
            loggable_url(
                "https://user:secret@openbao.example:8200/v1/auth/approle/login?token=abc#frag"
            ),
            "https://openbao.example:8200/v1/auth/approle/login"
        );
        assert_eq!(
            loggable_url("http://openbao.example/v1/auth/custom/login"),
            "http://openbao.example/v1/auth/custom/login"
        );
        for opaque in ["not a url with secret", "", "//secret@host"] {
            assert_eq!(loggable_url(opaque), "<unparseable URL>");
        }
        // An Agent socket in either spelling, never with what follows the path.
        for (given, shown) in [
            ("/run/openbao/agent.sock", "/run/openbao/agent.sock"),
            (
                "unix:///run/openbao/agent.sock",
                "unix:///run/openbao/agent.sock",
            ),
            (
                "/run/openbao/agent.sock?proxy_token=secret-query#frag",
                "/run/openbao/agent.sock",
            ),
            (
                "unix:///run/openbao/agent.sock?proxy_token=secret-query",
                "unix:///run/openbao/agent.sock",
            ),
            (
                "/run/openbao/agent.sock#secret-fragment",
                "/run/openbao/agent.sock",
            ),
            (
                "/run/openbao/agent.sock;semi_token=semi-sock-secret",
                "/run/openbao/agent.sock",
            ),
        ] {
            assert_eq!(loggable_url(given), shown);
        }
        // A mistyped address or a misplaced secret parses as a URL of some other scheme,
        // or without the `//` that makes the rest an authority. None of it is shown.
        for opaque in [
            "bao:bao-user:bao-password@openbao.internal:8200",
            "vault:hvs.secret-wrapping-token",
            "postgres://user:secret@db.internal/permesi",
            "unix://relative-secret",
            "unix:secret",
            "file:///etc/secret-path",
            "https://",
        ] {
            assert_eq!(loggable_url(opaque), "<unparseable URL>", "{opaque}");
        }
        // A `/` or `\` before the `@` ends the authority early and moves the credentials
        // into the path, and path parameters can carry a token. Such a path is not shown.
        for (given, shown) in [
            (
                "https://corp\\bao-user:backslash-secret@openbao.internal:8200/v1/auth/approle/login",
                "https://corp",
            ),
            (
                "https://bao-user:8200/slash-port-secret@openbao.internal:8200",
                "https://bao-user:8200",
            ),
            (
                "https://bao-user/slash-secret@openbao.internal:8200",
                "https://bao-user",
            ),
            (
                "https://openbao.internal:8200/v1/auth/approle/login;matrix_token=matrix-secret",
                "https://openbao.internal:8200",
            ),
            (
                "https://openbao.internal:8200/v1/auth/approle/login%3Ftoken=encoded-secret",
                "https://openbao.internal:8200",
            ),
        ] {
            let logged = loggable_url(given);
            assert_eq!(logged, shown, "{given}");
            assert!(!logged.contains("secret"), "{given}");
        }
        // A special scheme written without `//` still names a host, and only the host.
        assert_eq!(
            loggable_url("https:proxy-user:proxy-password@openbao.example:8200"),
            "https://openbao.example:8200/"
        );
    }

    /// The login address and the `RoleID` are operator secrets. Whether the login is
    /// accepted, refused or never connects, nothing of them may reach a log line, a span
    /// field or the returned error.
    #[tokio::test]
    async fn approle_login_keeps_the_address_secrets_and_role_id_out_of_diagnostics() -> Result<()>
    {
        if !can_bind_localhost() {
            return Ok(());
        }
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/auth/approle/login"))
            .and(body_json(
                json!({"role_id": "role-id-value", "secret_id": "good"}),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                json!({"auth": {"client_token": "issued-token-value", "lease_duration": 60}}),
            ))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/auth/approle/login"))
            .respond_with(
                ResponseTemplate::new(403).set_body_json(json!({"errors": ["permission denied"]})),
            )
            .mount(&server)
            .await;
        let address = server.address();
        let login = format!(
            "http://proxy-user:proxy-password@{address}/v1/auth/approle/login?proxy_token=query-token-value"
        );
        // Nothing listens on port 1, so this one fails in the transport.
        let unreachable = "http://proxy-user:proxy-password@127.0.0.1:1/v1/auth/approle/login?proxy_token=query-token-value";

        let errors = std::sync::Mutex::new(Vec::new());
        let logs = test_support::logs::capture_until("openbao.approle_login", || async {
            let accepted = approle_login(USER_AGENT, &login, "good", "role-id-value").await;
            let refused = approle_login(USER_AGENT, &login, "bad-secret-id", "role-id-value").await;
            let failed = approle_login(USER_AGENT, unreachable, "good", "role-id-value").await;
            if let Ok(mut seen) = errors.lock() {
                seen.push((accepted.is_ok(), format!("{refused:?} {failed:?}")));
            }
        })
        .await?;

        let seen = errors.lock().map_err(|_| anyhow!("poisoned"))?;
        assert!(!seen.is_empty() && seen.iter().all(|(accepted, _)| *accepted));
        let errors: String = seen.iter().map(|(_, text)| text.as_str()).collect();
        assert!(errors.contains("403") && errors.contains("/v1/auth/approle/login"));
        assert!(logs.contains(&format!("http://{address}/v1/auth/approle/login")));
        for (place, text) in [("logs", &logs), ("errors", &errors)] {
            for secret in [
                "proxy-user",
                "proxy-password",
                "query-token-value",
                "proxy_token",
                "role-id-value",
                "bad-secret-id",
                "issued-token-value",
            ] {
                assert!(!text.contains(secret), "{secret} appears in {place}");
            }
        }
        Ok(())
    }

    #[test]
    fn endpoint_url_defaults_http_port() -> Result<()> {
        let url = endpoint_url("http://example.com", "/v1/test")?;
        assert_eq!(url, "http://example.com:80/v1/test");
        Ok(())
    }

    #[test]
    fn endpoint_url_defaults_https_port() -> Result<()> {
        let url = endpoint_url("https://example.com", "/v1/test")?;
        assert_eq!(url, "https://example.com:443/v1/test");
        Ok(())
    }

    #[test]
    fn endpoint_url_rejects_unsupported_scheme() -> Result<()> {
        let err = endpoint_url("ftp://example.com", "/v1/test")
            .err()
            .ok_or_else(|| anyhow!("expected error"))?;
        assert!(err.to_string().contains("unsupported scheme"));
        Ok(())
    }

    #[test]
    fn approle_login_url_accepts_base_url() -> Result<()> {
        assert_eq!(
            approle_login_url("https://openbao.example")?,
            "https://openbao.example:443/v1/auth/approle/login"
        );
        Ok(())
    }

    #[test]
    fn approle_login_url_accepts_base_url_with_trailing_slash() -> Result<()> {
        assert_eq!(
            approle_login_url("https://openbao.example/")?,
            "https://openbao.example:443/v1/auth/approle/login"
        );
        Ok(())
    }

    #[test]
    fn approle_login_url_defaults_http_port() -> Result<()> {
        assert_eq!(
            approle_login_url("http://openbao.example")?,
            "http://openbao.example:80/v1/auth/approle/login"
        );
        Ok(())
    }

    #[test]
    fn approle_login_url_accepts_full_login_url() -> Result<()> {
        let url = "https://openbao.example:8200/v1/auth/approle/login";
        assert_eq!(approle_login_url(url)?, url);
        Ok(())
    }

    #[test]
    fn approle_login_url_accepts_custom_mount_login_url() -> Result<()> {
        let url = "https://openbao.example:8200/v1/auth/custom/login";
        assert_eq!(approle_login_url(url)?, url);
        Ok(())
    }

    #[test]
    fn approle_login_url_preserves_query_for_login_url() -> Result<()> {
        let url = "https://openbao.example:8200/v1/auth/approle/login?redirect=yes";
        assert_eq!(approle_login_url(url)?, url);
        Ok(())
    }

    #[test]
    fn approle_login_url_preserves_reverse_proxy_prefix() -> Result<()> {
        let url = "https://h/openbao";
        assert_eq!(approle_login_url(url)?, url);
        Ok(())
    }

    #[test]
    fn approle_login_url_preserves_custom_login_with_query() -> Result<()> {
        let url = "https://h/v1/auth/custom/login?namespace=dev";
        assert_eq!(approle_login_url(url)?, url);
        Ok(())
    }

    #[test]
    fn approle_login_url_preserves_trailing_slash_login_path() -> Result<()> {
        let url = "https://h/v1/auth/approle/login/";
        assert_eq!(approle_login_url(url)?, url);
        Ok(())
    }

    #[test]
    fn approle_login_url_rejects_ftp_login_url() -> Result<()> {
        let err = approle_login_url("ftp://h/v1/auth/x/login")
            .err()
            .ok_or_else(|| anyhow!("expected error"))?;
        assert!(err.to_string().contains("unsupported scheme"));
        Ok(())
    }

    #[test]
    fn approle_login_url_rejects_file_login_url() -> Result<()> {
        let err = approle_login_url("file:///v1/auth/x/login")
            .err()
            .ok_or_else(|| anyhow!("expected error"))?;
        assert!(err.to_string().contains("unsupported scheme"));
        Ok(())
    }

    #[test]
    fn approle_login_url_preserves_origin_query() -> Result<()> {
        assert_eq!(approle_login_url("https://h?x=1")?, "https://h?x=1");
        assert_eq!(approle_login_url("https://h/?x=1")?, "https://h/?x=1");
        assert_eq!(approle_login_url("https://h/?")?, "https://h/?");
        Ok(())
    }

    #[test]
    fn approle_login_url_preserves_login_path_suffix() -> Result<()> {
        let url = "https://h/v1/auth/approle/login/extra";
        assert_eq!(approle_login_url(url)?, url);
        Ok(())
    }

    #[test]
    fn approle_login_url_rejects_hostless_url() -> Result<()> {
        let err = approle_login_url("https://")
            .err()
            .ok_or_else(|| anyhow!("expected error"))?;
        assert!(err.to_string().contains("host"));
        Ok(())
    }

    #[test]
    fn approle_login_url_rejects_unsupported_scheme() -> Result<()> {
        let err = approle_login_url("ftp://openbao.example")
            .err()
            .ok_or_else(|| anyhow!("expected error"))?;
        assert!(err.to_string().contains("unsupported scheme"));
        Ok(())
    }

    #[test]
    fn approle_login_url_rejects_malformed_url() {
        assert!(approle_login_url("http://").is_err());
    }

    #[tokio::test]
    async fn unwrap_returns_secret_id() -> Result<()> {
        if !can_bind_localhost() {
            eprintln!("Skipping test: cannot bind localhost");
            return Ok(());
        }
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/sys/wrapping/unwrap"))
            .and(header("X-Vault-Token", "wrapped-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": {"secret_id": "secret-123"}
            })))
            .mount(&server)
            .await;

        let secret_id = unwrap(USER_AGENT, &server.uri(), "wrapped-token").await?;
        assert_eq!(secret_id, "secret-123");
        Ok(())
    }

    #[tokio::test]
    async fn unwrap_errors_on_failure_status() -> Result<()> {
        if !can_bind_localhost() {
            eprintln!("Skipping test: cannot bind localhost");
            return Ok(());
        }
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/sys/wrapping/unwrap"))
            .respond_with(ResponseTemplate::new(403).set_body_json(json!({
                "errors": ["nope"]
            })))
            .mount(&server)
            .await;

        let result = unwrap(USER_AGENT, &server.uri(), "wrapped-token").await;
        let err = result.err().ok_or_else(|| anyhow!("expected error"))?;
        assert!(err.to_string().contains("nope"));
        Ok(())
    }

    #[tokio::test]
    async fn approle_login_defaults_lease_duration() -> Result<()> {
        if !can_bind_localhost() {
            eprintln!("Skipping test: cannot bind localhost");
            return Ok(());
        }
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/auth/approle/login"))
            .and(body_json(json!({
                "role_id": "role-id",
                "secret_id": "secret-id"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "auth": {"client_token": "token-abc"}
            })))
            .mount(&server)
            .await;

        let url = format!("{}/v1/auth/approle/login", server.uri());
        let (token, lease_duration) =
            approle_login(USER_AGENT, &url, "secret-id", "role-id").await?;
        assert_eq!(token, "token-abc");
        assert_eq!(lease_duration, 1800);
        Ok(())
    }

    #[tokio::test]
    async fn renew_token_returns_lease_duration() -> Result<()> {
        if !can_bind_localhost() {
            eprintln!("Skipping test: cannot bind localhost");
            return Ok(());
        }
        let server = MockServer::start().await;
        let token = SecretString::from("openbao-token".to_string());

        Mock::given(method("POST"))
            .and(path("/v1/auth/token/renew-self"))
            .and(header("X-Vault-Token", "openbao-token"))
            .and(body_json(json!({
                "increment": 0
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "auth": {"lease_duration": 42}
            })))
            .mount(&server)
            .await;

        let lease_duration = renew_token(USER_AGENT, &server.uri(), &token, None).await?;
        assert_eq!(lease_duration, 42);
        Ok(())
    }

    #[tokio::test]
    async fn renew_token_errors_on_failure_status() -> Result<()> {
        if !can_bind_localhost() {
            eprintln!("Skipping test: cannot bind localhost");
            return Ok(());
        }
        let server = MockServer::start().await;
        let token = SecretString::from("openbao-token".to_string());

        Mock::given(method("POST"))
            .and(path("/v1/auth/token/renew-self"))
            .respond_with(ResponseTemplate::new(403).set_body_json(json!({
                "errors": ["nope"]
            })))
            .mount(&server)
            .await;

        let result = renew_token(USER_AGENT, &server.uri(), &token, None).await;
        let err = result.err().ok_or_else(|| anyhow!("expected error"))?;
        assert!(err.to_string().contains("nope"));
        Ok(())
    }

    #[tokio::test]
    async fn renew_token_errors_on_missing_lease_duration() -> Result<()> {
        if !can_bind_localhost() {
            eprintln!("Skipping test: cannot bind localhost");
            return Ok(());
        }
        let server = MockServer::start().await;
        let token = SecretString::from("openbao-token".to_string());

        Mock::given(method("POST"))
            .and(path("/v1/auth/token/renew-self"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "auth": {}
            })))
            .mount(&server)
            .await;

        let result = renew_token(USER_AGENT, &server.uri(), &token, None).await;
        let err = result.err().ok_or_else(|| anyhow!("expected error"))?;
        assert!(err.to_string().contains("no lease_duration"));
        Ok(())
    }

    #[tokio::test]
    async fn renew_db_token_returns_lease_duration() -> Result<()> {
        if !can_bind_localhost() {
            eprintln!("Skipping test: cannot bind localhost");
            return Ok(());
        }
        let server = MockServer::start().await;
        let token = SecretString::from("openbao-token".to_string());

        Mock::given(method("POST"))
            .and(path("/v1/sys/leases/renew"))
            .and(header("X-Vault-Token", "openbao-token"))
            .and(body_json(json!({
                "increment": 120,
                "lease_id": "lease-1"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "lease_duration": 120
            })))
            .mount(&server)
            .await;

        let lease_duration =
            renew_db_token(USER_AGENT, &server.uri(), &token, "lease-1", 120).await?;
        assert_eq!(lease_duration, 120);
        Ok(())
    }

    #[tokio::test]
    async fn renew_db_token_errors_on_failure_status() -> Result<()> {
        if !can_bind_localhost() {
            eprintln!("Skipping test: cannot bind localhost");
            return Ok(());
        }
        let server = MockServer::start().await;
        let token = SecretString::from("openbao-token".to_string());

        Mock::given(method("POST"))
            .and(path("/v1/sys/leases/renew"))
            .respond_with(ResponseTemplate::new(403).set_body_json(json!({
                "errors": ["nope"]
            })))
            .mount(&server)
            .await;

        let result = renew_db_token(USER_AGENT, &server.uri(), &token, "lease-1", 120).await;
        let err = result.err().ok_or_else(|| anyhow!("expected error"))?;
        assert!(err.to_string().contains("nope"));
        Ok(())
    }

    #[tokio::test]
    async fn renew_db_token_errors_on_missing_lease_duration() -> Result<()> {
        if !can_bind_localhost() {
            eprintln!("Skipping test: cannot bind localhost");
            return Ok(());
        }
        let server = MockServer::start().await;
        let token = SecretString::from("openbao-token".to_string());

        Mock::given(method("POST"))
            .and(path("/v1/sys/leases/renew"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .mount(&server)
            .await;

        let result = renew_db_token(USER_AGENT, &server.uri(), &token, "lease-1", 120).await;
        let err = result.err().ok_or_else(|| anyhow!("expected error"))?;
        assert!(err.to_string().contains("no lease_duration"));
        Ok(())
    }

    #[tokio::test]
    async fn database_creds_parses_fields() -> Result<()> {
        if !can_bind_localhost() {
            eprintln!("Skipping test: cannot bind localhost");
            return Ok(());
        }
        let server = MockServer::start().await;
        let token = SecretString::from("openbao-token".to_string());

        Mock::given(method("GET"))
            .and(path("/v1/database/creds/test"))
            .and(header("X-Vault-Token", "openbao-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "lease_id": "lease-123",
                "lease_duration": 55,
                "data": {"username": "user", "password": "pass"}
            })))
            .mount(&server)
            .await;

        let creds =
            database_creds(USER_AGENT, &server.uri(), &token, "/v1/database/creds/test").await?;

        assert_eq!(creds.lease_id, "lease-123");
        assert_eq!(creds.lease_duration, 55);
        assert_eq!(creds.username, "user");
        assert_eq!(creds.password.expose_secret(), "pass");
        Ok(())
    }

    /// A 307 keeps the method, body and `X-Vault-Token`, so following it would deliver
    /// the `SecretID`, the wrapping token or the service token to the named host.
    #[tokio::test]
    async fn token_bearing_requests_refuse_redirects() -> Result<()> {
        if !can_bind_localhost() {
            eprintln!("Skipping test: cannot bind localhost");
            return Ok(());
        }
        let openbao = MockServer::start().await;
        let attacker = MockServer::start().await;
        Mock::given(wiremock::matchers::any())
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "auth": {"client_token": "stolen", "lease_duration": 60},
                "data": {"secret_id": "stolen", "username": "u", "password": "p"},
                "lease_id": "l",
                "lease_duration": 60
            })))
            .mount(&attacker)
            .await;
        Mock::given(wiremock::matchers::any())
            .respond_with(ResponseTemplate::new(307).insert_header("Location", attacker.uri()))
            .mount(&openbao)
            .await;
        let token = SecretString::from("openbao-token".to_string());
        let login_url = approle_login_url(&openbao.uri())?;

        assert!(
            approle_login(USER_AGENT, &login_url, "secret-id", "role-id")
                .await
                .is_err()
        );
        assert!(
            unwrap(USER_AGENT, &openbao.uri(), "wrapped-token")
                .await
                .is_err()
        );
        assert!(
            renew_token(USER_AGENT, &openbao.uri(), &token, None)
                .await
                .is_err()
        );
        assert!(
            database_creds(
                USER_AGENT,
                &openbao.uri(),
                &token,
                "/v1/database/creds/permesi"
            )
            .await
            .is_err()
        );
        let transport =
            OpenBaoTransport::from_target(USER_AGENT, OpenBaoTarget::parse(&openbao.uri())?)?;
        let error = transport
            .request_json(
                http::Method::GET,
                "/v1/secret/data/permesi/config",
                Some("openbao-token"),
                None,
            )
            .await
            .err()
            .ok_or_else(|| anyhow!("followed redirect"))?;
        assert!(format!("{error:#}").contains("redirects are refused"));

        let delivered = attacker
            .received_requests()
            .await
            .ok_or_else(|| anyhow!("request recording disabled"))?;
        assert!(delivered.is_empty(), "a redirect was followed");
        let asked = openbao
            .received_requests()
            .await
            .ok_or_else(|| anyhow!("request recording disabled"))?;
        let paths: Vec<_> = asked.iter().map(|r| r.url.path().to_string()).collect();
        assert_eq!(asked.len(), 5, "{paths:?}");
        Ok(())
    }
}
