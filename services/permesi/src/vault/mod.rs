pub mod database;
pub mod kv;
pub mod renew;
pub mod step_up;
pub mod transit;

use crate::api::APP_USER_AGENT;
use anyhow::Result;
use tracing::instrument;

#[instrument]
/// # Errors
/// Returns an error if `url` cannot be parsed, has no host, or uses an unsupported scheme.
pub fn endpoint_url(url: &str, path: &str) -> Result<String> {
    vault_client::endpoint_url(url, path)
}

/// Unwrap a wrapped Vault client token
/// Create wrapped token with:
/// vault write -wrap-ttl=300s -f auth/approle/role/permesi/secret-id
/// # Errors
/// Returns an error if the Vault request fails, Vault returns a non-success status, or the response is missing expected fields.
#[instrument(skip(token))]
pub async fn unwrap(url: &str, token: &str) -> Result<String> {
    vault_client::unwrap(APP_USER_AGENT, url, token).await
}

/// Login to Vault using `AppRole`
/// Create a secret ID with:
/// vault write -f auth/approle/role/permesi/secret-id
/// # Errors
/// Returns an error if the Vault request fails, Vault returns a non-success status, or the response is missing expected fields.
#[instrument(skip(sid))]
pub async fn approle_login(url: &str, sid: &str, rid: &str) -> Result<(String, u64)> {
    vault_client::approle_login(APP_USER_AGENT, url, sid, rid).await
}

#[cfg(test)]
mod tests {
    use super::{approle_login, endpoint_url, unwrap};
    use anyhow::{Result, anyhow};
    use serde_json::json;
    use std::net::TcpListener;
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn can_bind_localhost() -> bool {
        TcpListener::bind("127.0.0.1:0").is_ok()
    }

    #[test]
    fn endpoint_url_defaults_https_port() -> Result<()> {
        let url = endpoint_url("https://vault.example", "/v1/test")?;
        assert_eq!(url, "https://vault.example:443/v1/test");
        Ok(())
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

        let secret_id = unwrap(&server.uri(), "wrapped-token").await?;
        assert_eq!(secret_id, "secret-123");
        Ok(())
    }

    #[tokio::test]
    async fn approle_login_returns_token_and_duration() -> Result<()> {
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
                "auth": {"client_token": "token-abc", "lease_duration": 120}
            })))
            .mount(&server)
            .await;

        let url = format!("{}/v1/auth/approle/login", server.uri());
        let (token, lease_duration) = approle_login(&url, "secret-id", "role-id").await?;
        assert_eq!(token, "token-abc");
        assert_eq!(lease_duration, 120);
        Ok(())
    }

    #[test]
    fn endpoint_url_rejects_unsupported_scheme() -> Result<()> {
        let err = endpoint_url("ftp://vault.example", "/v1/test")
            .err()
            .ok_or_else(|| anyhow!("expected error"))?;
        assert!(err.to_string().contains("unsupported scheme"));
        Ok(())
    }
}
