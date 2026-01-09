use anyhow::{Result, anyhow};
use reqwest::Client;
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Value, json};
use tracing::{Instrument, debug, info_span};
use url::Url;

pub struct DatabaseCreds {
    pub lease_id: String,
    pub lease_duration: u64,
    pub username: String,
    pub password: SecretString,
}

fn vault_error_message(json_response: &Value) -> &str {
    json_response
        .get("errors")
        .and_then(|v| v.get(0))
        .and_then(Value::as_str)
        .unwrap_or("")
}

fn client(user_agent: &str) -> Result<Client> {
    Ok(Client::builder().user_agent(user_agent).build()?)
}

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

/// Unwrap a wrapped Vault client token
/// # Errors
/// Returns an error if the Vault request fails, Vault returns a non-success status, or the response is missing expected fields.
pub async fn unwrap(user_agent: &str, url: &str, token: &str) -> Result<String> {
    let client = client(user_agent)?;

    let unwrap_url = endpoint_url(url, "/v1/sys/wrapping/unwrap")?;

    let span = info_span!(
        "vault.unwrap",
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
            vault_error_message(&json_response)
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

/// Login to Vault using `AppRole`
/// # Errors
/// Returns an error if the Vault request fails, Vault returns a non-success status, or the response is missing expected fields.
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

    debug!("login URL: {}, role ID: {}", url, rid);

    let span = info_span!(
        "vault.approle_login",
        http.method = "POST",
        url = %url
    );
    let response = client
        .post(url)
        .json(&login_payload)
        .send()
        .instrument(span)
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let json_response: Value = response.json().await?;

        return Err(anyhow!(
            "{} - {}, {}",
            url,
            status,
            vault_error_message(&json_response)
        ));
    }

    let json_response: Value = response.json().await?;
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

/// Renew a Vault token
/// # Errors
/// Returns an error if the Vault request fails, Vault returns a non-success status, or the response is missing expected fields.
pub async fn renew_token(
    user_agent: &str,
    url: &str,
    token: &SecretString,
    increment: Option<u64>,
) -> Result<u64> {
    let client = client(user_agent)?;

    let payload = json!({
        "increment": increment.map_or(0, |increment| increment)
    });

    let renew_url = endpoint_url(url, "/v1/auth/token/renew-self")?;

    let span = info_span!(
        "vault.renew_token",
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
            vault_error_message(&json_response)
        ));
    }

    let json_response: Value = response.json().await?;

    json_response
        .get("auth")
        .and_then(|v| v.get("lease_duration"))
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("Error parsing JSON response: no lease_duration found"))
}

/// Renew a Vault database lease
/// # Errors
/// Returns an error if the Vault request fails, Vault returns a non-success status, or the response is missing expected fields.
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
        "vault.renew_db_token",
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
            vault_error_message(&json_response)
        ));
    }

    let json_response: Value = response.json().await?;

    json_response
        .get("lease_duration")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("Error parsing JSON response: no lease_duration found"))
}

/// Get DB credentials from Vault
/// # Errors
/// Returns an error if the Vault request fails, Vault returns a non-success status, or the response is missing expected fields.
pub async fn database_creds(
    user_agent: &str,
    vault_url: &str,
    vault_token: &SecretString,
    db_path: &str,
) -> Result<DatabaseCreds> {
    let client = client(user_agent)?;

    let db_creds = endpoint_url(vault_url, db_path)?;

    let span = info_span!(
        "vault.database_creds",
        http.method = "GET",
        url = %db_creds
    );
    let response = client
        .get(&db_creds)
        .header("X-Vault-Token", vault_token.expose_secret())
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
            vault_error_message(&json_response)
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

    const USER_AGENT: &str = "vault-client-test/0.1";

    fn can_bind_localhost() -> bool {
        TcpListener::bind("127.0.0.1:0").is_ok()
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
        let token = SecretString::from("vault-token".to_string());

        Mock::given(method("POST"))
            .and(path("/v1/auth/token/renew-self"))
            .and(header("X-Vault-Token", "vault-token"))
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
        let token = SecretString::from("vault-token".to_string());

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
        let token = SecretString::from("vault-token".to_string());

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
        let token = SecretString::from("vault-token".to_string());

        Mock::given(method("POST"))
            .and(path("/v1/sys/leases/renew"))
            .and(header("X-Vault-Token", "vault-token"))
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
        let token = SecretString::from("vault-token".to_string());

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
        let token = SecretString::from("vault-token".to_string());

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
        let token = SecretString::from("vault-token".to_string());

        Mock::given(method("GET"))
            .and(path("/v1/database/creds/test"))
            .and(header("X-Vault-Token", "vault-token"))
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
}
