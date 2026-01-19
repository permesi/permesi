//! Database credential management via Vault.
//!
//! Handles fetching dynamic database credentials from Vault's database secrets engine.
//! Supports different roles (e.g. "permesi", "genesis") via the `role` parameter.

use crate::globals::GlobalArgs;
use anyhow::{Result, anyhow};
use secrecy::ExposeSecret;
use serde_json::Value;
use tracing::instrument;
use vault_client::DatabaseCreds;

/// Get DB credentials from Vault for a specific role.
///
/// This function calls the Vault endpoint `/v1/database/creds/{role}` to obtain
/// a username, password, and lease information. It then updates the `GlobalArgs`
/// struct with these credentials for use by the application's database pool.
///
/// # Errors
/// Returns an error if:
/// - The Vault request fails (network error, 4xx/5xx response).
/// - The Vault response body is not valid JSON or is missing required fields
///   (lease_id, lease_duration, username, password).
#[instrument(skip(globals))]
pub async fn database_creds(globals: &mut GlobalArgs, role: &str) -> Result<()> {
    let token_str = globals.vault_token.expose_secret();
    let token = if token_str.is_empty() {
        None
    } else {
        Some(token_str)
    };

    let path = format!("/v1/database/creds/{role}");

    let response = globals
        .vault_transport
        .request_json(http::Method::GET, &path, token, None)
        .await?;

    if !response.status.is_success() {
        let error_message = vault_error_message(&response.body);
        return Err(anyhow!(
            "{} - {}, {}",
            response.url,
            response.status,
            error_message
        ));
    }

    let creds = parse_database_creds(&response.body)?;

    globals.vault_db_lease_id = creds.lease_id;
    globals.vault_db_lease_duration = creds.lease_duration;
    globals.vault_db_username = creds.username;
    globals.vault_db_password = creds.password;

    Ok(())
}

fn vault_error_message(json_response: &Value) -> &str {
    json_response
        .get("errors")
        .and_then(|v| v.get(0))
        .and_then(Value::as_str)
        .unwrap_or("")
}

fn parse_database_creds(json_response: &Value) -> Result<DatabaseCreds> {
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
        password: secrecy::SecretString::from(password.to_string()),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::globals::GlobalArgs;
    use secrecy::{ExposeSecret, SecretString};
    use serde_json::json;
    use std::net::TcpListener;
    use vault_client::{VaultTarget, VaultTransport};
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn can_bind_localhost() -> bool {
        TcpListener::bind("127.0.0.1:0").is_ok()
    }

    #[tokio::test]
    async fn database_creds_success_updates_globals() {
        if !can_bind_localhost() {
            return;
        }
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1/database/creds/test-role"))
            .and(header("X-Vault-Token", "root"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "lease_id": "db/creds/test-role/123",
                "lease_duration": 3600,
                "data": {
                    "username": "dynamic-user",
                    "password": "dynamic-password"
                }
            })))
            .mount(&server)
            .await;

        let target = VaultTarget::parse(&server.uri()).unwrap();
        let transport = VaultTransport::from_target("test", target).unwrap();
        let mut globals = GlobalArgs::new(server.uri(), transport);
        globals.set_token(SecretString::from("root".to_string()));

        let result = database_creds(&mut globals, "test-role").await;
        assert!(result.is_ok());

        assert_eq!(globals.vault_db_lease_id, "db/creds/test-role/123");
        assert_eq!(globals.vault_db_lease_duration, 3600);
        assert_eq!(globals.vault_db_username, "dynamic-user");
        assert_eq!(
            globals.vault_db_password.expose_secret(),
            "dynamic-password"
        );
    }

    #[tokio::test]
    async fn database_creds_failure_returns_error() {
        if !can_bind_localhost() {
            return;
        }
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1/database/creds/test-role"))
            .respond_with(ResponseTemplate::new(403).set_body_json(json!({
                "errors": ["permission denied"]
            })))
            .mount(&server)
            .await;

        let target = VaultTarget::parse(&server.uri()).unwrap();
        let transport = VaultTransport::from_target("test", target).unwrap();
        let mut globals = GlobalArgs::new(server.uri(), transport);
        globals.set_token(SecretString::from("root".to_string()));

        let result = database_creds(&mut globals, "test-role").await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("permission denied")
        );
    }

    #[tokio::test]
    async fn database_creds_missing_fields_returns_error() {
        if !can_bind_localhost() {
            return;
        }
        let server = MockServer::start().await;

        // Missing lease_id
        Mock::given(method("GET"))
            .and(path("/v1/database/creds/test-role"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "lease_duration": 3600,
                "data": {
                    "username": "user",
                    "password": "password"
                }
            })))
            .mount(&server)
            .await;

        let target = VaultTarget::parse(&server.uri()).unwrap();
        let transport = VaultTransport::from_target("test", target).unwrap();
        let mut globals = GlobalArgs::new(server.uri(), transport);

        let result = database_creds(&mut globals, "test-role").await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("no lease_id found")
        );
    }
}
