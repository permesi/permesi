use crate::cli::globals::GlobalArgs;
use anyhow::{Result, anyhow};
use secrecy::ExposeSecret;
use serde_json::Value;
use tracing::instrument;
use vault_client::DatabaseCreds;

/// Get DB credentials from Vault
/// # Errors
/// Returns an error if the Vault request fails, Vault returns a non-success status, or the response is missing expected fields.
#[instrument(skip(globals))]
pub async fn database_creds(globals: &mut GlobalArgs) -> Result<()> {
    let token = globals
        .vault_transport
        .is_tcp()
        .then(|| globals.vault_token.expose_secret());
    let response = globals
        .vault_transport
        .request_json(http::Method::GET, "/v1/database/creds/genesis", token, None)
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
    use super::database_creds;
    use crate::cli::globals::GlobalArgs;
    use anyhow::Result;
    use secrecy::{ExposeSecret, SecretString};
    use serde_json::json;
    use std::net::TcpListener;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn can_bind_localhost() -> bool {
        TcpListener::bind("127.0.0.1:0").is_ok()
    }

    #[tokio::test]
    async fn database_creds_updates_globals() -> Result<()> {
        if !can_bind_localhost() {
            eprintln!("Skipping test: cannot bind localhost");
            return Ok(());
        }
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1/database/creds/genesis"))
            .and(header("X-Vault-Token", "vault-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "lease_id": "lease-123",
                "lease_duration": 55,
                "data": {"username": "user", "password": "pass"}
            })))
            .mount(&server)
            .await;

        let target = crate::vault::VaultTarget::parse(&server.uri()).unwrap();
        let transport = crate::vault::VaultTransport::from_target("test-agent", target).unwrap();
        let mut globals = GlobalArgs::new(server.uri(), transport);
        globals.set_token(SecretString::from("vault-token".to_string()));

        database_creds(&mut globals).await?;

        assert_eq!(globals.vault_db_lease_id, "lease-123");
        assert_eq!(globals.vault_db_lease_duration, 55);
        assert_eq!(globals.vault_db_username, "user");
        assert_eq!(globals.vault_db_password.expose_secret(), "pass");
        Ok(())
    }
}
