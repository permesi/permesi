use crate::{cli::globals::GlobalArgs, vault};
use anyhow::{Result, anyhow};
use reqwest::Client;
use secrecy::{ExposeSecret, SecretString};
use serde_json::Value;
use tracing::instrument;

fn vault_error_message(json_response: &Value) -> &str {
    json_response
        .get("errors")
        .and_then(|v| v.get(0))
        .and_then(Value::as_str)
        .unwrap_or("")
}

/// Get DB credentials from Vault
/// # Errors
/// Returns an error if the Vault request fails, Vault returns a non-success status, or the response is missing expected fields.
#[instrument]
pub async fn database_creds(globals: &mut GlobalArgs) -> Result<()> {
    let client = Client::builder()
        .user_agent(vault::APP_USER_AGENT)
        .build()?;

    // Parse the URL
    let db_creds = vault::endpoint_url(&globals.vault_url, "/v1/database/creds/genesis")?;

    let response = client
        .get(db_creds.as_str())
        .header("X-Vault-Token", globals.vault_token.expose_secret())
        .send()
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
    globals.vault_db_lease_id = lease_id.to_string();

    let lease_duration = json_response
        .get("lease_duration")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("Error parsing JSON response: no lease_duration found"))?;
    globals.vault_db_lease_duration = lease_duration;

    let username = json_response
        .get("data")
        .and_then(|v| v.get("username"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("Error parsing JSON response: no username found"))?;
    globals.vault_db_username = username.to_string();

    let password = json_response
        .get("data")
        .and_then(|v| v.get("password"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("Error parsing JSON response: no password found"))?;
    globals.vault_db_password = SecretString::from(password.to_string());

    Ok(())
}
