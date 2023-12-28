use crate::{cli::globals::GlobalArgs, vault};
use anyhow::{anyhow, Result};
use reqwest::Client;
use serde_json::Value;
use tracing::instrument;

/// Get DB credentials from Vault
#[instrument]
pub async fn database_creds(globals: &mut GlobalArgs) -> Result<()> {
    let client = Client::builder()
        .user_agent(vault::APP_USER_AGENT)
        .build()?;

    // Parse the URL
    let db_creds = vault::endpoint_url(globals, "/v1/database/creds/permesi")?;

    let response = client
        .get(db_creds.as_str())
        .header("X-Vault-Token", globals.vault_token.as_str())
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let json_response: Value = response.json().await?;

        return Err(anyhow!(
            "{} - {}, {}",
            db_creds,
            status,
            json_response["errors"][0].as_str().unwrap_or("")
        ));
    }

    let json_response: Value = response.json().await?;

    let lease_id = json_response["lease_id"]
        .as_str()
        .ok_or_else(|| anyhow!("Error parsing JSON response: no lease_id found"))?;
    globals.vault_db_lease_id = lease_id.to_string();

    let lease_duration = json_response["lease_duration"]
        .as_u64()
        .ok_or_else(|| anyhow!("Error parsing JSON response: no lease_duration found"))?;
    globals.vault_db_lease_duration = lease_duration;

    let username = json_response["data"]["username"]
        .as_str()
        .ok_or_else(|| anyhow!("Error parsing JSON response: no username found"))?;
    globals.vault_db_username = username.to_string();

    let password = json_response["data"]["password"]
        .as_str()
        .ok_or_else(|| anyhow!("Error parsing JSON response: no password found"))?;
    globals.vault_db_password = password.to_string();

    Ok(())
}
