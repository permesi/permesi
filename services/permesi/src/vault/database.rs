use crate::{cli::globals::GlobalArgs, permesi};
use anyhow::Result;
use tracing::instrument;

/// Get DB credentials from Vault
/// # Errors
/// Returns an error if the Vault request fails, Vault returns a non-success status, or the response is missing expected fields.
#[instrument]
pub async fn database_creds(globals: &mut GlobalArgs) -> Result<()> {
    let creds = vault_client::database_creds(
        permesi::APP_USER_AGENT,
        &globals.vault_url,
        &globals.vault_token,
        "/v1/database/creds/permesi",
    )
    .await?;

    globals.vault_db_lease_id = creds.lease_id;
    globals.vault_db_lease_duration = creds.lease_duration;
    globals.vault_db_username = creds.username;
    globals.vault_db_password = creds.password;

    Ok(())
}
