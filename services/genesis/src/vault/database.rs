use crate::cli::globals::GlobalArgs;
use anyhow::Result;
use tracing::instrument;

/// Get DB credentials from Vault
/// # Errors
/// Returns an error if the Vault request fails.
#[instrument(skip(globals))]
pub async fn database_creds(globals: &mut GlobalArgs) -> Result<()> {
    service_utils::vault::database::database_creds(globals, "genesis").await
}
