use crate::{api, cli::globals::GlobalArgs, vault};
use anyhow::{Context, Result, anyhow};
use secrecy::{ExposeSecret, SecretString};
use tracing::debug;
use url::Url;

#[derive(Debug)]
pub struct Args {
    pub port: u16,
    pub dsn: String,
    pub vault_url: String,
    pub vault_role_id: String,
    pub vault_secret_id: Option<String>,
    pub vault_wrapped_token: Option<String>,
}

/// Execute the server action.
/// # Errors
/// Returns an error if Vault login fails, DB credentials cannot be fetched, or the server fails to start.
pub async fn execute(args: Args) -> Result<()> {
    let mut globals = GlobalArgs::new(args.vault_url);

    // If vault wrapped token try to unwrap, otherwise use secret-id.
    let vault_token: String = if let Some(wrapped) = &args.vault_wrapped_token {
        let vault_session_id = vault::unwrap(&globals.vault_url, wrapped).await?;
        let (token, _) =
            vault::approle_login(&globals.vault_url, &vault_session_id, &args.vault_role_id)
                .await?;
        token
    } else {
        let secret_id = args
            .vault_secret_id
            .as_deref()
            .ok_or_else(|| anyhow!("Vault secret-id is required"))?;
        let (token, _) =
            vault::approle_login(&globals.vault_url, secret_id, &args.vault_role_id).await?;
        token
    };

    globals.set_token(SecretString::from(vault_token));

    // Get database username and password from Vault
    vault::database::database_creds(&mut globals)
        .await
        .context("Could not get database username and password")?;

    debug!("Global args: {:?}", globals);

    let mut dsn = Url::parse(&args.dsn)?;

    // Set username & password from GlobalArgs
    dsn.set_username(&globals.vault_db_username)
        .map_err(|()| anyhow!("Error setting username"))?;

    dsn.set_password(Some(globals.vault_db_password.expose_secret()))
        .map_err(|()| anyhow!("Error setting password"))?;

    api::new(args.port, dsn.to_string(), &globals).await
}
