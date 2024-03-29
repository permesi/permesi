use crate::cli::{actions::Action, globals::GlobalArgs};
use crate::permesi::new;
use anyhow::{anyhow, Result};
use secrecy::ExposeSecret;
use url::Url;

/// Handle the create action
/// # Errors
/// Will return an error if the DSN is invalid
pub async fn handle(action: Action, globals: &GlobalArgs) -> Result<()> {
    match action {
        Action::Server { port, dsn } => {
            let mut dsn = Url::parse(&dsn)?;

            // Set username & password from GlobalArgs
            dsn.set_username(&globals.vault_db_username)
                .map_err(|()| anyhow!("Error setting username"))?;

            dsn.set_password(Some(globals.vault_db_password.expose_secret()))
                .map_err(|()| anyhow!("Error setting password"))?;

            new(port, dsn.to_string(), globals).await?;
        }
    }

    Ok(())
}
