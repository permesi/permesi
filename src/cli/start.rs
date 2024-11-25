use crate::cli::{actions::Action, commands, dispatch::handler, globals::GlobalArgs, telemetry};
use crate::vault;
use anyhow::{anyhow, Context, Result};
use secrecy::SecretString;
use tracing::debug;

/// Start the CLI
/// # Errors
/// Will return an error if the vault role-id or vault url is not provided
pub async fn start() -> Result<(Action, GlobalArgs)> {
    let matches = commands::new().get_matches();

    // vault role-id
    let vault_role_id = matches
        .get_one::<String>("vault-role-id")
        .map(|s: &String| s.to_string())
        .ok_or_else(|| anyhow!("Vault role-id is required"))?;

    // vault url
    let vault_url = matches
        .get_one::<String>("vault-url")
        .map(|s: &String| s.to_string())
        .ok_or_else(|| anyhow!("Vault URL is required"))?;

    let mut global_args = GlobalArgs::new(vault_url);

    let vault_token: String;

    // if vault wrapped token try to unwrap
    if let Some(wrapped_token) = matches.get_one::<String>("vault-wrapped-token") {
        let vault_session_id = vault::unwrap(&global_args.vault_url, wrapped_token).await?;
        (vault_token, _) =
            vault::approle_login(&global_args.vault_url, &vault_session_id, &vault_role_id).await?;
    } else {
        let vault_session_id = matches
            .get_one::<String>("vault-secret-id")
            .map(|s: &String| s.to_string())
            .ok_or_else(|| anyhow!("Vault secret-id is required"))?;

        (vault_token, _) =
            vault::approle_login(&global_args.vault_url, &vault_session_id, &vault_role_id).await?;
    }

    global_args.set_token(SecretString::from(vault_token));

    // get database username and password from Vault
    vault::database::database_creds(&mut global_args)
        .await
        .context("Could not get database username and password")?;

    let verbosity_level = match matches.get_one::<u8>("verbosity").map_or(0, |&v| v) {
        0 => tracing::Level::ERROR,
        1 => tracing::Level::WARN,
        2 => tracing::Level::INFO,
        3 => tracing::Level::DEBUG,
        _ => tracing::Level::TRACE,
    };

    telemetry::init(verbosity_level)?;

    let action = handler(&matches)?;

    debug!("Global args: {:?}", global_args);

    Ok((action, global_args))
}
