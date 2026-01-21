use crate::cli::actions::{Action, server::Args};
use anyhow::{Context, Result};

/// # Errors
/// Returns an error if required arguments are missing or inconsistent.
pub fn handler(matches: &clap::ArgMatches) -> Result<Action> {
    let port = matches.get_one::<u16>("port").copied().unwrap_or(8080);
    let dsn = matches
        .get_one::<String>("dsn")
        .cloned()
        .context("missing required argument: --dsn")?;

    let vault_url = matches
        .get_one::<String>("vault-url")
        .cloned()
        .context("missing required argument: --vault-url")?;
    let vault_target =
        crate::vault::VaultTarget::parse(&vault_url).context("invalid GENESIS_VAULT_URL")?;

    // Validate vault auth arguments relative to the URL scheme
    crate::cli::commands::validate(matches).map_err(|e| anyhow::anyhow!(e))?;

    let vault_role_id = matches.get_one::<String>("vault-role-id").cloned();
    let vault_secret_id = matches.get_one::<String>("vault-secret-id").cloned();
    let vault_wrapped_token = matches.get_one::<String>("vault-wrapped-token").cloned();
    let tls_pem_bundle = matches.get_one::<String>("tls-pem-bundle").cloned();
    let socket_path = matches.get_one::<String>("socket-path").cloned();

    Ok(Action::Server(Args {
        port,
        socket_path,
        dsn,
        vault_url,
        vault_target,
        vault_role_id,
        vault_secret_id,
        vault_wrapped_token,
        tls_pem_bundle,
    }))
}
