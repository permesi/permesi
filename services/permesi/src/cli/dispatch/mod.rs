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
    let vault_role_id = matches
        .get_one::<String>("vault-role-id")
        .cloned()
        .context("missing required argument: --vault-role-id")?;

    let vault_secret_id = matches.get_one::<String>("vault-secret-id").cloned();
    let vault_wrapped_token = matches.get_one::<String>("vault-wrapped-token").cloned();

    if vault_secret_id.is_none() && vault_wrapped_token.is_none() {
        anyhow::bail!("missing required argument: --vault-secret-id or --vault-wrapped-token");
    }

    let admission_jwks_path = matches.get_one::<String>("admission-jwks-path").cloned();
    let admission_jwks = matches.get_one::<String>("admission-jwks").cloned();

    if admission_jwks_path.is_none() && admission_jwks.is_none() {
        anyhow::bail!("missing required argument: --admission-jwks-path or --admission-jwks");
    }

    let admission_issuer = matches.get_one::<String>("admission-issuer").cloned();
    let admission_audience = matches.get_one::<String>("admission-audience").cloned();

    Ok(Action::Server(Args {
        port,
        dsn,
        vault_url,
        vault_role_id,
        vault_secret_id,
        vault_wrapped_token,
        admission_jwks,
        admission_jwks_path,
        admission_issuer,
        admission_audience,
    }))
}
