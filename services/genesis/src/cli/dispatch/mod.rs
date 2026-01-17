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
    let tls_cert_path = read_required_path_arg(matches, "tls-cert-path", "GENESIS_TLS_CERT_PATH")?;
    let tls_key_path = read_required_path_arg(matches, "tls-key-path", "GENESIS_TLS_KEY_PATH")?;
    let tls_ca_path = read_required_path_arg(matches, "tls-ca-path", "GENESIS_TLS_CA_PATH")?;

    if vault_secret_id.is_none() && vault_wrapped_token.is_none() {
        anyhow::bail!("missing required argument: --vault-secret-id or --vault-wrapped-token");
    }

    Ok(Action::Server(Args {
        port,
        dsn,
        vault_url,
        vault_role_id,
        vault_secret_id,
        vault_wrapped_token,
        tls_cert_path,
        tls_key_path,
        tls_ca_path,
    }))
}

fn read_required_path_arg(
    matches: &clap::ArgMatches,
    name: &str,
    env_name: &str,
) -> Result<String> {
    match matches.get_one::<String>(name) {
        Some(value) if value.trim().is_empty() => {
            anyhow::bail!("{env_name} must not be empty");
        }
        Some(value) => Ok(value.clone()),
        None => anyhow::bail!("missing required argument: --{name}"),
    }
}
