use crate::cli::actions::{Action, server::Args};
use anyhow::{Context, Result, anyhow};

const ARG_VAULT_TRANSIT_MOUNT: &str = "vault-transit-mount";

/// Normalize a Vault mount path received from CLI/env.
///
/// Mounts are stored without leading/trailing slashes and must not be empty
/// after normalization.
fn normalize_vault_mount(arg: &str, value: &str) -> Result<String> {
    let normalized = value.trim_matches('/').to_string();
    if normalized.is_empty() {
        return Err(anyhow!("invalid argument: --{arg} must not be empty"));
    }
    if normalized.chars().any(char::is_whitespace) {
        return Err(anyhow!(
            "invalid argument: --{arg} must not contain whitespace"
        ));
    }
    Ok(normalized)
}

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
    let vault_transit_mount = matches
        .get_one::<String>(ARG_VAULT_TRANSIT_MOUNT)
        .cloned()
        .context("missing required argument: --vault-transit-mount")?;
    let vault_transit_mount = normalize_vault_mount(ARG_VAULT_TRANSIT_MOUNT, &vault_transit_mount)?;
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
        vault_transit_mount,
        tls_pem_bundle,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transit_mount_is_normalized_in_dispatch() {
        let command = crate::cli::commands::new();
        let matches = command.get_matches_from(vec![
            "genesis",
            "--dsn",
            "postgres://",
            "--tls-pem-bundle",
            "bundle",
            "--vault-url",
            "http://vault:8200",
            "--vault-role-id",
            "role",
            "--vault-secret-id",
            "secret",
            "--vault-transit-mount",
            "/transit/genesis/",
        ]);

        let action = handler(&matches);
        assert!(action.is_ok(), "dispatch should succeed");
        if let Ok(Action::Server(args)) = action {
            assert_eq!(args.vault_transit_mount, "transit/genesis");
        }
    }

    #[test]
    fn empty_transit_mount_is_rejected() {
        let command = crate::cli::commands::new();
        let matches = command.get_matches_from(vec![
            "genesis",
            "--dsn",
            "postgres://",
            "--tls-pem-bundle",
            "bundle",
            "--vault-url",
            "http://vault:8200",
            "--vault-role-id",
            "role",
            "--vault-secret-id",
            "secret",
            "--vault-transit-mount",
            "///",
        ]);

        let result = handler(&matches);
        assert!(result.is_err(), "expected validation error");
        if let Err(err) = result {
            assert!(err.to_string().contains("--vault-transit-mount"));
        }
    }
}
