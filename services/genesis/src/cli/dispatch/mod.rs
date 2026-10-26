use crate::cli::actions::{Action, server::Args};
use anyhow::{Context, Result, anyhow};

#[cfg(test)]
mod native_tests;

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

/// Revalidate auth selection at dispatch; Kubernetes settings never activate fallback.
/// Auto sockets retain Agent behavior, including ignored legacy `AppRole` arguments.
pub(crate) fn vault_auth(
    matches: &clap::ArgMatches,
) -> Result<Option<vault_client::kubernetes::KubernetesAuth>> {
    let url = matches
        .get_one::<String>("vault-url")
        .context("missing --vault-url")?;
    let target = vault_client::VaultTarget::parse(url)?;
    let method = matches
        .get_one::<String>("vault-auth-method")
        .context("missing --vault-auth-method")?;
    let role_id = matches.get_one::<String>("vault-role-id");
    let secret_id = matches.get_one::<String>("vault-secret-id");
    let wrapped = matches.get_one::<String>("vault-wrapped-token");
    let mount = matches
        .get_one::<String>("vault-kubernetes-auth-mount")
        .context("missing Kubernetes auth mount")?;
    vault_client::kubernetes::validate_auth_mount(mount).map_err(|e| anyhow!(e))?;
    let role = matches.get_one::<String>("vault-kubernetes-role");
    let token_path = matches
        .get_one::<String>("vault-kubernetes-token-path")
        .context("missing Kubernetes token path")?;
    if token_path.trim().is_empty() {
        return Err(anyhow!("--vault-kubernetes-token-path must not be empty"));
    }
    if !matches!(method.as_str(), "auto" | "approle" | "kubernetes") {
        return Err(anyhow!("invalid --vault-auth-method"));
    }
    if method != "auto" && !target.is_tcp() {
        return Err(anyhow!(
            "explicit --vault-auth-method requires a TCP Vault URL"
        ));
    }
    if method == "kubernetes" {
        if role_id.is_some() || secret_id.is_some() || wrapped.is_some() {
            return Err(anyhow!(
                "AppRole credentials are forbidden with --vault-auth-method kubernetes"
            ));
        }
        let role = role
            .filter(|r| !r.trim().is_empty())
            .context("--vault-kubernetes-role is required for Kubernetes authentication")?;
        vault_client::kubernetes::kubernetes_login_url(url, mount)?;
        return Ok(Some(vault_client::kubernetes::KubernetesAuth {
            mount: mount.clone(),
            role: role.clone(),
            token_path: token_path.into(),
        }));
    }
    if role.is_some()
        || ["vault-kubernetes-auth-mount", "vault-kubernetes-token-path"]
            .iter()
            .any(|arg| {
                matches
                    .value_source(arg)
                    .is_some_and(|source| source != clap::parser::ValueSource::DefaultValue)
            })
    {
        return Err(anyhow!(
            "Kubernetes settings require --vault-auth-method kubernetes"
        ));
    }
    if target.is_tcp() {
        if role_id.is_none_or(|r| r.trim().is_empty()) {
            return Err(anyhow!("--vault-role-id is required for AppRole TCP mode"));
        }
        if secret_id.is_some() && wrapped.is_some() {
            return Err(anyhow!(
                "--vault-secret-id conflicts with --vault-wrapped-token"
            ));
        }
        if secret_id.or(wrapped).is_none_or(|s| s.trim().is_empty()) {
            return Err(anyhow!(
                "--vault-secret-id or --vault-wrapped-token is required for AppRole TCP mode"
            ));
        }
    }
    Ok(None)
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

    let vault_kubernetes = vault_auth(matches)?;

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

    let db_pool = crate::cli::commands::database::parse(matches)?;

    Ok(Action::Server(Args {
        port,
        socket_path,
        dsn,
        db_pool,
        vault_url,
        vault_target,
        vault_kubernetes,
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
