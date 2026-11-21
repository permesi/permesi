use crate::cli::actions::{Action, server::Args};
use anyhow::{Context, Result, anyhow};

#[cfg(test)]
mod native_tests;

const ARG_OPENBAO_TRANSIT_MOUNT: &str = "openbao-transit-mount";

/// Normalize an OpenBao mount path received from CLI/env.
///
/// Mounts are stored without leading/trailing slashes and must not be empty
/// after normalization.
fn normalize_openbao_mount(arg: &str, value: &str) -> Result<String> {
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
pub(crate) fn openbao_auth(
    matches: &clap::ArgMatches,
) -> Result<Option<openbao_client::kubernetes::KubernetesAuth>> {
    let url = matches
        .get_one::<String>("openbao-url")
        .context("missing --openbao-url")?;
    let target = openbao_client::OpenBaoTarget::parse(url)?;
    let method = matches
        .get_one::<String>("openbao-auth-method")
        .context("missing --openbao-auth-method")?;
    let role_id = matches.get_one::<String>("openbao-role-id");
    let secret_id = matches.get_one::<String>("openbao-secret-id");
    let wrapped = matches.get_one::<String>("openbao-wrapped-token");
    let mount = matches
        .get_one::<String>("openbao-kubernetes-auth-mount")
        .context("missing Kubernetes auth mount")?;
    openbao_client::kubernetes::validate_auth_mount(mount).map_err(|e| anyhow!(e))?;
    let role = matches.get_one::<String>("openbao-kubernetes-role");
    let token_path = matches
        .get_one::<String>("openbao-kubernetes-token-path")
        .context("missing Kubernetes token path")?;
    if token_path.trim().is_empty() {
        return Err(anyhow!("--openbao-kubernetes-token-path must not be empty"));
    }
    if !matches!(method.as_str(), "auto" | "approle" | "kubernetes") {
        return Err(anyhow!("invalid --openbao-auth-method"));
    }
    if method != "auto" && !target.is_tcp() {
        return Err(anyhow!(
            "explicit --openbao-auth-method requires a TCP OpenBao URL"
        ));
    }
    if method == "kubernetes" {
        if role_id.is_some() || secret_id.is_some() || wrapped.is_some() {
            return Err(anyhow!(
                "AppRole credentials are forbidden with --openbao-auth-method kubernetes"
            ));
        }
        let role = role
            .filter(|r| !r.trim().is_empty())
            .context("--openbao-kubernetes-role is required for Kubernetes authentication")?;
        openbao_client::kubernetes::kubernetes_login_url(url, mount)?;
        return Ok(Some(openbao_client::kubernetes::KubernetesAuth {
            mount: mount.clone(),
            role: role.clone(),
            token_path: token_path.into(),
        }));
    }
    if role.is_some()
        || [
            "openbao-kubernetes-auth-mount",
            "openbao-kubernetes-token-path",
        ]
        .iter()
        .any(|arg| {
            matches
                .value_source(arg)
                .is_some_and(|source| source != clap::parser::ValueSource::DefaultValue)
        })
    {
        return Err(anyhow!(
            "Kubernetes settings require --openbao-auth-method kubernetes"
        ));
    }
    if target.is_tcp() {
        if role_id.is_none_or(|r| r.trim().is_empty()) {
            return Err(anyhow!(
                "--openbao-role-id is required for AppRole TCP mode"
            ));
        }
        if secret_id.is_some() && wrapped.is_some() {
            return Err(anyhow!(
                "--openbao-secret-id conflicts with --openbao-wrapped-token"
            ));
        }
        if secret_id.or(wrapped).is_none_or(|s| s.trim().is_empty()) {
            return Err(anyhow!(
                "--openbao-secret-id or --openbao-wrapped-token is required for AppRole TCP mode"
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

    let openbao_url = matches
        .get_one::<String>("openbao-url")
        .cloned()
        .context("missing required argument: --openbao-url")?;
    let openbao_target = crate::openbao::OpenBaoTarget::parse(&openbao_url)
        .context("invalid GENESIS_OPENBAO_URL")?;

    let openbao_kubernetes = openbao_auth(matches)?;

    let openbao_role_id = matches.get_one::<String>("openbao-role-id").cloned();
    let openbao_secret_id = matches.get_one::<String>("openbao-secret-id").cloned();
    let openbao_wrapped_token = matches.get_one::<String>("openbao-wrapped-token").cloned();
    let openbao_transit_mount = matches
        .get_one::<String>(ARG_OPENBAO_TRANSIT_MOUNT)
        .cloned()
        .context("missing required argument: --openbao-transit-mount")?;
    let openbao_transit_mount =
        normalize_openbao_mount(ARG_OPENBAO_TRANSIT_MOUNT, &openbao_transit_mount)?;
    let tls_pem_bundle = matches.get_one::<String>("tls-pem-bundle").cloned();
    let socket_path = matches.get_one::<String>("socket-path").cloned();

    let db_pool = crate::cli::commands::database::parse(matches)?;

    Ok(Action::Server(Args {
        port,
        socket_path,
        dsn,
        db_pool,
        openbao_url,
        openbao_target,
        openbao_kubernetes,
        openbao_role_id,
        openbao_secret_id,
        openbao_wrapped_token,
        openbao_transit_mount,
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
            "--openbao-url",
            "http://openbao:8200",
            "--openbao-role-id",
            "role",
            "--openbao-secret-id",
            "secret",
            "--openbao-transit-mount",
            "/transit/genesis/",
        ]);

        let action = handler(&matches);
        assert!(action.is_ok(), "dispatch should succeed");
        if let Ok(Action::Server(args)) = action {
            assert_eq!(args.openbao_transit_mount, "transit/genesis");
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
            "--openbao-url",
            "http://openbao:8200",
            "--openbao-role-id",
            "role",
            "--openbao-secret-id",
            "secret",
            "--openbao-transit-mount",
            "///",
        ]);

        let result = handler(&matches);
        assert!(result.is_err(), "expected validation error");
        if let Err(err) = result {
            assert!(err.to_string().contains("--openbao-transit-mount"));
        }
    }
}
