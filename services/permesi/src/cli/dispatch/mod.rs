//! Command-line argument dispatch and server initialization.
//!
//! This module parses validated CLI arguments and maps them to the appropriate
//! action, such as starting the API server with its full configuration state.

use crate::cli::actions::{Action, server::Args};
use crate::cli::commands::{admission, auth, tls, vault};
use anyhow::{Context, Result, anyhow};

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

/// Map validated CLI matches to a server action.
///
/// # Errors
/// Returns an error if required arguments are missing or inconsistent.
pub fn handler(matches: &clap::ArgMatches) -> Result<Action> {
    let port = matches.get_one::<u16>("port").copied().unwrap_or(8080);
    let dsn = matches
        .get_one::<String>("dsn")
        .cloned()
        .context("missing required argument: --dsn")?;

    // Validate vault auth arguments relative to the URL scheme
    crate::cli::commands::validate(matches).map_err(|e| anyhow::anyhow!(e))?;

    let vault_opts = vault::Options::parse(matches)?;
    let vault_kv_mount = normalize_vault_mount(vault::ARG_VAULT_KV_MOUNT, &vault_opts.kv_mount)?;
    let vault_transit_mount =
        normalize_vault_mount(vault::ARG_VAULT_TRANSIT_MOUNT, &vault_opts.transit_mount)?;
    let vault_target =
        vault_client::VaultTarget::parse(&vault_opts.url).context("invalid PERMESI_VAULT_URL")?;

    let admission_opts = admission::Options::parse(matches)?;
    let auth_opts = auth::Options::parse(matches)?;
    let tls_opts = tls::Options::parse(matches)?;
    let socket_path = matches.get_one::<String>("socket-path").cloned();

    Ok(Action::Server(Args {
        port,
        socket_path,
        dsn,
        vault_url: vault_opts.url,
        vault_target,
        vault_role_id: vault_opts.role_id,
        vault_secret_id: vault_opts.secret_id,
        vault_wrapped_token: vault_opts.wrapped_token,
        admission_paserk_url: admission_opts.url,
        admission_issuer: admission_opts.issuer,
        admission_audience: admission_opts.audience,
        tls_pem_bundle: tls_opts.map(|o| o.pem_bundle),
        admission_paserk_ca_path: admission_opts.paserk_ca_path,
        frontend_base_url: auth_opts.frontend_base_url,
        email_token_ttl_seconds: auth_opts.email_token_ttl_seconds,
        email_resend_cooldown_seconds: auth_opts.email_resend_cooldown_seconds,
        session_ttl_seconds: auth_opts.session_ttl_seconds,
        email_outbox_poll_seconds: auth_opts.email_outbox.poll_seconds,
        email_outbox_batch_size: auth_opts.email_outbox.batch_size,
        email_outbox_max_attempts: auth_opts.email_outbox.max_attempts,
        email_outbox_backoff_base_seconds: auth_opts.email_outbox.backoff_base_seconds,
        email_outbox_backoff_max_seconds: auth_opts.email_outbox.backoff_max_seconds,
        opaque_server_id: auth_opts.opaque.server_id,
        opaque_login_ttl_seconds: auth_opts.opaque.login_ttl_seconds,
        platform_admin_ttl_seconds: auth_opts.admin.ttl_seconds,
        platform_recent_auth_seconds: auth_opts.admin.recent_auth_seconds,
        vault_kv_mount,
        vault_kv_path: vault_opts.kv_path,
        vault_transit_mount,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admission_paserk_url_required() {
        temp_env::with_vars(
            [
                ("PERMESI_ADMISSION_PASERK_URL", None::<&str>),
                ("PERMESI_TLS_PEM_BUNDLE", Some("/tmp/permesi-bundle.pem")),
                (
                    "PERMESI_DSN",
                    Some("postgres://user@localhost:5432/permesi"),
                ),
                (
                    "PERMESI_VAULT_URL",
                    Some("http://127.0.0.1:8200/v1/auth/approle/login"),
                ),
                ("PERMESI_VAULT_ROLE_ID", Some("role-id")),
                ("PERMESI_VAULT_SECRET_ID", Some("secret-id")),
            ],
            || {
                let command = crate::cli::commands::new();
                let matches = command.get_matches_from(vec!["permesi"]);
                let result = handler(&matches);
                assert!(result.is_err());
                if let Err(err) = result {
                    assert!(
                        err.to_string()
                            .contains("missing required argument: --admission-paserk-url")
                    );
                }
            },
        );
    }

    #[test]
    fn vault_mounts_are_normalized_in_dispatch() {
        let command = crate::cli::commands::new();
        let matches = command.get_matches_from(vec![
            "permesi",
            "--dsn",
            "postgres://",
            "--admission-paserk-url",
            "https://url",
            "--tls-pem-bundle",
            "bundle",
            "--vault-url",
            "http://vault:8200",
            "--vault-role-id",
            "role",
            "--vault-secret-id",
            "secret",
            "--vault-kv-mount",
            "/secret/permesi/",
            "--vault-transit-mount",
            "/transit/permesi/",
        ]);

        let action = handler(&matches);
        assert!(action.is_ok(), "dispatch should succeed");
        if let Ok(Action::Server(args)) = action {
            assert_eq!(args.vault_kv_mount, "secret/permesi");
            assert_eq!(args.vault_transit_mount, "transit/permesi");
        }
    }

    #[test]
    fn empty_transit_mount_is_rejected() {
        let command = crate::cli::commands::new();
        let matches = command.get_matches_from(vec![
            "permesi",
            "--dsn",
            "postgres://",
            "--admission-paserk-url",
            "https://url",
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
