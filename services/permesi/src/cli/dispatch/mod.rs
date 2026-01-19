//! Command-line argument dispatch and server initialization.
//!
//! This module parses validated CLI arguments and maps them to the appropriate
//! action, such as starting the API server with its full configuration state.

use crate::cli::actions::{Action, server::Args};
use crate::cli::commands::{admission, auth, tls, vault};
use anyhow::{Context, Result};

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
    let vault_target =
        vault_client::VaultTarget::parse(&vault_opts.url).context("invalid PERMESI_VAULT_URL")?;

    let admission_opts = admission::Options::parse(matches)?;
    let auth_opts = auth::Options::parse(matches)?;
    let tls_opts = tls::Options::parse(matches)?;

    Ok(Action::Server(Args {
        port,
        dsn,
        vault_url: vault_opts.url,
        vault_target,
        vault_role_id: vault_opts.role_id,
        vault_secret_id: vault_opts.secret_id,
        vault_wrapped_token: vault_opts.wrapped_token,
        admission_paserk_url: admission_opts.url,
        admission_issuer: admission_opts.issuer,
        admission_audience: admission_opts.audience,
        tls_cert_path: tls_opts.cert_path,
        tls_key_path: tls_opts.key_path,
        tls_ca_path: tls_opts.ca_path,
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
        vault_kv_mount: vault_opts.kv_mount,
        vault_kv_path: vault_opts.kv_path,
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
                ("PERMESI_TLS_CERT_PATH", Some("/tmp/permesi-cert.pem")),
                ("PERMESI_TLS_KEY_PATH", Some("/tmp/permesi-key.pem")),
                ("PERMESI_TLS_CA_PATH", Some("/tmp/permesi-ca.pem")),
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
}
