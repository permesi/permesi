//! Command-line argument dispatch and server initialization.
//!
//! This module parses validated CLI arguments and maps them to the appropriate
//! action, such as starting the API server with its full configuration state.

use crate::cli::actions::{Action, server::Args};
use crate::cli::commands::{admission, auth, database, tls, vault};
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

fn require_positive(arg: &str, value: i64) -> Result<i64> {
    if value > 0 {
        Ok(value)
    } else {
        Err(anyhow!(
            "invalid argument: --{arg} must be greater than zero"
        ))
    }
}

/// Resolves trusted RP/origin defaults and revalidates clap-defined `WebAuthn` policy.
fn passkey_config(
    matches: &clap::ArgMatches,
    options: &auth::Options,
) -> Result<crate::webauthn::PasskeyConfig> {
    // Revalidate clap settings and resolve implicit RP/origin defaults from trusted auth configuration.
    let base_auth = crate::api::handlers::auth::AuthConfig::new(options.frontend_base_url.clone())
        .with_cors_allowed_origins(options.cors_allowed_origins.clone());
    crate::webauthn::PasskeyConfig::new(
        matches
            .get_one::<String>("passkeys-rp-id")
            .cloned()
            .unwrap_or_else(|| base_auth.webauthn_rp_id().to_owned()),
        matches
            .get_one::<String>("passkeys-rp-name")
            .cloned()
            .context("missing passkey RP name")?,
        matches
            .get_one::<String>("passkeys-allowed-origins")
            .map_or_else(
                || base_auth.webauthn_allowed_origins(),
                |s| Ok(s.split(',').map(|v| v.trim().to_owned()).collect()),
            )?,
        std::time::Duration::from_secs(
            *matches
                .get_one::<u64>("passkeys-challenge-ttl-seconds")
                .context("missing passkey TTL")?,
        ),
        *matches
            .get_one::<bool>("passkeys-preview-mode")
            .context("missing passkey preview policy")?,
    )
}

/// Revalidates tenant budgets, slug attempts and deadline ordering after clap parsing.
fn tenant_mutation_policy(
    matches: &clap::ArgMatches,
) -> Result<crate::api::tenant::MutationPolicy> {
    crate::api::tenant::MutationPolicy::new(
        *matches
            .get_one::<i64>("tenant-lock-timeout-ms")
            .context("missing tenant lock timeout")?,
        *matches
            .get_one::<u64>("tenant-mutation-timeout-ms")
            .context("missing tenant mutation timeout")?,
        *matches
            .get_one::<u16>("tenant-slug-attempts")
            .context("missing tenant slug attempts")?,
    )
}

/// Rechecks the challenge budget after clap so programmatic matches cannot bypass bounds.
fn mfa_challenge_limit(matches: &clap::ArgMatches) -> Result<i32> {
    let limit = *matches
        .get_one::<i32>("mfa-challenge-max-attempts")
        .context("missing MFA challenge attempt limit")?;
    if !(1..=20).contains(&limit) {
        return Err(anyhow!("invalid MFA challenge attempt limit"));
    }
    Ok(limit)
}

/// Revalidates pending-state capacity against both process and PostgreSQL integer bounds.
fn pending_state_limit(value: u64) -> Result<usize> {
    let auth_max_pending_states = usize::try_from(value)
        .context("--auth-max-pending-states exceeds this platform's capacity")?;
    if auth_max_pending_states == 0 {
        return Err(anyhow!(
            "invalid argument: --{} must be greater than zero",
            auth::ARG_AUTH_MAX_PENDING_STATES
        ));
    }
    i64::try_from(auth_max_pending_states)
        .context("--auth-max-pending-states exceeds PostgreSQL capacity")?;
    Ok(auth_max_pending_states)
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
    if !(1..=3600).contains(&auth_opts.opaque.login_ttl_seconds) {
        return Err(anyhow!(
            "invalid argument: --{} must be between 1 and 3600",
            auth::ARG_OPAQUE_LOGIN_TTL
        ));
    }
    if !(1..=10_000).contains(&auth_opts.opaque.exchange_timeout_ms) {
        return Err(anyhow!(
            "invalid argument: --{} must be between 1 and 10000",
            auth::ARG_OPAQUE_EXCHANGE_TIMEOUT
        ));
    }
    let auth_max_pending_states = pending_state_limit(auth_opts.max_pending_states)?;
    let auth_rate_limit_window_seconds = require_positive(
        auth::ARG_AUTH_RATE_LIMIT_WINDOW,
        auth_opts.rate_limit.window_seconds,
    )?;
    let auth_rate_limit_ip_attempts = require_positive(
        auth::ARG_AUTH_RATE_LIMIT_IP_ATTEMPTS,
        auth_opts.rate_limit.ip_attempts,
    )?;
    let auth_rate_limit_account_attempts = require_positive(
        auth::ARG_AUTH_RATE_LIMIT_ACCOUNT_ATTEMPTS,
        auth_opts.rate_limit.account_attempts,
    )?;
    let passkeys = passkey_config(matches, &auth_opts)?;
    let mfa_challenge_max_attempts = mfa_challenge_limit(matches)?;
    let tls_opts = tls::Options::parse(matches)?;
    let socket_path = matches.get_one::<String>("socket-path").cloned();

    let db_pool = database::parse(matches)?;
    let oauth = crate::oauth::config::OAuthConfig::from_matches(matches)?;
    let tenant_mutations = tenant_mutation_policy(matches)?;

    let registration = crate::api::handlers::auth::registration::Policy::from_matches(matches)?;
    let email_delivery = crate::api::email::DeliveryConfig::from_matches(matches)?;
    Ok(Action::Server(Args {
        registration,
        email_delivery,
        port,
        socket_path,
        dsn,
        db_pool,
        oauth,
        tenant_mutations,
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
        cors_allowed_origins: auth_opts.cors_allowed_origins,
        email_token_ttl_seconds: auth_opts.email_token_ttl_seconds,
        email_resend_cooldown_seconds: auth_opts.email_resend_cooldown_seconds,
        session_ttl_seconds: auth_opts.session_ttl_seconds,
        email_outbox_poll_seconds: auth_opts.email_outbox.poll_seconds,
        email_outbox_batch_size: auth_opts.email_outbox.batch_size,
        email_outbox_max_attempts: auth_opts.email_outbox.max_attempts,
        email_outbox_backoff_base_seconds: auth_opts.email_outbox.backoff_base_seconds,
        email_outbox_backoff_max_seconds: auth_opts.email_outbox.backoff_max_seconds,
        passkeys,
        mfa_challenge_max_attempts,
        opaque_server_id: auth_opts.opaque.server_id,
        opaque_login_ttl_seconds: auth_opts.opaque.login_ttl_seconds,
        opaque_exchange_timeout_ms: auth_opts.opaque.exchange_timeout_ms,
        auth_max_pending_states,
        auth_operations: crate::api::handlers::auth::operations::OperationsConfig::from_matches(
            matches,
        )?,
        auth_rate_limit_window_seconds,
        auth_rate_limit_ip_attempts,
        auth_rate_limit_account_attempts,
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
    fn mfa_challenge_limit_rejects_out_of_range_clap_and_programmatic_values() -> Result<()> {
        let base = [
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
        ];
        for value in ["0", "21"] {
            assert!(
                crate::cli::commands::new()
                    .try_get_matches_from(
                        base.into_iter()
                            .chain(["--mfa-challenge-max-attempts", value])
                    )
                    .is_err()
            );
            let matches = crate::cli::commands::new()
                .mut_arg("mfa-challenge-max-attempts", |arg| {
                    arg.value_parser(clap::value_parser!(i32))
                })
                .try_get_matches_from(
                    base.into_iter()
                        .chain(["--mfa-challenge-max-attempts", value]),
                )?;
            assert!(mfa_challenge_limit(&matches).is_err());
        }
        Ok(())
    }

    /// Clap bounds and dispatch revalidation must both reject invalid operator budgets.
    #[test]
    fn tenant_mutation_budgets_are_validated_by_clap_and_dispatch() -> Result<()> {
        temp_env::with_vars(
            [
                ("PERMESI_TENANT_LOCK_TIMEOUT_MS", None::<&str>),
                ("PERMESI_TENANT_MUTATION_TIMEOUT_MS", None::<&str>),
                ("PERMESI_TENANT_SLUG_ATTEMPTS", None::<&str>),
            ],
            || {
                let base = [
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
                ];
                for (lock, total) in [
                    ("0", "5000"),
                    ("10001", "30000"),
                    ("1", "0"),
                    ("1", "30001"),
                ] {
                    let args = base.into_iter().chain([
                        "--tenant-lock-timeout-ms",
                        lock,
                        "--tenant-mutation-timeout-ms",
                        total,
                    ]);
                    assert!(
                        crate::cli::commands::new()
                            .try_get_matches_from(args)
                            .is_err()
                    );
                    // Programmatic matches can bypass clap's range validators; dispatch cannot.
                    let matches = crate::cli::commands::new()
                        .mut_arg("tenant-lock-timeout-ms", |arg| {
                            arg.value_parser(clap::value_parser!(i64))
                        })
                        .mut_arg("tenant-mutation-timeout-ms", |arg| {
                            arg.value_parser(clap::value_parser!(u64))
                        })
                        .try_get_matches_from(base.into_iter().chain([
                            "--tenant-lock-timeout-ms",
                            lock,
                            "--tenant-mutation-timeout-ms",
                            total,
                        ]))?;
                    assert!(handler(&matches).is_err());
                }
                let matches =
                    crate::cli::commands::new().try_get_matches_from(base.into_iter().chain([
                        "--tenant-lock-timeout-ms",
                        "1000",
                        "--tenant-mutation-timeout-ms",
                        "999",
                    ]))?;
                assert!(handler(&matches).is_err());
                for attempts in ["0", "129"] {
                    let args = base.into_iter().chain(["--tenant-slug-attempts", attempts]);
                    assert!(
                        crate::cli::commands::new()
                            .try_get_matches_from(args)
                            .is_err()
                    );
                    let matches = crate::cli::commands::new()
                        .mut_arg("tenant-slug-attempts", |arg| {
                            arg.value_parser(clap::value_parser!(u16))
                        })
                        .try_get_matches_from(
                            base.into_iter().chain(["--tenant-slug-attempts", attempts]),
                        )?;
                    assert!(handler(&matches).is_err());
                }
                let matches = crate::cli::commands::new().try_get_matches_from(base)?;
                assert!(handler(&matches).is_ok());
                Ok(())
            },
        )
    }

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
