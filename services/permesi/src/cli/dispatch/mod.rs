use crate::cli::actions::{Action, server::Args};
use anyhow::{Context, Result};

struct EmailOutboxArgs {
    poll_seconds: u64,
    batch_size: usize,
    max_attempts: u32,
    backoff_base_seconds: u64,
    backoff_max_seconds: u64,
}

fn parse_email_outbox_args(matches: &clap::ArgMatches) -> EmailOutboxArgs {
    EmailOutboxArgs {
        poll_seconds: matches
            .get_one::<u64>("email-outbox-poll-seconds")
            .copied()
            .unwrap_or(5),
        batch_size: matches
            .get_one::<usize>("email-outbox-batch-size")
            .copied()
            .unwrap_or(10),
        max_attempts: matches
            .get_one::<u32>("email-outbox-max-attempts")
            .copied()
            .unwrap_or(5),
        backoff_base_seconds: matches
            .get_one::<u64>("email-outbox-backoff-base-seconds")
            .copied()
            .unwrap_or(5),
        backoff_max_seconds: matches
            .get_one::<u64>("email-outbox-backoff-max-seconds")
            .copied()
            .unwrap_or(300),
    }
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
    let vault_role_id = matches
        .get_one::<String>("vault-role-id")
        .cloned()
        .context("missing required argument: --vault-role-id")?;

    let vault_secret_id = matches.get_one::<String>("vault-secret-id").cloned();
    let vault_wrapped_token = matches.get_one::<String>("vault-wrapped-token").cloned();

    if vault_secret_id.is_none() && vault_wrapped_token.is_none() {
        anyhow::bail!("missing required argument: --vault-secret-id or --vault-wrapped-token");
    }

    let admission_paserk_path = matches.get_one::<String>("admission-paserk-path").cloned();
    let admission_paserk = matches.get_one::<String>("admission-paserk").cloned();
    let admission_paserk_url = matches.get_one::<String>("admission-paserk-url").cloned();

    if admission_paserk_path.is_none()
        && admission_paserk.is_none()
        && admission_paserk_url.is_none()
    {
        anyhow::bail!(
            "missing required argument: --admission-paserk-path, --admission-paserk, or --admission-paserk-url"
        );
    }

    let admission_issuer = matches.get_one::<String>("admission-issuer").cloned();
    let admission_audience = matches.get_one::<String>("admission-audience").cloned();

    let zero_token_validate_url = matches
        .get_one::<String>("zero-token-validate-url")
        .cloned()
        .context("missing required argument: --zero-token-validate-url")?;
    let frontend_base_url = matches
        .get_one::<String>("frontend-base-url")
        .cloned()
        .context("missing required argument: --frontend-base-url")?;
    let email_token_ttl_seconds = matches
        .get_one::<i64>("email-token-ttl-seconds")
        .copied()
        .unwrap_or(1800);
    let email_resend_cooldown_seconds = matches
        .get_one::<i64>("email-resend-cooldown-seconds")
        .copied()
        .unwrap_or(60);
    let email_outbox = parse_email_outbox_args(matches);
    let opaque_kv_mount = matches
        .get_one::<String>("opaque-kv-mount")
        .cloned()
        .unwrap_or_else(|| "kv".to_string());
    let opaque_kv_path = matches
        .get_one::<String>("opaque-kv-path")
        .cloned()
        .unwrap_or_else(|| "permesi/opaque".to_string());
    let opaque_server_id = matches
        .get_one::<String>("opaque-server-id")
        .cloned()
        .unwrap_or_else(|| "api.permesi.dev".to_string());
    let opaque_login_ttl_seconds = matches
        .get_one::<u64>("opaque-login-ttl-seconds")
        .copied()
        .unwrap_or(300);

    Ok(Action::Server(Args {
        port,
        dsn,
        vault_url,
        vault_role_id,
        vault_secret_id,
        vault_wrapped_token,
        admission_paserk,
        admission_paserk_path,
        admission_paserk_url,
        admission_issuer,
        admission_audience,
        zero_token_validate_url,
        frontend_base_url,
        email_token_ttl_seconds,
        email_resend_cooldown_seconds,
        email_outbox_poll_seconds: email_outbox.poll_seconds,
        email_outbox_batch_size: email_outbox.batch_size,
        email_outbox_max_attempts: email_outbox.max_attempts,
        email_outbox_backoff_base_seconds: email_outbox.backoff_base_seconds,
        email_outbox_backoff_max_seconds: email_outbox.backoff_max_seconds,
        opaque_kv_mount,
        opaque_kv_path,
        opaque_server_id,
        opaque_login_ttl_seconds,
    }))
}
