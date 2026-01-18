use clap::{Arg, Command};

pub fn with_args(command: Command) -> Command {
    let command = with_auth_email_args(command);
    let command = with_auth_outbox_args(command);
    let command = with_auth_opaque_args(command);
    with_admin_args(command)
}

fn with_auth_email_args(command: Command) -> Command {
    command
        .arg(
            Arg::new("frontend-base-url")
                .long("frontend-base-url")
                .help("Frontend base URL used for verification links")
                .env("PERMESI_FRONTEND_BASE_URL")
                .default_value("https://permesi.dev"),
        )
        .arg(
            Arg::new("email-token-ttl-seconds")
                .long("email-token-ttl-seconds")
                .help("Email verification token TTL in seconds")
                .env("PERMESI_EMAIL_TOKEN_TTL_SECONDS")
                .default_value("1800")
                .value_parser(clap::value_parser!(i64)),
        )
        .arg(
            Arg::new("email-resend-cooldown-seconds")
                .long("email-resend-cooldown-seconds")
                .help("Cooldown before resending verification emails")
                .env("PERMESI_EMAIL_RESEND_COOLDOWN_SECONDS")
                .default_value("60")
                .value_parser(clap::value_parser!(i64)),
        )
        .arg(
            Arg::new("session-ttl-seconds")
                .long("session-ttl-seconds")
                .help("Session cookie TTL in seconds")
                .env("PERMESI_SESSION_TTL_SECONDS")
                .default_value("604800")
                .value_parser(clap::value_parser!(i64)),
        )
}

fn with_auth_outbox_args(command: Command) -> Command {
    command
        .arg(
            Arg::new("email-outbox-poll-seconds")
                .long("email-outbox-poll-seconds")
                .help("Email outbox poll interval in seconds")
                .env("PERMESI_EMAIL_OUTBOX_POLL_SECONDS")
                .default_value("5")
                .value_parser(clap::value_parser!(u64)),
        )
        .arg(
            Arg::new("email-outbox-batch-size")
                .long("email-outbox-batch-size")
                .help("Email outbox batch size per poll")
                .env("PERMESI_EMAIL_OUTBOX_BATCH_SIZE")
                .default_value("10")
                .value_parser(clap::value_parser!(usize)),
        )
        .arg(
            Arg::new("email-outbox-max-attempts")
                .long("email-outbox-max-attempts")
                .help("Max attempts before marking an email as failed")
                .env("PERMESI_EMAIL_OUTBOX_MAX_ATTEMPTS")
                .default_value("5")
                .value_parser(clap::value_parser!(u32)),
        )
        .arg(
            Arg::new("email-outbox-backoff-base-seconds")
                .long("email-outbox-backoff-base-seconds")
                .help("Base delay for email outbox retry backoff")
                .env("PERMESI_EMAIL_OUTBOX_BACKOFF_BASE_SECONDS")
                .default_value("5")
                .value_parser(clap::value_parser!(u64)),
        )
        .arg(
            Arg::new("email-outbox-backoff-max-seconds")
                .long("email-outbox-backoff-max-seconds")
                .help("Max delay for email outbox retry backoff")
                .env("PERMESI_EMAIL_OUTBOX_BACKOFF_MAX_SECONDS")
                .default_value("300")
                .value_parser(clap::value_parser!(u64)),
        )
}

fn with_auth_opaque_args(command: Command) -> Command {
    command
        .arg(
            Arg::new("opaque-server-id")
                .long("opaque-server-id")
                .help("OPAQUE server identifier")
                .env("PERMESI_OPAQUE_SERVER_ID")
                .default_value("api.permesi.dev"),
        )
        .arg(
            Arg::new("opaque-login-ttl-seconds")
                .long("opaque-login-ttl-seconds")
                .help("TTL for OPAQUE login state storage")
                .env("PERMESI_OPAQUE_LOGIN_TTL_SECONDS")
                .default_value("300")
                .value_parser(clap::value_parser!(u64)),
        )
}

fn with_admin_args(command: Command) -> Command {
    command
        .arg(
            Arg::new("vault-addr")
                .long("vault-addr")
                .help("Vault base address for admin step-up lookups")
                .env("VAULT_ADDR"),
        )
        .arg(
            Arg::new("vault-namespace")
                .long("vault-namespace")
                .help("Vault namespace for admin step-up lookups")
                .env("VAULT_NAMESPACE"),
        )
        .arg(
            Arg::new("vault-policy")
                .long("vault-policy")
                .help("Vault policy required for operator elevation")
                .env("PERMESI_VAULT_POLICY")
                .default_value("permesi-operators"),
        )
        .arg(
            Arg::new("platform-admin-ttl-seconds")
                .long("platform-admin-ttl-seconds")
                .help("Admin elevation token TTL in seconds")
                .env("PLATFORM_ADMIN_TTL_SECONDS")
                .default_value("43200")
                .value_parser(clap::value_parser!(i64)),
        )
        .arg(
            Arg::new("platform-recent-auth-seconds")
                .long("platform-recent-auth-seconds")
                .help("Maximum session age for bootstrap in seconds")
                .env("PLATFORM_RECENT_AUTH_SECONDS")
                .default_value("3600")
                .value_parser(clap::value_parser!(i64)),
        )
}
