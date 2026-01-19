use clap::{Arg, ArgMatches, Command};

pub const ARG_FRONTEND_BASE_URL: &str = "frontend-base-url";
pub const ARG_EMAIL_TOKEN_TTL: &str = "email-token-ttl-seconds";
pub const ARG_EMAIL_RESEND_COOLDOWN: &str = "email-resend-cooldown-seconds";
pub const ARG_SESSION_TTL: &str = "session-ttl-seconds";

pub const ARG_EMAIL_OUTBOX_POLL: &str = "email-outbox-poll-seconds";
pub const ARG_EMAIL_OUTBOX_BATCH: &str = "email-outbox-batch-size";
pub const ARG_EMAIL_OUTBOX_MAX_ATTEMPTS: &str = "email-outbox-max-attempts";
pub const ARG_EMAIL_OUTBOX_BACKOFF_BASE: &str = "email-outbox-backoff-base-seconds";
pub const ARG_EMAIL_OUTBOX_BACKOFF_MAX: &str = "email-outbox-backoff-max-seconds";

pub const ARG_OPAQUE_SERVER_ID: &str = "opaque-server-id";
pub const ARG_OPAQUE_LOGIN_TTL: &str = "opaque-login-ttl-seconds";

pub const ARG_PLATFORM_ADMIN_TTL: &str = "platform-admin-ttl-seconds";
pub const ARG_PLATFORM_RECENT_AUTH: &str = "platform-recent-auth-seconds";

#[derive(Debug, Clone)]
pub struct EmailOutboxOptions {
    pub poll_seconds: u64,
    pub batch_size: usize,
    pub max_attempts: u32,
    pub backoff_base_seconds: u64,
    pub backoff_max_seconds: u64,
}

#[derive(Debug, Clone)]
pub struct OpaqueOptions {
    pub server_id: String,
    pub login_ttl_seconds: u64,
}

#[derive(Debug, Clone)]
pub struct AdminOptions {
    pub ttl_seconds: i64,
    pub recent_auth_seconds: i64,
}

#[derive(Debug, Clone)]
pub struct Options {
    pub frontend_base_url: String,
    pub email_token_ttl_seconds: i64,
    pub email_resend_cooldown_seconds: i64,
    pub session_ttl_seconds: i64,
    pub email_outbox: EmailOutboxOptions,
    pub opaque: OpaqueOptions,
    pub admin: AdminOptions,
}

impl Options {
    /// Parse auth arguments from matches.
    ///
    /// # Errors
    /// Returns an error if required arguments are missing.
    pub fn parse(matches: &ArgMatches) -> anyhow::Result<Self> {
        let frontend_base_url = matches
            .get_one::<String>(ARG_FRONTEND_BASE_URL)
            .cloned()
            .ok_or_else(|| {
                anyhow::anyhow!("missing required argument: --{ARG_FRONTEND_BASE_URL}")
            })?;

        Ok(Self {
            frontend_base_url,
            email_token_ttl_seconds: matches
                .get_one::<i64>(ARG_EMAIL_TOKEN_TTL)
                .copied()
                .unwrap_or(1800),
            email_resend_cooldown_seconds: matches
                .get_one::<i64>(ARG_EMAIL_RESEND_COOLDOWN)
                .copied()
                .unwrap_or(60),
            session_ttl_seconds: matches
                .get_one::<i64>(ARG_SESSION_TTL)
                .copied()
                .unwrap_or(604_800),
            email_outbox: EmailOutboxOptions {
                poll_seconds: matches
                    .get_one::<u64>(ARG_EMAIL_OUTBOX_POLL)
                    .copied()
                    .unwrap_or(5),
                batch_size: matches
                    .get_one::<usize>(ARG_EMAIL_OUTBOX_BATCH)
                    .copied()
                    .unwrap_or(10),
                max_attempts: matches
                    .get_one::<u32>(ARG_EMAIL_OUTBOX_MAX_ATTEMPTS)
                    .copied()
                    .unwrap_or(5),
                backoff_base_seconds: matches
                    .get_one::<u64>(ARG_EMAIL_OUTBOX_BACKOFF_BASE)
                    .copied()
                    .unwrap_or(5),
                backoff_max_seconds: matches
                    .get_one::<u64>(ARG_EMAIL_OUTBOX_BACKOFF_MAX)
                    .copied()
                    .unwrap_or(300),
            },
            opaque: OpaqueOptions {
                server_id: matches
                    .get_one::<String>(ARG_OPAQUE_SERVER_ID)
                    .cloned()
                    .unwrap_or_else(|| "api.permesi.dev".to_string()),
                login_ttl_seconds: matches
                    .get_one::<u64>(ARG_OPAQUE_LOGIN_TTL)
                    .copied()
                    .unwrap_or(300),
            },
            admin: AdminOptions {
                ttl_seconds: matches
                    .get_one::<i64>(ARG_PLATFORM_ADMIN_TTL)
                    .copied()
                    .unwrap_or(43200),
                recent_auth_seconds: matches
                    .get_one::<i64>(ARG_PLATFORM_RECENT_AUTH)
                    .copied()
                    .unwrap_or(3600),
            },
        })
    }
}

#[must_use]
pub fn with_args(command: Command) -> Command {
    let command = with_auth_email_args(command);
    let command = with_auth_outbox_args(command);
    let command = with_auth_opaque_args(command);
    with_admin_args(command)
}

fn with_auth_email_args(command: Command) -> Command {
    command
        .arg(
            Arg::new(ARG_FRONTEND_BASE_URL)
                .long(ARG_FRONTEND_BASE_URL)
                .help("Frontend base URL used for verification links")
                .env("PERMESI_FRONTEND_BASE_URL")
                .default_value("https://permesi.dev"),
        )
        .arg(
            Arg::new(ARG_EMAIL_TOKEN_TTL)
                .long(ARG_EMAIL_TOKEN_TTL)
                .help("Email verification token TTL in seconds")
                .env("PERMESI_EMAIL_TOKEN_TTL_SECONDS")
                .default_value("1800")
                .value_parser(clap::value_parser!(i64)),
        )
        .arg(
            Arg::new(ARG_EMAIL_RESEND_COOLDOWN)
                .long(ARG_EMAIL_RESEND_COOLDOWN)
                .help("Cooldown before resending verification emails")
                .env("PERMESI_EMAIL_RESEND_COOLDOWN_SECONDS")
                .default_value("60")
                .value_parser(clap::value_parser!(i64)),
        )
        .arg(
            Arg::new(ARG_SESSION_TTL)
                .long(ARG_SESSION_TTL)
                .help("Session cookie TTL in seconds")
                .env("PERMESI_SESSION_TTL_SECONDS")
                .default_value("604800")
                .value_parser(clap::value_parser!(i64)),
        )
}

fn with_auth_outbox_args(command: Command) -> Command {
    command
        .arg(
            Arg::new(ARG_EMAIL_OUTBOX_POLL)
                .long(ARG_EMAIL_OUTBOX_POLL)
                .help("Email outbox poll interval in seconds")
                .env("PERMESI_EMAIL_OUTBOX_POLL_SECONDS")
                .default_value("5")
                .value_parser(clap::value_parser!(u64)),
        )
        .arg(
            Arg::new(ARG_EMAIL_OUTBOX_BATCH)
                .long(ARG_EMAIL_OUTBOX_BATCH)
                .help("Email outbox batch size per poll")
                .env("PERMESI_EMAIL_OUTBOX_BATCH_SIZE")
                .default_value("10")
                .value_parser(clap::value_parser!(usize)),
        )
        .arg(
            Arg::new(ARG_EMAIL_OUTBOX_MAX_ATTEMPTS)
                .long(ARG_EMAIL_OUTBOX_MAX_ATTEMPTS)
                .help("Max attempts before marking an email as failed")
                .env("PERMESI_EMAIL_OUTBOX_MAX_ATTEMPTS")
                .default_value("5")
                .value_parser(clap::value_parser!(u32)),
        )
        .arg(
            Arg::new(ARG_EMAIL_OUTBOX_BACKOFF_BASE)
                .long(ARG_EMAIL_OUTBOX_BACKOFF_BASE)
                .help("Base delay for email outbox retry backoff")
                .env("PERMESI_EMAIL_OUTBOX_BACKOFF_BASE_SECONDS")
                .default_value("5")
                .value_parser(clap::value_parser!(u64)),
        )
        .arg(
            Arg::new(ARG_EMAIL_OUTBOX_BACKOFF_MAX)
                .long(ARG_EMAIL_OUTBOX_BACKOFF_MAX)
                .help("Max delay for email outbox retry backoff")
                .env("PERMESI_EMAIL_OUTBOX_BACKOFF_MAX_SECONDS")
                .default_value("300")
                .value_parser(clap::value_parser!(u64)),
        )
}

fn with_auth_opaque_args(command: Command) -> Command {
    command
        .arg(
            Arg::new(ARG_OPAQUE_SERVER_ID)
                .long(ARG_OPAQUE_SERVER_ID)
                .help("OPAQUE server identifier")
                .env("PERMESI_OPAQUE_SERVER_ID")
                .default_value("api.permesi.dev"),
        )
        .arg(
            Arg::new(ARG_OPAQUE_LOGIN_TTL)
                .long(ARG_OPAQUE_LOGIN_TTL)
                .help("TTL for OPAQUE login state storage")
                .env("PERMESI_OPAQUE_LOGIN_TTL_SECONDS")
                .default_value("300")
                .value_parser(clap::value_parser!(u64)),
        )
}

fn with_admin_args(command: Command) -> Command {
    command
        .arg(
            Arg::new(ARG_PLATFORM_ADMIN_TTL)
                .long(ARG_PLATFORM_ADMIN_TTL)
                .help("Admin elevation token TTL in seconds")
                .env("PLATFORM_ADMIN_TTL_SECONDS")
                .default_value("43200")
                .value_parser(clap::value_parser!(i64)),
        )
        .arg(
            Arg::new(ARG_PLATFORM_RECENT_AUTH)
                .long(ARG_PLATFORM_RECENT_AUTH)
                .help("Maximum session age for bootstrap in seconds")
                .env("PLATFORM_RECENT_AUTH_SECONDS")
                .default_value("3600")
                .value_parser(clap::value_parser!(i64)),
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Command;

    #[test]
    fn test_auth_args_presence() {
        let cmd = with_args(Command::new("test"));

        let expected_args = [
            ARG_FRONTEND_BASE_URL,
            ARG_EMAIL_TOKEN_TTL,
            ARG_EMAIL_RESEND_COOLDOWN,
            ARG_SESSION_TTL,
            ARG_EMAIL_OUTBOX_POLL,
            ARG_EMAIL_OUTBOX_BATCH,
            ARG_EMAIL_OUTBOX_MAX_ATTEMPTS,
            ARG_EMAIL_OUTBOX_BACKOFF_BASE,
            ARG_EMAIL_OUTBOX_BACKOFF_MAX,
            ARG_OPAQUE_SERVER_ID,
            ARG_OPAQUE_LOGIN_TTL,
            ARG_PLATFORM_ADMIN_TTL,
            ARG_PLATFORM_RECENT_AUTH,
        ];

        for arg in expected_args {
            assert!(
                cmd.get_arguments().any(|a| a.get_id() == arg),
                "Missing expected argument: {arg}"
            );
        }
    }
}
