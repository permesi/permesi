use clap::{Arg, ArgMatches, Command};

pub const ARG_FRONTEND_BASE_URL: &str = "frontend-base-url";
pub const ARG_CORS_ALLOWED_ORIGINS: &str = "cors-allowed-origins";
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
pub const ARG_OPAQUE_EXCHANGE_TIMEOUT: &str = "opaque-exchange-timeout-ms";
pub const ARG_AUTH_MAX_PENDING_STATES: &str = "auth-max-pending-states";

pub const ARG_AUTH_RATE_LIMIT_WINDOW: &str = "auth-rate-limit-window-seconds";
pub const ARG_AUTH_RATE_LIMIT_IP_ATTEMPTS: &str = "auth-rate-limit-ip-attempts";
pub const ARG_AUTH_RATE_LIMIT_ACCOUNT_ATTEMPTS: &str = "auth-rate-limit-account-attempts";

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
    pub exchange_timeout_ms: i64,
}

#[derive(Debug, Clone)]
pub struct RateLimitOptions {
    pub window_seconds: i64,
    pub ip_attempts: i64,
    pub account_attempts: i64,
}

#[derive(Debug, Clone)]
pub struct AdminOptions {
    pub ttl_seconds: i64,
    pub recent_auth_seconds: i64,
}

#[derive(Debug, Clone)]
pub struct Options {
    pub frontend_base_url: String,
    pub cors_allowed_origins: Vec<String>,
    pub email_token_ttl_seconds: i64,
    pub email_resend_cooldown_seconds: i64,
    pub session_ttl_seconds: i64,
    pub email_outbox: EmailOutboxOptions,
    pub opaque: OpaqueOptions,
    pub max_pending_states: u64,
    pub rate_limit: RateLimitOptions,
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

        let cors_allowed_origins: Vec<String> = matches
            .get_one::<String>(ARG_CORS_ALLOWED_ORIGINS)
            .map(|s| {
                s.split(',')
                    .map(|o| o.trim().to_string())
                    .filter(|o| !o.is_empty())
                    .collect()
            })
            .unwrap_or_default();

        Ok(Self {
            frontend_base_url,
            cors_allowed_origins,
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
                exchange_timeout_ms: matches
                    .get_one::<i64>(ARG_OPAQUE_EXCHANGE_TIMEOUT)
                    .copied()
                    .ok_or_else(|| anyhow::anyhow!("missing required OPAQUE exchange timeout"))?,
            },
            max_pending_states: matches
                .get_one::<u64>(ARG_AUTH_MAX_PENDING_STATES)
                .copied()
                .unwrap_or(10_000),
            rate_limit: RateLimitOptions {
                window_seconds: matches
                    .get_one::<i64>(ARG_AUTH_RATE_LIMIT_WINDOW)
                    .copied()
                    .unwrap_or(600),
                ip_attempts: matches
                    .get_one::<i64>(ARG_AUTH_RATE_LIMIT_IP_ATTEMPTS)
                    .copied()
                    .unwrap_or(100),
                account_attempts: matches
                    .get_one::<i64>(ARG_AUTH_RATE_LIMIT_ACCOUNT_ATTEMPTS)
                    .copied()
                    .unwrap_or(10),
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
    let command = super::with_operations_args(command);
    let command = super::with_webauthn_args(command);
    let command = with_auth_email_args(command);
    let command = with_auth_outbox_args(command);
    let command = with_auth_opaque_args(command);
    let command = with_auth_rate_limit_args(command);
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
            Arg::new(ARG_CORS_ALLOWED_ORIGINS)
                .long(ARG_CORS_ALLOWED_ORIGINS)
                .help("Comma-separated list of additional CORS allowed origins (frontend-base-url is always included)")
                .env("PERMESI_CORS_ALLOWED_ORIGINS"),
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
                .help("TTL for shared OPAQUE exchange storage (1-3600 seconds)")
                .env("PERMESI_OPAQUE_LOGIN_TTL_SECONDS")
                .default_value("300")
                .value_parser(clap::value_parser!(u64).range(1..=3600)),
        )
        .arg(
            Arg::new(ARG_AUTH_MAX_PENDING_STATES)
                .long(ARG_AUTH_MAX_PENDING_STATES)
                .help("Additional per-purpose cluster-wide ceiling for pending OPAQUE and WebAuthn exchanges")
                .env("PERMESI_AUTH_MAX_PENDING_STATES")
                .default_value("10000")
                .value_parser(clap::value_parser!(u64).range(1..)),
        )
        .arg(
            Arg::new(ARG_OPAQUE_EXCHANGE_TIMEOUT)
                .long(ARG_OPAQUE_EXCHANGE_TIMEOUT)
                .help("Per-lock and per-statement OPAQUE exchange deadline (1-10000 milliseconds)")
                .env("PERMESI_OPAQUE_EXCHANGE_TIMEOUT_MS")
                .default_value("1000")
                .value_parser(clap::value_parser!(i64).range(1..=10000)),
        )
}

fn with_auth_rate_limit_args(command: Command) -> Command {
    command
        .arg(
            Arg::new(ARG_AUTH_RATE_LIMIT_WINDOW)
                .long(ARG_AUTH_RATE_LIMIT_WINDOW)
                .help("Authentication rate-limit fixed-window duration in seconds")
                .env("PERMESI_AUTH_RATE_LIMIT_WINDOW_SECONDS")
                .default_value("600")
                .value_parser(clap::value_parser!(i64).range(1..)),
        )
        .arg(
            Arg::new(ARG_AUTH_RATE_LIMIT_IP_ATTEMPTS)
                .long(ARG_AUTH_RATE_LIMIT_IP_ATTEMPTS)
                .help("Maximum authentication attempts per IP and action per window")
                .env("PERMESI_AUTH_RATE_LIMIT_IP_ATTEMPTS")
                .default_value("100")
                .value_parser(clap::value_parser!(i64).range(1..)),
        )
        .arg(
            Arg::new(ARG_AUTH_RATE_LIMIT_ACCOUNT_ATTEMPTS)
                .long(ARG_AUTH_RATE_LIMIT_ACCOUNT_ATTEMPTS)
                .help("Maximum authentication attempts per account and action per window")
                .env("PERMESI_AUTH_RATE_LIMIT_ACCOUNT_ATTEMPTS")
                .default_value("10")
                .value_parser(clap::value_parser!(i64).range(1..)),
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
    /// Lock/statement waits have positive bounded defaults and cannot be disabled by configuration.
    #[test]
    fn opaque_exchange_deadline_parser_enforces_bounds_and_default() -> anyhow::Result<()> {
        temp_env::with_var(
            "PERMESI_OPAQUE_EXCHANGE_TIMEOUT_MS",
            None::<&str>,
            || -> anyhow::Result<()> {
                for value in ["-1", "0", "10001", "9223372036854775807"] {
                    assert!(
                        super::with_args(clap::Command::new("test"))
                            .try_get_matches_from(["test", "--opaque-exchange-timeout-ms", value])
                            .is_err()
                    );
                }
                for value in ["1", "1000", "10000"] {
                    assert!(
                        super::with_args(clap::Command::new("test"))
                            .try_get_matches_from(["test", "--opaque-exchange-timeout-ms", value])
                            .is_ok()
                    );
                }
                let defaults =
                    super::with_args(clap::Command::new("test")).try_get_matches_from(["test"])?;
                assert_eq!(
                    defaults
                        .get_one::<i64>(super::ARG_OPAQUE_EXCHANGE_TIMEOUT)
                        .copied(),
                    Some(crate::cli::commands::DEFAULT_OPAQUE_EXCHANGE_TIMEOUT_MS)
                );
                Ok(())
            },
        )
    }

    /// Invalid lifetimes fail before startup; one-second and one-hour boundaries are supported.
    #[test]
    fn opaque_exchange_ttl_parser_enforces_short_positive_lifetime() {
        for value in ["0", "3601", "18446744073709551615"] {
            assert!(
                super::with_args(clap::Command::new("test"))
                    .try_get_matches_from(["test", "--opaque-login-ttl-seconds", value])
                    .is_err()
            );
        }
        for value in ["1", "300", "3600"] {
            assert!(
                super::with_args(clap::Command::new("test"))
                    .try_get_matches_from(["test", "--opaque-login-ttl-seconds", value])
                    .is_ok()
            );
        }
    }
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
            ARG_OPAQUE_EXCHANGE_TIMEOUT,
            ARG_AUTH_MAX_PENDING_STATES,
            ARG_AUTH_RATE_LIMIT_WINDOW,
            ARG_AUTH_RATE_LIMIT_IP_ATTEMPTS,
            ARG_AUTH_RATE_LIMIT_ACCOUNT_ATTEMPTS,
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
