use clap::{
    Arg, ColorChoice, Command,
    builder::{
        ValueParser,
        styling::{AnsiColor, Effects, Styles},
    },
};

#[must_use]
pub fn validator_log_level() -> ValueParser {
    ValueParser::from(move |level: &str| -> std::result::Result<u8, String> {
        if let Ok(parsed) = level.parse::<u8>() {
            // Successfully parsed as a number
            if parsed <= 5 {
                return Ok(parsed);
            }
        }

        match level.to_lowercase().as_str() {
            "error" => Ok(0),
            "warn" => Ok(1),
            "info" => Ok(2),
            "debug" => Ok(3),
            "trace" => Ok(4),
            _ => Err("invalid log level".to_string()),
        }
    })
}

#[must_use]
pub fn new() -> Command {
    let styles = Styles::styled()
        .header(AnsiColor::Yellow.on_default() | Effects::BOLD)
        .usage(AnsiColor::Green.on_default() | Effects::BOLD)
        .literal(AnsiColor::Blue.on_default() | Effects::BOLD)
        .placeholder(AnsiColor::Green.on_default());

    let long_version: &'static str = Box::leak(
        format!("{} - {}", env!("CARGO_PKG_VERSION"), crate::GIT_COMMIT_HASH).into_boxed_str(),
    );

    let command = Command::new("permesi")
        .about("Identity and Access Management")
        .version(env!("CARGO_PKG_VERSION"))
        .long_version(long_version)
        .color(ColorChoice::Auto)
        .styles(styles)
        .arg(
            Arg::new("port")
                .short('p')
                .long("port")
                .help("Port to listen on")
                .default_value("8080")
                .env("PERMESI_PORT")
                .value_parser(clap::value_parser!(u16)),
        )
        .arg(
            Arg::new("dsn")
                .short('d')
                .long("dsn")
                .help("Database connection string")
                .long_help(
                    "Database connection string. Username/password are injected from Vault DB creds, so they are not required in the DSN.",
                )
                .env("PERMESI_DSN")
                .required(true),
        );

    let command = with_admission_args(command);
    let command = with_tls_args(command);
    let command = with_vault_args(command);
    let command = with_auth_args(command);
    with_logging_args(command)
}

fn with_admission_args(command: Command) -> Command {
    command
        .arg(
            Arg::new("admission-paserk-url")
                .long("admission-paserk-url")
                .help("PASERK keyset URL used to verify Admission Tokens")
                .long_help(
                    "PASERK keyset URL (typically genesis `/paserk.json`) used to verify Admission Tokens.\n\
The keyset is cached (TTL ~5 minutes) and refreshed on unknown `kid` with a cooldown. Verification\n\
itself is local and does not call genesis per request.",
                )
                .env("PERMESI_ADMISSION_PASERK_URL"),
        )
        .arg(
            Arg::new("admission-issuer")
                .long("admission-issuer")
                .help("Expected Admission Token issuer (iss)")
                .env("PERMESI_ADMISSION_ISS"),
        )
        .arg(
            Arg::new("admission-audience")
                .long("admission-audience")
                .help("Expected Admission Token audience (aud)")
                .env("PERMESI_ADMISSION_AUD"),
        )
}

fn with_tls_args(command: Command) -> Command {
    command
        .arg(
            Arg::new("tls-cert-path")
                .long("tls-cert-path")
                .help("Path to TLS certificate (PEM)")
                .env("PERMESI_TLS_CERT_PATH")
                .required(true),
        )
        .arg(
            Arg::new("tls-key-path")
                .long("tls-key-path")
                .help("Path to TLS private key (PEM)")
                .env("PERMESI_TLS_KEY_PATH")
                .required(true),
        )
        .arg(
            Arg::new("tls-ca-path")
                .long("tls-ca-path")
                .help("Path to TLS CA bundle (PEM)")
                .env("PERMESI_TLS_CA_PATH")
                .required(true),
        )
        .arg(
            Arg::new("admission-paserk-ca-path")
                .long("admission-paserk-ca-path")
                .help("Path to CA bundle for the PASERK URL (PEM)")
                .env("PERMESI_ADMISSION_PASERK_CA_PATH"),
        )
}

fn with_vault_args(command: Command) -> Command {
    command
        .arg(
            Arg::new("vault-url")
                .long("vault-url")
                .help("Vault approle login URL, example: https://vault.tld:8200/v1/auth/<approle>/login")
                .env("PERMESI_VAULT_URL")
                .required(true),
        )
        .arg(
            Arg::new("vault-role-id")
                .long("vault-role-id")
                .help("Vault role id")
                .env("PERMESI_VAULT_ROLE_ID")
                .required(true),
        )
        .arg(
            Arg::new("vault-secret-id")
                .long("vault-secret-id")
                .help("Vault secret id")
                .env("PERMESI_VAULT_SECRET_ID")
                .required_unless_present("vault-wrapped-token"),
        )
        .arg(
            Arg::new("vault-wrapped-token")
                .long("vault-wrapped-token")
                .help("Vault wrapped token")
                .env("PERMESI_VAULT_WRAPPED_TOKEN"),
        )
}

fn with_auth_args(command: Command) -> Command {
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

fn with_logging_args(command: Command) -> Command {
    command.arg(
        Arg::new("verbosity")
            .short('v')
            .long("verbose")
            .help("Verbosity level: ERROR, WARN, INFO, DEBUG, TRACE (default: ERROR)")
            .env("PERMESI_LOG_LEVEL")
            .global(true)
            .action(clap::ArgAction::Count)
            .value_parser(validator_log_level()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let command = new();

        assert_eq!(command.get_name(), "permesi");
        assert_eq!(
            command.get_about().map(ToString::to_string),
            Some("Identity and Access Management".to_string())
        );
        assert_eq!(
            command.get_version().map(ToString::to_string),
            Some(env!("CARGO_PKG_VERSION").to_string())
        );
    }

    #[test]
    fn test_check_port_and_dsn() {
        let command = new();
        let matches = command.get_matches_from(vec![
            "permesi",
            "--port",
            "8080",
            "--dsn",
            "postgres://user:password@localhost:5432/permesi",
            "--admission-paserk-url",
            "https://genesis.permesi.localhost:8000/paserk.json",
            "--tls-cert-path",
            "/tmp/permesi-cert.pem",
            "--tls-key-path",
            "/tmp/permesi-key.pem",
            "--tls-ca-path",
            "/tmp/permesi-ca.pem",
            "--vault-url",
            "https://vault.tld:8200",
            "--vault-role-id",
            "role-id",
            "--vault-secret-id",
            "secret-id",
        ]);

        assert_eq!(matches.get_one::<u16>("port").copied(), Some(8080));
        assert_eq!(
            matches.get_one::<String>("dsn").cloned(),
            Some("postgres://user:password@localhost:5432/permesi".to_string())
        );
        assert_eq!(
            matches.get_one::<String>("vault-url").cloned(),
            Some("https://vault.tld:8200".to_string())
        );
        assert_eq!(
            matches.get_one::<String>("vault-role-id").cloned(),
            Some("role-id".to_string())
        );
        assert_eq!(
            matches.get_one::<String>("vault-secret-id").cloned(),
            Some("secret-id".to_string())
        );
    }

    #[test]
    fn test_check_env() {
        temp_env::with_vars(
            [
                (
                    "PERMESI_ADMISSION_PASERK_URL",
                    Some("https://genesis.permesi.localhost:8000/paserk.json"),
                ),
                ("PERMESI_TLS_CERT_PATH", Some("/tmp/permesi-cert.pem")),
                ("PERMESI_TLS_KEY_PATH", Some("/tmp/permesi-key.pem")),
                ("PERMESI_TLS_CA_PATH", Some("/tmp/permesi-ca.pem")),
                ("PERMESI_VAULT_URL", Some("https://vault.tld:8200")),
                ("PERMESI_VAULT_ROLE_ID", Some("role_id")),
                ("PERMESI_VAULT_SECRET_ID", Some("secret_id")),
                ("PERMESI_PORT", Some("443")),
                (
                    "PERMESI_DSN",
                    Some("postgres://user:password@localhost:5432/permesi"),
                ),
                ("PERMESI_LOG_LEVEL", Some("info")),
            ],
            || {
                let command = new();
                let matches = command.get_matches_from(vec!["permesi"]);
                assert_eq!(matches.get_one::<u16>("port").copied(), Some(443));
                assert_eq!(
                    matches.get_one::<String>("dsn").cloned(),
                    Some("postgres://user:password@localhost:5432/permesi".to_string())
                );
                assert_eq!(
                    matches.get_one::<String>("vault-url").cloned(),
                    Some("https://vault.tld:8200".to_string())
                );
                assert_eq!(matches.get_one::<u8>("verbosity").copied(), Some(2));
            },
        );
    }

    #[test]
    fn test_check_log_level_env() {
        // loop cover all possible value_parse
        let levels = ["error", "warn", "info", "debug", "trace"];
        for (index, &level) in levels.iter().enumerate() {
            temp_env::with_vars(
                [
                    ("PERMESI_LOG_LEVEL", Some(level)),
                    (
                        "PERMESI_ADMISSION_PASERK_URL",
                        Some("https://genesis.permesi.localhost:8000/paserk.json"),
                    ),
                    ("PERMESI_TLS_CERT_PATH", Some("/tmp/permesi-cert.pem")),
                    ("PERMESI_TLS_KEY_PATH", Some("/tmp/permesi-key.pem")),
                    ("PERMESI_TLS_CA_PATH", Some("/tmp/permesi-ca.pem")),
                    ("PERMESI_VAULT_URL", Some("http://vault.tld:8200")),
                    ("PERMESI_VAULT_ROLE_ID", Some("role_id")),
                    ("PERMESI_VAULT_SECRET_ID", Some("secret_id")),
                    (
                        "PERMESI_DSN",
                        Some("postgres://user:password@localhost:5432/permesi"),
                    ),
                ],
                || {
                    let command = new();
                    let matches = command.get_matches_from(vec!["permesi"]);
                    assert_eq!(
                        matches.get_one::<u8>("verbosity").copied(),
                        u8::try_from(index).ok()
                    );
                },
            );
        }
    }

    #[test]
    fn test_check_log_level_verbosity() {
        // loop cover all possible value_parse
        let levels = ["error", "warn", "info", "debug", "trace"];
        for (index, _) in levels.iter().enumerate() {
            temp_env::with_vars([("PERMESI_LOG_LEVEL", None::<String>)], || {
                let mut args = vec![
                    "permesi".to_string(),
                    "--dsn".to_string(),
                    "postgres://user:password@localhost:5432/permesi".to_string(),
                    "--admission-paserk-url".to_string(),
                    "https://genesis.permesi.localhost:8000/paserk.json".to_string(),
                    "--tls-cert-path".to_string(),
                    "/tmp/permesi-cert.pem".to_string(),
                    "--tls-key-path".to_string(),
                    "/tmp/permesi-key.pem".to_string(),
                    "--tls-ca-path".to_string(),
                    "/tmp/permesi-ca.pem".to_string(),
                    "--vault-url".to_string(),
                    "https://vault.tld:8200".to_string(),
                    "--vault-role-id".to_string(),
                    "role_id".to_string(),
                    "--vault-secret-id".to_string(),
                    "secret_id".to_string(),
                ];

                // Add the appropriate number of "-v" flags based on the index
                if index > 0 {
                    let v = format!("-{}", "v".repeat(index));
                    args.push(v);
                }

                let command = new();

                let matches = command.get_matches_from(args);

                assert_eq!(
                    matches.get_one::<u8>("verbosity").copied(),
                    u8::try_from(index).ok()
                );
            });
        }
    }
}
