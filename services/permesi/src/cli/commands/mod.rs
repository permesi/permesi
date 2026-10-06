pub mod admission;
pub mod auth;
pub mod database;
pub mod logging;
pub mod tls;
pub mod vault;

/// Default per-lock/per-statement deadline for shared OPAQUE exchange transactions.
pub(crate) const DEFAULT_OPAQUE_EXCHANGE_TIMEOUT_MS: i64 = 1000;

/// Default fair-share ceiling for each keyed subject in a pending authentication purpose.
pub const DEFAULT_AUTH_SUBJECT_LIMIT: i64 = 16;
pub const DEFAULT_AUTH_LOGIN_LIMIT: i64 = 10000;
pub const DEFAULT_AUTH_REAUTH_LIMIT: i64 = 1000;
pub const DEFAULT_AUTH_REGISTRATION_LIMIT: i64 = 1000;
pub const DEFAULT_AUTH_MFA_LIMIT: i64 = 1000;

/// Defines every authentication admission/trusted-edge runtime option in clap.
pub(crate) fn with_operations_args(mut command: clap::Command) -> clap::Command {
    for (name, env, default) in [
        (
            "auth-pending-subject-limit",
            "PERMESI_AUTH_PENDING_SUBJECT_LIMIT",
            "16",
        ),
        (
            "auth-pending-login-limit",
            "PERMESI_AUTH_PENDING_LOGIN_LIMIT",
            "10000",
        ),
        (
            "auth-pending-reauth-limit",
            "PERMESI_AUTH_PENDING_REAUTH_LIMIT",
            "1000",
        ),
        (
            "auth-pending-registration-limit",
            "PERMESI_AUTH_PENDING_REGISTRATION_LIMIT",
            "1000",
        ),
        (
            "auth-pending-mfa-limit",
            "PERMESI_AUTH_PENDING_MFA_LIMIT",
            "1000",
        ),
    ] {
        command = command.arg(
            clap::Arg::new(name)
                .long(name)
                .env(env)
                .default_value(default)
                .value_parser(clap::value_parser!(i64).range(1..=1_000_000)),
        );
    }
    command
        .arg(
            clap::Arg::new("auth-trusted-proxy")
                .long("auth-trusted-proxy")
                .env("PERMESI_AUTH_TRUSTED_PROXIES")
                .value_delimiter(',')
                .action(clap::ArgAction::Append)
                .value_parser(clap::value_parser!(sqlx::types::ipnetwork::IpNetwork))
                .help("Explicit trusted proxy CIDRs; edge must overwrite X-Real-IP"),
        )
        .arg(
            clap::Arg::new("auth-trust-unix-proxy")
                .long("auth-trust-unix-proxy")
                .env("PERMESI_AUTH_TRUST_UNIX_PROXY")
                .action(clap::ArgAction::SetTrue)
                .help("Trust X-Real-IP from the restricted same-host Unix proxy"),
        )
}

pub(crate) fn with_webauthn_args(command: clap::Command) -> clap::Command {
    use clap::{Arg, ArgAction};
    command
        .arg(
            Arg::new("passkeys-rp-id")
                .long("passkeys-rp-id")
                .env("PERMESI_PASSKEYS_RP_ID"),
        )
        .arg(
            Arg::new("passkeys-rp-name")
                .long("passkeys-rp-name")
                .env("PERMESI_PASSKEYS_RP_NAME")
                .default_value("Permesi"),
        )
        .arg(
            Arg::new("passkeys-allowed-origins")
                .long("passkeys-allowed-origins")
                .env("PERMESI_PASSKEYS_ALLOWED_ORIGINS"),
        )
        .arg(
            Arg::new("passkeys-challenge-ttl-seconds")
                .long("passkeys-challenge-ttl-seconds")
                .env("PERMESI_PASSKEYS_CHALLENGE_TTL_SECONDS")
                .default_value("300")
                .value_parser(clap::value_parser!(u64).range(1..=3600)),
        )
        .arg(
            Arg::new("passkeys-preview-mode")
                .long("passkeys-preview-mode")
                .env("PERMESI_PASSKEYS_PREVIEW_MODE")
                .default_value("false")
                .action(ArgAction::Set)
                .value_parser(clap::value_parser!(bool)),
        )
}

use clap::{
    Arg, ColorChoice, Command,
    builder::styling::{AnsiColor, Effects, Styles},
};

#[cfg(test)]
use self::vault::{ARG_VAULT_KV_MOUNT, ARG_VAULT_KV_PATH, ARG_VAULT_TRANSIT_MOUNT};
use self::vault::{ARG_VAULT_ROLE_ID, ARG_VAULT_SECRET_ID, ARG_VAULT_URL, ARG_VAULT_WRAPPED_TOKEN};

/// Validate that TCP mode requirements are met if the URL implies TCP.
///
/// # Errors
/// Returns an error string if `vault-url` is HTTP(S) but auth arguments are missing.
pub fn validate(matches: &clap::ArgMatches) -> Result<(), String> {
    let Some(url) = matches.get_one::<String>(ARG_VAULT_URL) else {
        return Ok(()); // Should be handled by required=true in clap
    };

    if url.starts_with("http://") || url.starts_with("https://") {
        if !matches.contains_id(ARG_VAULT_ROLE_ID) {
            return Err(format!(
                "Missing required argument: --{ARG_VAULT_ROLE_ID} (required for TCP mode)"
            ));
        }
        if !matches.contains_id(ARG_VAULT_SECRET_ID)
            && !matches.contains_id(ARG_VAULT_WRAPPED_TOKEN)
        {
            return Err(format!(
                "Missing required argument: --{ARG_VAULT_SECRET_ID} or --{ARG_VAULT_WRAPPED_TOKEN} (required for TCP mode)"
            ));
        }
    }
    Ok(())
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
            Arg::new("socket-path")
                .long("socket-path")
                .help("Bind to Unix domain socket instead of TCP port")
                .env("PERMESI_SOCKET_PATH")
                .conflicts_with_all(["port", tls::ARG_TLS_PEM_BUNDLE]),
        )
        .arg(
            Arg::new("port")
                .short('p')
                .long("port")
                .help("Port to listen on (prefers [::], falls back to 0.0.0.0)")
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

    let command = oauth_args(command);
    let command = admission::with_args(command);
    let command = tls::with_args(command);
    let command = vault::with_args(command);
    let command = auth::with_args(command);
    let command = database::with_args(command);
    logging::with_args(command)
}

/// Defines opt-in OAuth runtime policy; dispatch independently validates every value.
fn oauth_args(command: Command) -> Command {
    command
        .arg(Arg::new("oidc-issuer").long("oidc-issuer").env("PERMESI_OIDC_ISSUER")
            .requires("oauth-audience").value_parser(crate::oauth::config::parse_issuer)
            .help("Explicit HTTPS issuer origin; enables OAuth authorization and OIDC metadata"))
        .arg(Arg::new("oauth-audience").long("oauth-audience").env("PERMESI_OAUTH_AUDIENCE")
            .requires("oidc-issuer").value_parser(crate::oauth::config::parse_audience)
            .help("Explicit delegated access-token resource audience; ID token audience is the client"))
        .arg(Arg::new("oidc-signing-key").long("oidc-signing-key").env("PERMESI_OIDC_SIGNING_KEY")
            .default_value("oidc-signing").value_parser(crate::oauth::config::parse_key_name)
            .help("Vault transit RSA-2048 key; rotation and retirement are operator-managed"))
        .arg(Arg::new("oauth-code-ttl-seconds").long("oauth-code-ttl-seconds")
            .env("PERMESI_OAUTH_CODE_TTL_SECONDS").default_value("120")
            .value_parser(clap::value_parser!(i64).range(1..=300)))
        .arg(Arg::new("oauth-access-token-ttl-seconds").long("oauth-access-token-ttl-seconds")
            .env("PERMESI_OAUTH_ACCESS_TOKEN_TTL_SECONDS").default_value("300")
            .value_parser(clap::value_parser!(i64).range(1..=3600)))
        .arg(Arg::new("oauth-token-rate-window-seconds").long("oauth-token-rate-window-seconds")
            .env("PERMESI_OAUTH_TOKEN_RATE_WINDOW_SECONDS").default_value("60")
            .value_parser(clap::value_parser!(i64).range(1..=3600)).help("Shared token rate window (1-3600 seconds)"))
        .arg(Arg::new("oauth-token-rate-ip-attempts").long("oauth-token-rate-ip-attempts")
            .env("PERMESI_OAUTH_TOKEN_RATE_IP_ATTEMPTS").default_value("120")
            .value_parser(clap::value_parser!(i64).range(1..=100_000)).help("Token requests per IP per shared window"))
        .arg(Arg::new("oauth-token-rate-client-ip-attempts").long("oauth-token-rate-client-ip-attempts")
            .env("PERMESI_OAUTH_TOKEN_RATE_CLIENT_IP_ATTEMPTS").default_value("30")
            .value_parser(clap::value_parser!(i64).range(1..=100_000)).help("Token requests per client/IP pair per shared window"))
        .arg(Arg::new("oidc-id-token-ttl-seconds").long("oidc-id-token-ttl-seconds")
            .env("PERMESI_OIDC_ID_TOKEN_TTL_SECONDS").default_value("300")
            .value_parser(clap::value_parser!(i64).range(1..=3600)))
        .arg(Arg::new("oauth-token-timeout-ms").long("oauth-token-timeout-ms")
            .env("PERMESI_OAUTH_TOKEN_TIMEOUT_MS").default_value("5000")
            .value_parser(clap::value_parser!(u64).range(1..=30000)))
        .arg(Arg::new("oauth-token-max-body-bytes").long("oauth-token-max-body-bytes")
            .env("PERMESI_OAUTH_TOKEN_MAX_BODY_BYTES").default_value("8192")
            .value_parser(clap::value_parser!(u32).range(1024..=65536)))
        .arg(Arg::new("oauth-request-ttl-seconds").long("oauth-request-ttl-seconds")
            .env("PERMESI_OAUTH_REQUEST_TTL_SECONDS").default_value("600")
            .value_parser(clap::value_parser!(i64).range(1..=1800)))
        .arg(Arg::new("oauth-lock-timeout-ms").long("oauth-lock-timeout-ms")
            .env("PERMESI_OAUTH_LOCK_TIMEOUT_MS").default_value("1000")
            .value_parser(clap::value_parser!(i64).range(1..=10_000)))
        .arg(Arg::new("oauth-client-secret-grace-seconds").long("oauth-client-secret-grace-seconds")
            .env("PERMESI_OAUTH_CLIENT_SECRET_GRACE_SECONDS").default_value("900")
            .value_parser(clap::value_parser!(i64).range(1..=3600)))
        .arg(Arg::new("oauth-client-secret-memory-kib").long("oauth-client-secret-memory-kib")
            .env("PERMESI_OAUTH_CLIENT_SECRET_MEMORY_KIB").default_value("19456")
            .value_parser(clap::value_parser!(u32).range(19456..=65536)))
        .arg(Arg::new("oauth-client-secret-iterations").long("oauth-client-secret-iterations")
            .env("PERMESI_OAUTH_CLIENT_SECRET_ITERATIONS").default_value("2")
            .value_parser(clap::value_parser!(u32).range(2..=6)))
        .arg(Arg::new("oauth-client-secret-parallelism").long("oauth-client-secret-parallelism")
            .env("PERMESI_OAUTH_CLIENT_SECRET_PARALLELISM").default_value("1")
            .value_parser(clap::value_parser!(u32).range(1..=4)))
        .arg(Arg::new("oauth-client-secret-hash-workers").long("oauth-client-secret-hash-workers")
            .env("PERMESI_OAUTH_CLIENT_SECRET_HASH_WORKERS").default_value("2")
            .value_parser(clap::value_parser!(u32).range(1..=8)))
        .arg(Arg::new("oidc-jwks-cache-ttl-seconds").long("oidc-jwks-cache-ttl-seconds")
            .env("PERMESI_OIDC_JWKS_CACHE_TTL_SECONDS").default_value("30")
            .value_parser(clap::value_parser!(i64).range(1..=300)))
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
            "--tls-pem-bundle",
            "/tmp/permesi-bundle.pem",
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
            matches.get_one::<String>(ARG_VAULT_URL).cloned(),
            Some("https://vault.tld:8200".to_string())
        );
        assert_eq!(
            matches.get_one::<String>(ARG_VAULT_ROLE_ID).cloned(),
            Some("role-id".to_string())
        );
        assert_eq!(
            matches.get_one::<String>(ARG_VAULT_SECRET_ID).cloned(),
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
                ("PERMESI_TLS_PEM_BUNDLE", Some("/tmp/permesi-bundle.pem")),
                ("PERMESI_VAULT_URL", Some("https://vault.tld:8200")),
                ("PERMESI_VAULT_ROLE_ID", Some("role_id")),
                ("PERMESI_VAULT_SECRET_ID", Some("secret_id")),
                ("PERMESI_PORT", Some("443")),
                (
                    "PERMESI_DSN",
                    Some("postgres://user:password@localhost:5432/permesi"),
                ),
                ("PERMESI_LOG_LEVEL", Some("info")),
                ("PERMESI_VAULT_KV_MOUNT", Some("secret/custom")),
                ("PERMESI_VAULT_KV_PATH", Some("config/custom")),
                ("PERMESI_VAULT_TRANSIT_MOUNT", Some("transit/custom")),
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
                    matches.get_one::<String>(ARG_VAULT_URL).cloned(),
                    Some("https://vault.tld:8200".to_string())
                );
                assert_eq!(
                    matches.get_one::<u8>(logging::ARG_VERBOSITY).copied(),
                    Some(2)
                );
                assert_eq!(
                    matches
                        .get_one::<String>(ARG_VAULT_KV_MOUNT)
                        .map(String::as_str),
                    Some("secret/custom")
                );
                assert_eq!(
                    matches
                        .get_one::<String>(ARG_VAULT_KV_PATH)
                        .map(String::as_str),
                    Some("config/custom")
                );
                assert_eq!(
                    matches
                        .get_one::<String>(ARG_VAULT_TRANSIT_MOUNT)
                        .map(String::as_str),
                    Some("transit/custom")
                );
            },
        );
    }

    #[test]
    fn test_vault_mount_defaults() {
        temp_env::with_vars(
            [
                ("PERMESI_VAULT_KV_MOUNT", None::<&str>),
                ("PERMESI_VAULT_KV_PATH", None::<&str>),
                ("PERMESI_VAULT_TRANSIT_MOUNT", None::<&str>),
            ],
            || {
                let command = new();
                let matches = command.get_matches_from(vec![
                    "permesi",
                    "--dsn",
                    "postgres://user:password@localhost:5432/permesi",
                    "--admission-paserk-url",
                    "https://genesis.permesi.localhost:8000/paserk.json",
                    "--tls-pem-bundle",
                    "/tmp/permesi-bundle.pem",
                    "--vault-url",
                    "https://vault.tld:8200",
                    "--vault-role-id",
                    "role-id",
                    "--vault-secret-id",
                    "secret-id",
                ]);

                assert_eq!(
                    matches
                        .get_one::<String>(ARG_VAULT_KV_MOUNT)
                        .map(String::as_str),
                    Some("secret/permesi")
                );
                assert_eq!(
                    matches
                        .get_one::<String>(ARG_VAULT_KV_PATH)
                        .map(String::as_str),
                    Some("config")
                );
                assert_eq!(
                    matches
                        .get_one::<String>(ARG_VAULT_TRANSIT_MOUNT)
                        .map(String::as_str),
                    Some("transit/permesi")
                );
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
                    ("PERMESI_TLS_PEM_BUNDLE", Some("/tmp/permesi-bundle.pem")),
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
                        matches.get_one::<u8>(logging::ARG_VERBOSITY).copied(),
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
                    "--tls-pem-bundle".to_string(),
                    "/tmp/permesi-bundle.pem".to_string(),
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
                    matches.get_one::<u8>(logging::ARG_VERBOSITY).copied(),
                    u8::try_from(index).ok()
                );
            });
        }
    }

    #[test]
    fn test_removed_args_fail() {
        let command = new();
        // vault-addr should be rejected
        let result = command.clone().try_get_matches_from(vec![
            "permesi",
            "--dsn",
            "postgres://localhost",
            "--vault-addr",
            "http://addr",
        ]);
        assert_eq!(
            result.map_err(|e| e.kind()),
            Err(clap::error::ErrorKind::UnknownArgument)
        );

        // vault-policy should be rejected
        let result = command.try_get_matches_from(vec![
            "permesi",
            "--dsn",
            "postgres://localhost",
            "--vault-policy",
            "policy",
        ]);
        assert_eq!(
            result.map_err(|e| e.kind()),
            Err(clap::error::ErrorKind::UnknownArgument)
        );
    }

    // Helper to clear env vars for TCP validation tests
    fn with_cleared_vault_env<F, R>(f: F) -> R
    where
        F: FnOnce() -> R,
    {
        temp_env::with_vars(
            [
                ("PERMESI_VAULT_ROLE_ID", None::<&str>),
                ("PERMESI_VAULT_SECRET_ID", None::<&str>),
                ("PERMESI_VAULT_WRAPPED_TOKEN", None::<&str>),
            ],
            f,
        )
    }

    #[test]
    fn test_validate_tcp_missing_role() -> Result<(), Box<dyn std::error::Error>> {
        with_cleared_vault_env(|| {
            let command = new();
            // 1. TCP mode (http) missing role-id
            let matches = command.try_get_matches_from(vec![
                "permesi",
                "--dsn",
                "postgres://",
                "--admission-paserk-url",
                "https://url",
                "--tls-pem-bundle",
                "bundle",
                "--vault-url",
                "http://vault:8200",
            ])?;
            assert!(validate(&matches).is_err(), "Should fail missing role-id");
            Ok(())
        })
    }

    #[test]
    fn test_validate_tcp_missing_secret() -> Result<(), Box<dyn std::error::Error>> {
        with_cleared_vault_env(|| {
            let command = new();
            // 2. TCP mode (https) missing secret-id/wrapped-token
            let matches = command.try_get_matches_from(vec![
                "permesi",
                "--dsn",
                "postgres://",
                "--admission-paserk-url",
                "https://url",
                "--tls-pem-bundle",
                "bundle",
                "--vault-url",
                "https://vault:8200",
                "--vault-role-id",
                "role",
            ])?;
            assert!(
                validate(&matches).is_err(),
                "Should fail missing secret-id/wrapped-token"
            );
            Ok(())
        })
    }

    #[test]
    fn test_validate_tcp_valid() -> Result<(), Box<dyn std::error::Error>> {
        with_cleared_vault_env(|| {
            let command = new();
            // 3. TCP mode (http) valid
            let matches = command.try_get_matches_from(vec![
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
            ])?;
            assert!(
                validate(&matches).is_ok(),
                "Should pass with valid TCP args"
            );
            Ok(())
        })
    }

    #[test]
    fn test_validate_agent_unix() -> Result<(), Box<dyn std::error::Error>> {
        with_cleared_vault_env(|| {
            let command = new();
            // 4. Agent mode (unix socket) valid without auth
            let matches = command.try_get_matches_from(vec![
                "permesi",
                "--dsn",
                "postgres://",
                "--admission-paserk-url",
                "https://url",
                "--tls-pem-bundle",
                "bundle",
                "--vault-url",
                "unix:///tmp/agent.sock",
            ])?;
            assert!(validate(&matches).is_ok(), "Should pass with unix socket");
            Ok(())
        })
    }

    #[test]
    fn test_validate_agent_path() -> Result<(), Box<dyn std::error::Error>> {
        with_cleared_vault_env(|| {
            let command = new();
            // 5. Agent mode (path) valid without auth
            let matches = command.try_get_matches_from(vec![
                "permesi",
                "--dsn",
                "postgres://",
                "--admission-paserk-url",
                "https://url",
                "--tls-pem-bundle",
                "bundle",
                "--vault-url",
                "/tmp/agent.sock",
            ])?;
            assert!(validate(&matches).is_ok(), "Should pass with socket path");
            Ok(())
        })
    }

    #[test]
    fn test_socket_conflicts() {
        let command = new();

        // Conflict: socket-path AND port
        let result = command.clone().try_get_matches_from(vec![
            "permesi",
            "--dsn",
            "postgres://",
            "--socket-path",
            "/tmp/permesi.sock",
            "--port",
            "9090",
        ]);
        assert_eq!(
            result.map_err(|e| e.kind()),
            Err(clap::error::ErrorKind::ArgumentConflict)
        );

        // Conflict: socket-path AND tls-pem-bundle
        let result = command.try_get_matches_from(vec![
            "permesi",
            "--dsn",
            "postgres://",
            "--socket-path",
            "/tmp/permesi.sock",
            "--tls-pem-bundle",
            "/tmp/bundle.pem",
        ]);
        assert_eq!(
            result.map_err(|e| e.kind()),
            Err(clap::error::ErrorKind::ArgumentConflict)
        );
    }

    #[test]
    fn webauthn_cli_rejects_invalid_ttl_and_preview_policy() {
        for (flag, value) in [
            ("--passkeys-challenge-ttl-seconds", "0"),
            ("--passkeys-challenge-ttl-seconds", "3601"),
            ("--passkeys-preview-mode", "yes"),
        ] {
            assert!(
                super::with_webauthn_args(Command::new("test"))
                    .try_get_matches_from(["test", flag, value])
                    .is_err()
            );
        }
    }

    #[test]
    fn webauthn_cli_preserves_explicit_rp_origin_and_policy()
    -> Result<(), Box<dyn std::error::Error>> {
        let matches = super::with_webauthn_args(Command::new("test")).try_get_matches_from([
            "test",
            "--passkeys-rp-id",
            "example.com",
            "--passkeys-rp-name",
            "Example",
            "--passkeys-allowed-origins",
            "https://example.com:8443",
            "--passkeys-challenge-ttl-seconds",
            "60",
            "--passkeys-preview-mode",
            "false",
        ])?;
        assert_eq!(
            matches
                .get_one::<String>("passkeys-rp-id")
                .map(String::as_str),
            Some("example.com")
        );
        assert_eq!(
            matches
                .get_one::<String>("passkeys-allowed-origins")
                .map(String::as_str),
            Some("https://example.com:8443")
        );
        assert_eq!(
            matches.get_one::<u64>("passkeys-challenge-ttl-seconds"),
            Some(&60)
        );
        assert_eq!(
            matches.get_one::<bool>("passkeys-preview-mode"),
            Some(&false)
        );
        Ok(())
    }
}
