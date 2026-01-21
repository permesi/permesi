pub mod admission;
pub mod auth;
pub mod logging;
pub mod tls;
pub mod vault;

use clap::{
    Arg, ColorChoice, Command,
    builder::styling::{AnsiColor, Effects, Styles},
};

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

    let command = admission::with_args(command);
    let command = tls::with_args(command);
    let command = vault::with_args(command);
    let command = auth::with_args(command);
    logging::with_args(command)
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
}
