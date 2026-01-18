mod admission;
mod auth;
mod logging;
mod tls;
mod vault;

use clap::{
    Arg, ColorChoice, Command,
    builder::styling::{AnsiColor, Effects, Styles},
};

/// Validate that TCP mode requirements are met if the URL implies TCP.
///
/// # Errors
/// Returns an error string if `vault-url` is HTTP(S) but auth arguments are missing.
pub fn validate(matches: &clap::ArgMatches) -> Result<(), String> {
    let Some(url) = matches.get_one::<String>("vault-url") else {
        return Ok(()); // Should be handled by required=true in clap
    };

    if url.starts_with("http://") || url.starts_with("https://") {
        if !matches.contains_id("vault-role-id") {
            return Err(
                "Missing required argument: --vault-role-id (required for TCP mode)".to_string(),
            );
        }
        if !matches.contains_id("vault-secret-id") && !matches.contains_id("vault-wrapped-token") {
            return Err("Missing required argument: --vault-secret-id or --vault-wrapped-token (required for TCP mode)".to_string());
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
