pub mod database;
pub mod http;
mod logging;
mod openbao;
mod tls;

use clap::{
    Arg, ColorChoice, Command,
    builder::styling::{AnsiColor, Effects, Styles},
};

/// Validate auth-mode requirements without attempting login or falling back.
///
/// # Errors
/// Rejects incompatible transport/credential settings and missing mode requirements.
pub fn validate(matches: &clap::ArgMatches) -> Result<(), String> {
    crate::cli::dispatch::openbao_auth(matches)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Define opt-in native login settings; auto preserves the existing auth selection.
fn with_native_openbao_args(command: Command) -> Command {
    command
        .arg(Arg::new("openbao-auth-method").long("openbao-auth-method")
            .env("GENESIS_OPENBAO_AUTH_METHOD").default_value("auto")
            .value_parser(["auto", "approle", "kubernetes"])
            .help("OpenBao auth: auto selects Agent for sockets and AppRole for TCP; explicit methods require TCP"))
        .arg(Arg::new("openbao-kubernetes-auth-mount").long("openbao-kubernetes-auth-mount")
            .env("GENESIS_OPENBAO_KUBERNETES_AUTH_MOUNT").default_value("kubernetes")
            .value_parser(openbao_client::kubernetes::validate_auth_mount)
            .help("Relative Kubernetes auth mount, without /v1/auth/ (Kubernetes mode only)"))
        .arg(Arg::new("openbao-kubernetes-role").long("openbao-kubernetes-role")
            .env("GENESIS_OPENBAO_KUBERNETES_ROLE")
            .value_parser(clap::builder::NonEmptyStringValueParser::new())
            .help("OpenBao Kubernetes role (required only for Kubernetes mode)"))
        .arg(Arg::new("openbao-kubernetes-token-path").long("openbao-kubernetes-token-path")
            .env("GENESIS_OPENBAO_KUBERNETES_TOKEN_PATH")
            .default_value("/var/run/secrets/kubernetes.io/serviceaccount/token")
            .value_parser(clap::builder::NonEmptyStringValueParser::new())
            .help("JWT file read at login; prefer an audience-scoped projected token"))
}

pub const DEFAULT_ADMISSION_ISSUER: &str = "https://genesis.permesi.dev";
pub const DEFAULT_ADMISSION_AUDIENCE: &str = "permesi";
pub const DEFAULT_CLIENT_IP_HEADER: &str = "CF-Connecting-IP";
pub const DEFAULT_CLIENT_COUNTRY_HEADER: &str = "CF-IPCountry";

/// Accept only a value that can name an HTTP header.
fn header_name(value: &str) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("header name is empty".to_string());
    }
    axum::http::HeaderName::try_from(value)
        .map(|_| value.to_string())
        .map_err(|_| "not a valid HTTP header name".to_string())
}

/// The `iss` and `aud` of every admission token. Permesi has to be started with the
/// same pair, or it rejects the tokens.
fn with_admission_args(command: Command) -> Command {
    command
        .arg(
            Arg::new("admission-issuer")
                .long("admission-issuer")
                .env("GENESIS_ADMISSION_ISS")
                .default_value(DEFAULT_ADMISSION_ISSUER)
                .value_parser(clap::builder::NonEmptyStringValueParser::new())
                .help("Issuer (iss) written into admission tokens; must match Permesi"),
        )
        .arg(
            Arg::new("admission-audience")
                .long("admission-audience")
                .env("GENESIS_ADMISSION_AUD")
                .default_value(DEFAULT_ADMISSION_AUDIENCE)
                .value_parser(clap::builder::NonEmptyStringValueParser::new())
                .help("Audience (aud) written into admission tokens; must match Permesi"),
        )
}

/// Where the audit record's client address and country come from. The headers are read
/// only from a trusted proxy; with none configured the transport peer is recorded.
fn with_client_metadata_args(command: Command) -> Command {
    command
        .arg(
            Arg::new("client-ip-header")
                .long("client-ip-header")
                .env("GENESIS_IP_HEADER")
                .default_value(DEFAULT_CLIENT_IP_HEADER)
                .value_parser(header_name)
                .help("Header a trusted proxy overwrites with the client address"),
        )
        .arg(
            Arg::new("client-country-header")
                .long("client-country-header")
                .env("GENESIS_COUNTRY_HEADER")
                .default_value(DEFAULT_CLIENT_COUNTRY_HEADER)
                .value_parser(header_name)
                .help("Header a trusted proxy sets to the client's two-character country code"),
        )
        .arg(
            Arg::new("trusted-proxy")
                .long("trusted-proxy")
                .env("GENESIS_TRUSTED_PROXIES")
                .value_delimiter(',')
                .action(clap::ArgAction::Append)
                .value_parser(trusted_proxy_range)
                .help(
                    "Proxy CIDRs allowed to supply the client address and country headers; \
                     a range that covers every address is refused",
                ),
        )
        .arg(
            Arg::new("trust-unix-proxy")
                .long("trust-unix-proxy")
                .env("GENESIS_TRUST_UNIX_PROXY")
                .action(clap::ArgAction::SetTrue)
                .help("Accept those headers from the same-host proxy on the Unix socket"),
        )
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

    let command = Command::new("genesis")
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .version(env!("CARGO_PKG_VERSION"))
        .long_version(long_version)
        .color(ColorChoice::Auto)
        .styles(styles)
        .arg(
            Arg::new("socket-path")
                .long("socket-path")
                .help("Bind to Unix domain socket instead of TCP port")
                .env("GENESIS_SOCKET_PATH")
                .conflicts_with_all(["port", "tls-pem-bundle"]),
        )
        .arg(
            Arg::new("port")
                .short('p')
                .long("port")
                .help("Port to listen on (prefers [::], falls back to 0.0.0.0)")
                .default_value("8080")
                .env("GENESIS_PORT")
                .value_parser(clap::value_parser!(u16)),
        )
        .arg(
            Arg::new("dsn")
                .short('d')
                .long("dsn")
                .help("Database connection string")
                .long_help(
                    "Database connection string. Username/password are injected from OpenBao DB creds, so they are not required in the DSN.",
                )
                .env("GENESIS_DSN")
                .hide_env_values(true)
                .required(true),
        );

    let command = command.arg(
        Arg::new("admission-signing-version")
            .long("admission-signing-version")
            .env("GENESIS_ADMISSION_SIGNING_VERSION")
            .default_value("1")
            .value_parser(clap::value_parser!(u32).range(1..))
            .help("Published Transit version to use for new admission signatures"),
    );
    let command = with_admission_args(command);
    let command = with_client_metadata_args(command);
    let command = openbao::with_args(command);
    let command = with_native_openbao_args(command);
    let command = tls::with_args(command);
    let mut command = command;
    for (name, env, default) in [
        (
            "public-requests-per-second",
            "GENESIS_PUBLIC_REQUESTS_PER_SECOND",
            "8",
        ),
        ("public-burst", "GENESIS_PUBLIC_BURST", "8"),
        ("public-max-in-flight", "GENESIS_PUBLIC_MAX_IN_FLIGHT", "8"),
    ] {
        command = command.arg(
            clap::Arg::new(name)
                .long(name)
                .env(env)
                .default_value(default)
                .value_parser(clap::value_parser!(u32).range(1..=65535)),
        );
    }
    let command = database::with_args(command);
    let command = http::with_args(command);
    logging::with_args(command)
}

/// Parse one trusted proxy range. A prefix length of zero names every address of its
/// family, which would let any caller supply the client address and country again, so
/// it is refused instead of read as "trust everyone".
///
/// # Errors
/// Returns a message for a value that is not a CIDR range or that covers every address.
pub fn trusted_proxy_range(value: &str) -> Result<sqlx::types::ipnetwork::IpNetwork, String> {
    let range: sqlx::types::ipnetwork::IpNetwork = value
        .trim()
        .parse()
        .map_err(|_| "not an IP address or CIDR range".to_string())?;
    if range.prefix() == 0 {
        return Err("a range that covers every address would trust every caller".to_string());
    }
    Ok(range)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `--help` prints the current value of an environment-backed argument unless the
    /// argument hides it, and these five hold a credential or an address that can carry one.
    #[test]
    fn help_shows_no_value_of_a_credential_bearing_argument() {
        let command = new();
        for name in [
            "dsn",
            "openbao-url",
            "openbao-role-id",
            "openbao-secret-id",
            "openbao-wrapped-token",
        ] {
            let argument = command
                .get_arguments()
                .find(|argument| argument.get_id() == name);
            assert!(
                argument.is_some_and(clap::Arg::is_hide_env_values_set),
                "{name} would print its environment value in --help"
            );
        }
    }

    #[test]
    fn test_new() {
        let command = new();

        assert_eq!(command.get_name(), "genesis");
        assert_eq!(
            command.get_about().map(ToString::to_string),
            Some(env!("CARGO_PKG_DESCRIPTION").to_string())
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
            "genesis",
            "--port",
            "8080",
            "--dsn",
            "postgres://user:password@localhost:5432/genesis",
            "--tls-pem-bundle",
            "/tmp/genesis-bundle.pem",
            "--openbao-url",
            "https://openbao.tld:8200",
            "--openbao-role-id",
            "role-id",
            "--openbao-secret-id",
            "secret-id",
        ]);

        assert_eq!(matches.get_one::<u16>("port").copied(), Some(8080));
        assert_eq!(
            matches.get_one::<String>("dsn").cloned(),
            Some("postgres://user:password@localhost:5432/genesis".to_string())
        );
        assert_eq!(
            matches.get_one::<String>("openbao-url").cloned(),
            Some("https://openbao.tld:8200".to_string())
        );
        assert_eq!(
            matches.get_one::<String>("openbao-role-id").cloned(),
            Some("role-id".to_string())
        );
        assert_eq!(
            matches.get_one::<String>("openbao-secret-id").cloned(),
            Some("secret-id".to_string())
        );
    }

    #[test]
    fn test_check_env() {
        temp_env::with_vars(
            [
                ("GENESIS_TLS_PEM_BUNDLE", Some("/tmp/genesis-bundle.pem")),
                ("GENESIS_OPENBAO_URL", Some("https://openbao.tld:8200")),
                ("GENESIS_OPENBAO_ROLE_ID", Some("role_id")),
                ("GENESIS_OPENBAO_SECRET_ID", Some("secret_id")),
                ("GENESIS_TRANSIT_MOUNT", Some("transit/custom")),
                ("GENESIS_PORT", Some("443")),
                (
                    "GENESIS_DSN",
                    Some("postgres://user:password@localhost:5432/genesis"),
                ),
                ("GENESIS_LOG_LEVEL", Some("info")),
            ],
            || {
                let command = new();
                let matches = command.get_matches_from(vec!["genesis"]);
                assert_eq!(matches.get_one::<u16>("port").copied(), Some(443));
                assert_eq!(
                    matches.get_one::<String>("dsn").cloned(),
                    Some("postgres://user:password@localhost:5432/genesis".to_string())
                );
                assert_eq!(
                    matches.get_one::<String>("openbao-url").cloned(),
                    Some("https://openbao.tld:8200".to_string())
                );
                assert_eq!(
                    matches
                        .get_one::<String>("openbao-transit-mount")
                        .map(String::as_str),
                    Some("transit/custom")
                );
                assert_eq!(matches.get_one::<u8>("verbosity").copied(), Some(2));
            },
        );
    }

    #[test]
    fn test_openbao_transit_mount_default() {
        temp_env::with_vars([("GENESIS_TRANSIT_MOUNT", None::<&str>)], || {
            let command = new();
            let matches = command.get_matches_from(vec![
                "genesis",
                "--port",
                "8080",
                "--dsn",
                "postgres://user:password@localhost:5432/genesis",
                "--tls-pem-bundle",
                "/tmp/genesis-bundle.pem",
                "--openbao-url",
                "https://openbao.tld:8200",
                "--openbao-role-id",
                "role-id",
                "--openbao-secret-id",
                "secret-id",
            ]);

            assert_eq!(
                matches
                    .get_one::<String>("openbao-transit-mount")
                    .map(String::as_str),
                Some("transit/genesis")
            );
        });
    }

    #[test]
    fn test_check_log_level_env() {
        // loop cover all possible value_parse
        let levels = ["error", "warn", "info", "debug", "trace"];
        for (index, &level) in levels.iter().enumerate() {
            temp_env::with_vars(
                [
                    ("GENESIS_LOG_LEVEL", Some(level)),
                    ("GENESIS_TLS_PEM_BUNDLE", Some("/tmp/genesis-bundle.pem")),
                    ("GENESIS_OPENBAO_URL", Some("http://openbao.tld:8200")),
                    ("GENESIS_OPENBAO_ROLE_ID", Some("role_id")),
                    ("GENESIS_OPENBAO_SECRET_ID", Some("secret_id")),
                    (
                        "GENESIS_DSN",
                        Some("postgres://user:password@localhost:5432/genesis"),
                    ),
                ],
                || {
                    let command = new();
                    let matches = command.get_matches_from(vec!["genesis"]);
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
            temp_env::with_vars([("GENESIS_LOG_LEVEL", None::<String>)], || {
                let mut args = vec![
                    "genesis".to_string(),
                    "--dsn".to_string(),
                    "postgres://user:password@localhost:5432/genesis".to_string(),
                    "--tls-pem-bundle".to_string(),
                    "/tmp/genesis-bundle.pem".to_string(),
                    "--openbao-url".to_string(),
                    "https://openbao.tld:8200".to_string(),
                    "--openbao-role-id".to_string(),
                    "role_id".to_string(),
                    "--openbao-secret-id".to_string(),
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

    #[test]
    fn test_socket_conflicts() {
        let command = new();

        // Conflict: socket-path AND port
        let result = command.clone().try_get_matches_from(vec![
            "genesis",
            "--dsn",
            "postgres://",
            "--socket-path",
            "/tmp/genesis.sock",
            "--port",
            "9090",
        ]);
        assert_eq!(
            result.map_err(|e| e.kind()),
            Err(clap::error::ErrorKind::ArgumentConflict)
        );

        // Conflict: socket-path AND tls-pem-bundle
        let result = command.try_get_matches_from(vec![
            "genesis",
            "--dsn",
            "postgres://",
            "--socket-path",
            "/tmp/genesis.sock",
            "--tls-pem-bundle",
            "/tmp/bundle.pem",
        ]);
        assert_eq!(
            result.map_err(|e| e.kind()),
            Err(clap::error::ErrorKind::ArgumentConflict)
        );
    }
}
