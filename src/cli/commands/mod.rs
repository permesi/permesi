use clap::{
    builder::{
        styling::{AnsiColor, Effects, Styles},
        ValueParser,
    },
    Arg, ColorChoice, Command,
};

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

pub fn new() -> Command {
    let styles = Styles::styled()
        .header(AnsiColor::Yellow.on_default() | Effects::BOLD)
        .usage(AnsiColor::Green.on_default() | Effects::BOLD)
        .literal(AnsiColor::Blue.on_default() | Effects::BOLD)
        .placeholder(AnsiColor::Green.on_default());

    Command::new("permesi")
        .about("Identity and Access Management")
        .version(env!("CARGO_PKG_VERSION"))
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
                .env("PERMESI_DSN")
                .required(true),
        )
        .arg(
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
            command.get_about().unwrap().to_string(),
            "Identity and Access Management"
        );
        assert_eq!(
            command.get_version().unwrap().to_string(),
            env!("CARGO_PKG_VERSION")
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
            "postgres://localhost",
        ]);

        assert_eq!(matches.get_one::<u16>("port").map(|s| *s), Some(8080));
        assert_eq!(
            matches.get_one::<String>("dsn").map(|s| s.to_string()),
            Some("postgres://localhost".to_string())
        );
    }

    #[test]
    fn test_check_env() {
        temp_env::with_vars(
            [
                ("PERMESI_DSN", Some("postgres://localhost")),
                ("PERMESI_PORT", Some("443")),
                ("PERMESI_LOG_LEVEL", Some("info")),
            ],
            || {
                let command = new();
                let matches = command.get_matches_from(vec!["permesi"]);
                assert_eq!(matches.get_one::<u16>("port").map(|s| *s), Some(443));
                assert_eq!(
                    matches.get_one::<String>("dsn").map(|s| s.to_string()),
                    Some("postgres://localhost".to_string())
                );
                assert_eq!(matches.get_one::<u8>("verbosity").map(|s| *s), Some(2));
            },
        );
    }

    #[test]
    fn test_check_log_level_env() {
        // loop cover all possible value_parse
        let levels = vec!["error", "warn", "info", "debug", "trace"];
        for (index, &level) in levels.iter().enumerate() {
            temp_env::with_vars(
                [
                    ("PERMESI_LOG_LEVEL", Some(level)),
                    ("PERMESI_DSN", Some("postgres://localhost")),
                ],
                || {
                    let command = new();
                    let matches = command.get_matches_from(vec!["permesi"]);
                    assert_eq!(
                        matches.get_one::<u8>("verbosity").map(|s| *s),
                        Some(index as u8)
                    );
                },
            );
        }
    }

    #[test]
    fn test_check_log_level_verbosity() {
        // loop cover all possible value_parse
        let levels = vec!["error", "warn", "info", "debug", "trace"];
        for (index, _) in levels.iter().enumerate() {
            temp_env::with_vars([("PERMESI_LOG_LEVEL", None::<String>)], || {
                let mut args = vec![
                    "permesi".to_string(),
                    "--dsn".to_string(),
                    "postgres://localhost".to_string(),
                ];

                // Add the appropriate number of "-v" flags based on the index
                if index > 0 {
                    let v = format!("-{}", "v".repeat(index));
                    args.push(v);
                }

                let command = new();

                let matches = command.get_matches_from(args);

                assert_eq!(
                    matches.get_one::<u8>("verbosity").map(|s| *s),
                    Some(index as u8)
                );
            });
        }
    }
}
