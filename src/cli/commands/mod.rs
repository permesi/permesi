use clap::{
    builder::styling::{AnsiColor, Effects, Styles},
    Arg, ColorChoice, Command,
};

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
            "sqlite::memory:",
        ]);

        assert_eq!(matches.get_one::<u16>("port").map(|s| *s), Some(8080));
        assert_eq!(
            matches.get_one::<String>("dsn").map(|s| s.to_string()),
            Some("sqlite::memory:".to_string())
        );
    }

    #[test]
    fn test_check_env() {
        temp_env::with_vars(
            [
                ("PERMESI_DSN", Some("sqlite::memory:")),
                ("PERMESI_PORT", Some("443")),
            ],
            || {
                let command = new();
                let matches = command.get_matches_from(vec!["permesi"]);
                assert_eq!(matches.get_one::<u16>("port").map(|s| *s), Some(443));
                assert_eq!(
                    matches.get_one::<String>("dsn").map(|s| s.to_string()),
                    Some("sqlite::memory:".to_string())
                );
            },
        );
    }
}
