use clap::{Arg, Command, builder::ValueParser};

pub const ARG_VERBOSITY: &str = "verbosity";

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
pub fn with_args(command: Command) -> Command {
    command.arg(
        Arg::new(ARG_VERBOSITY)
            .short('v')
            .long("verbose")
            .help("Verbosity level: ERROR, WARN, INFO, DEBUG, TRACE (default: ERROR)")
            .env("PERMESI_LOG_LEVEL")
            .global(true)
            .action(clap::ArgAction::Count)
            .value_parser(validator_log_level()),
    )
}
