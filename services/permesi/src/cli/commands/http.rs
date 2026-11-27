//! Server-wide HTTP deadline flags.
//!
//! Clap enforces each value's range; [`parse`] then builds the [`HttpLimits`], which
//! also checks that reading the headers may not take longer than the whole request. See
//! `service_utils::http_limits` for what each deadline bounds.

use anyhow::{Context, Result};
use clap::{Arg, ArgMatches, Command, value_parser};
use service_utils::http_limits::HttpLimits;
use std::time::Duration;

pub const ARG_REQUEST_TIMEOUT_SECONDS: &str = "request-timeout-seconds";
pub const ARG_HEADER_READ_TIMEOUT_SECONDS: &str = "header-read-timeout-seconds";
pub const ARG_SHUTDOWN_DRAIN_SECONDS: &str = "shutdown-drain-seconds";

/// Build the validated limits from parsed flags.
///
/// # Errors
/// Returns an error if a flag is missing or the combination is inconsistent.
pub fn parse(matches: &ArgMatches) -> Result<HttpLimits> {
    let seconds = |id: &str| -> Result<Duration> {
        matches
            .get_one::<u64>(id)
            .copied()
            .map(Duration::from_secs)
            .with_context(|| format!("missing required argument: --{id}"))
    };
    HttpLimits::new(
        seconds(ARG_REQUEST_TIMEOUT_SECONDS)?,
        seconds(ARG_HEADER_READ_TIMEOUT_SECONDS)?,
        seconds(ARG_SHUTDOWN_DRAIN_SECONDS)?,
    )
    .context("invalid HTTP deadline settings")
}

#[must_use]
pub fn with_args(command: Command) -> Command {
    command
        .arg(
            Arg::new(ARG_REQUEST_TIMEOUT_SECONDS)
                .long(ARG_REQUEST_TIMEOUT_SECONDS)
                .help("Longest any request may take to be answered; a slower one gets 503")
                .env("PERMESI_REQUEST_TIMEOUT_SECONDS")
                .default_value("60")
                .value_parser(value_parser!(u64).range(1..=600)),
        )
        .arg(
            Arg::new(ARG_HEADER_READ_TIMEOUT_SECONDS)
                .long(ARG_HEADER_READ_TIMEOUT_SECONDS)
                .help("Longest a TCP/TLS connection may take to deliver a request's headers")
                .env("PERMESI_HEADER_READ_TIMEOUT_SECONDS")
                .default_value("10")
                .value_parser(value_parser!(u64).range(1..=60)),
        )
        .arg(
            Arg::new(ARG_SHUTDOWN_DRAIN_SECONDS)
                .long(ARG_SHUTDOWN_DRAIN_SECONDS)
                .help("Longest in-flight requests may take to finish on shutdown; a second signal ends it at once")
                .env("PERMESI_SHUTDOWN_DRAIN_SECONDS")
                .default_value("20")
                .value_parser(value_parser!(u64).range(1..=300)),
        )
}

#[cfg(test)]
mod tests {
    use super::{parse, with_args};
    use clap::Command;
    use std::time::Duration;

    fn command() -> Command {
        with_args(Command::new("test"))
    }

    /// Hermetic: a developer shell may export any of these.
    const ENV: [&str; 3] = [
        "PERMESI_REQUEST_TIMEOUT_SECONDS",
        "PERMESI_HEADER_READ_TIMEOUT_SECONDS",
        "PERMESI_SHUTDOWN_DRAIN_SECONDS",
    ];

    #[test]
    fn http_deadlines_default_and_are_bounded() -> anyhow::Result<()> {
        temp_env::with_vars_unset(ENV, || {
            let limits = parse(&command().try_get_matches_from(["test"])?)?;
            assert_eq!(limits.request_timeout(), Duration::from_mins(1));
            assert_eq!(limits.header_read_timeout(), Duration::from_secs(10));
            assert_eq!(limits.drain_timeout(), Duration::from_secs(20));

            let set = parse(&command().try_get_matches_from([
                "test",
                "--request-timeout-seconds",
                "5",
                "--header-read-timeout-seconds",
                "2",
                "--shutdown-drain-seconds",
                "3",
            ])?)?;
            assert_eq!(set.to_string(), "request=5s header_read=2s drain=3s");

            // None of them can be switched off or left effectively unbounded.
            for refused in [
                ["--request-timeout-seconds", "0"],
                ["--request-timeout-seconds", "601"],
                ["--header-read-timeout-seconds", "0"],
                ["--header-read-timeout-seconds", "61"],
                ["--shutdown-drain-seconds", "0"],
                ["--shutdown-drain-seconds", "301"],
            ] {
                assert!(
                    command()
                        .try_get_matches_from(["test"].into_iter().chain(refused))
                        .is_err(),
                    "{refused:?}"
                );
            }
            // Reading the headers may not take longer than the whole request.
            let inverted = command().try_get_matches_from([
                "test",
                "--request-timeout-seconds",
                "5",
                "--header-read-timeout-seconds",
                "6",
            ])?;
            assert!(parse(&inverted).is_err());
            Ok(())
        })
    }
}
