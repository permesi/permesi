//! PostgreSQL connection-pool flags.
//!
//! Clap enforces each value's range; [`parse`] then builds a [`PoolConfig`], which
//! also checks the cross-field rules (min connections not above max, idle timeout
//! below the connection lifetime). See `service_utils::database` for why the
//! defaults are what they are.

use anyhow::{Context, Result};
use clap::{Arg, ArgMatches, Command, value_parser};
use service_utils::database::PoolConfig;
use std::time::Duration;

pub const ARG_DB_MAX_CONNECTIONS: &str = "db-max-connections";
pub const ARG_DB_MIN_CONNECTIONS: &str = "db-min-connections";
pub const ARG_DB_ACQUIRE_TIMEOUT_MS: &str = "db-acquire-timeout-ms";
pub const ARG_DB_IDLE_TIMEOUT_SECONDS: &str = "db-idle-timeout-seconds";
pub const ARG_DB_MAX_LIFETIME_SECONDS: &str = "db-max-lifetime-seconds";

/// Build the validated pool configuration from parsed flags.
///
/// # Errors
/// Returns an error if a flag is missing or the combination is inconsistent.
pub fn parse(matches: &ArgMatches) -> Result<PoolConfig> {
    let count = |id: &str| -> Result<u32> {
        matches
            .get_one::<u32>(id)
            .copied()
            .with_context(|| format!("missing required argument: --{id}"))
    };
    let amount = |id: &str| -> Result<u64> {
        matches
            .get_one::<u64>(id)
            .copied()
            .with_context(|| format!("missing required argument: --{id}"))
    };

    PoolConfig::new(
        count(ARG_DB_MAX_CONNECTIONS)?,
        count(ARG_DB_MIN_CONNECTIONS)?,
        Duration::from_millis(amount(ARG_DB_ACQUIRE_TIMEOUT_MS)?),
        Duration::from_secs(amount(ARG_DB_IDLE_TIMEOUT_SECONDS)?),
        Duration::from_secs(amount(ARG_DB_MAX_LIFETIME_SECONDS)?),
    )
    .context("invalid database pool settings (--db-*)")
}

#[must_use]
pub fn with_args(command: Command) -> Command {
    command
        .arg(
            Arg::new(ARG_DB_MAX_CONNECTIONS)
                .long(ARG_DB_MAX_CONNECTIONS)
                .help("Maximum open PostgreSQL connections for this process")
                .env("PERMESI_DB_MAX_CONNECTIONS")
                .default_value("10")
                .value_parser(value_parser!(u32).range(1..=200)),
        )
        .arg(
            Arg::new(ARG_DB_MIN_CONNECTIONS)
                .long(ARG_DB_MIN_CONNECTIONS)
                .help("PostgreSQL connections kept open while idle")
                .env("PERMESI_DB_MIN_CONNECTIONS")
                .default_value("2")
                .value_parser(value_parser!(u32).range(0..=200)),
        )
        .arg(
            Arg::new(ARG_DB_ACQUIRE_TIMEOUT_MS)
                .long(ARG_DB_ACQUIRE_TIMEOUT_MS)
                .help("Longest wait for a free PostgreSQL connection, in milliseconds")
                .env("PERMESI_DB_ACQUIRE_TIMEOUT_MS")
                .default_value("3000")
                .value_parser(value_parser!(u64).range(100..=30_000)),
        )
        .arg(
            Arg::new(ARG_DB_IDLE_TIMEOUT_SECONDS)
                .long(ARG_DB_IDLE_TIMEOUT_SECONDS)
                .help("Close idle PostgreSQL connections above the minimum after this many seconds")
                .env("PERMESI_DB_IDLE_TIMEOUT_SECONDS")
                .default_value("600")
                .value_parser(value_parser!(u64).range(10..=86_400)),
        )
        .arg(
            Arg::new(ARG_DB_MAX_LIFETIME_SECONDS)
                .long(ARG_DB_MAX_LIFETIME_SECONDS)
                .help("Recycle every PostgreSQL connection after this many seconds")
                .env("PERMESI_DB_MAX_LIFETIME_SECONDS")
                .default_value("1800")
                .value_parser(value_parser!(u64).range(60..=86_400)),
        )
}

#[cfg(test)]
mod tests {
    use super::{ARG_DB_IDLE_TIMEOUT_SECONDS, ARG_DB_MAX_LIFETIME_SECONDS, parse, with_args};
    use clap::Command;
    use std::time::Duration;

    fn command() -> Command {
        with_args(Command::new("test"))
    }

    #[test]
    fn database_defaults_build_a_valid_pool_config() -> anyhow::Result<()> {
        let matches = command().try_get_matches_from(["test"])?;
        let config = parse(&matches)?;
        assert_eq!(config.max_connections(), 10);
        assert_eq!(config.min_connections(), 2);
        assert_eq!(config.acquire_timeout(), Duration::from_secs(3));
        assert_eq!(config.idle_timeout(), Duration::from_mins(10));
        assert_eq!(config.max_lifetime(), Duration::from_mins(30));
        Ok(())
    }

    #[test]
    fn database_flags_reject_out_of_range_values() {
        assert!(
            command()
                .try_get_matches_from(["test", "--db-max-connections", "0"])
                .is_err()
        );
        assert!(
            command()
                .try_get_matches_from(["test", "--db-acquire-timeout-ms", "50"])
                .is_err()
        );
    }

    #[test]
    fn database_flags_reject_idle_timeout_above_lifetime() -> anyhow::Result<()> {
        let matches = command().try_get_matches_from([
            "test",
            &format!("--{ARG_DB_IDLE_TIMEOUT_SECONDS}"),
            "900",
            &format!("--{ARG_DB_MAX_LIFETIME_SECONDS}"),
            "600",
        ])?;
        assert!(parse(&matches).is_err());
        Ok(())
    }
}
