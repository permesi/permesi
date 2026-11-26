//! Bounded PostgreSQL connection-pool configuration shared by the services.
//!
//! Each process shares one pool between request handlers and background work
//! (permesi's email outbox poller, readiness and health probes). The values come
//! from each service's CLI (`--db-*` flags and `*_DB_*` environment variables,
//! with defaults defined in `cli/commands`), and [`PoolConfig::new`] rejects
//! shapes that could exhaust PostgreSQL or starve the service, so a bad value
//! fails startup instead of degrading at runtime.
//!
//! A short acquire timeout turns pool exhaustion into a prompt error instead of
//! letting requests queue for sqlx's 30-second default, usually behind a proxy
//! that has already given up on them. Connections are recycled after
//! `max_lifetime`; recycling more often would not refresh credentials, because
//! the OpenBao-issued username and password are fixed in the DSN for the life of
//! the process (a new lease means a restart), and OpenBao's revocation statements
//! already terminate live sessions. `test_before_acquire` replaces connections a
//! proxy or the database dropped while idle.
//!
//! Every option is set explicitly, including those equal to sqlx defaults, so a
//! dependency upgrade cannot silently change pool behavior. Connections carry an
//! `application_name` so they can be told apart in `pg_stat_activity`.
//!
//! Flow Overview: [`begin`] acquires a connection in the caller, then completes
//! BEGIN in an owned task. Cancelling the caller cannot interrupt `SQLx` before it
//! tracks the server transaction. An abandoned task result drops the tracked
//! transaction and schedules rollback before the connection can be reused.

use anyhow::{Context, Result, bail};
use sqlx::{
    PgPool, Postgres, Transaction,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use std::{fmt, str::FromStr, time::Duration};
use tracing::warn;

/// Upper bound on `max_connections` for one process.
pub const MAX_CONNECTIONS_LIMIT: u32 = 200;
const ACQUIRE_TIMEOUT_MIN: Duration = Duration::from_millis(100);
const ACQUIRE_TIMEOUT_MAX: Duration = Duration::from_secs(30);
const IDLE_TIMEOUT_MIN: Duration = Duration::from_secs(10);
const MAX_LIFETIME_MIN: Duration = Duration::from_mins(1);
const MAX_LIFETIME_MAX: Duration = Duration::from_hours(24);

/// Longest wait for pooled connections to close during shutdown.
pub const POOL_CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

/// Starts a pool-owned transaction without exposing `SQLx`'s interrupted-BEGIN window.
///
/// Pool acquisition stays cancellable and bounded by existing caller/pool deadlines.
/// After acquisition, the owned task finishes BEGIN even if its receiver disappears;
/// its dropped output then rolls back a fully tracked transaction. The task holds
/// one existing pool permit and never executes application writes after cancellation.
///
/// # Errors
/// Returns pool/BEGIN failures or a sanitized worker error if initialization panics.
pub async fn begin(pool: &PgPool) -> Result<Transaction<'static, Postgres>, sqlx::Error> {
    let connection = pool.acquire().await?;
    // SQLx 0.9's doc-hidden constructor accepts the owned pool connection, keeping
    // this transaction 'static. Preserve the BEGIN-cancellation regression on upgrades.
    tokio::spawn(async move { Transaction::begin(connection, None).await })
        .await
        .map_err(|_| sqlx::Error::WorkerCrashed)?
}

/// Validated shape of a service's PostgreSQL pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolConfig {
    max_connections: u32,
    min_connections: u32,
    acquire_timeout: Duration,
    idle_timeout: Duration,
    max_lifetime: Duration,
}

impl PoolConfig {
    /// Validate and build a pool configuration.
    ///
    /// # Errors
    /// Returns an error when a value is outside its safe range, when
    /// `min_connections` exceeds `max_connections`, or when the idle timeout is
    /// not shorter than the lifetime (idle reaping would then never happen).
    pub fn new(
        max_connections: u32,
        min_connections: u32,
        acquire_timeout: Duration,
        idle_timeout: Duration,
        max_lifetime: Duration,
    ) -> Result<Self> {
        if !(1..=MAX_CONNECTIONS_LIMIT).contains(&max_connections) {
            bail!("max connections must be between 1 and {MAX_CONNECTIONS_LIMIT}");
        }
        if min_connections > max_connections {
            bail!("min connections must not exceed max connections");
        }
        if !(ACQUIRE_TIMEOUT_MIN..=ACQUIRE_TIMEOUT_MAX).contains(&acquire_timeout) {
            bail!("acquire timeout must be between 100 ms and 30 s");
        }
        if !(MAX_LIFETIME_MIN..=MAX_LIFETIME_MAX).contains(&max_lifetime) {
            bail!("max lifetime must be between 60 s and 24 h");
        }
        if idle_timeout < IDLE_TIMEOUT_MIN || idle_timeout >= max_lifetime {
            bail!("idle timeout must be at least 10 s and below the max lifetime");
        }
        Ok(Self {
            max_connections,
            min_connections,
            acquire_timeout,
            idle_timeout,
            max_lifetime,
        })
    }

    #[must_use]
    pub const fn max_connections(&self) -> u32 {
        self.max_connections
    }

    #[must_use]
    pub const fn min_connections(&self) -> u32 {
        self.min_connections
    }

    #[must_use]
    pub const fn acquire_timeout(&self) -> Duration {
        self.acquire_timeout
    }

    #[must_use]
    pub const fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }

    #[must_use]
    pub const fn max_lifetime(&self) -> Duration {
        self.max_lifetime
    }

    /// Translate this configuration into sqlx pool options, setting every option.
    #[must_use]
    pub fn pool_options(&self) -> PgPoolOptions {
        PgPoolOptions::new()
            .max_connections(self.max_connections)
            .min_connections(self.min_connections)
            .acquire_timeout(self.acquire_timeout)
            .idle_timeout(self.idle_timeout)
            .max_lifetime(self.max_lifetime)
            .test_before_acquire(true)
    }

    /// Connect a pool whose connections report `application_name` to PostgreSQL.
    ///
    /// Errors never include the DSN, which carries the OpenBao-issued password.
    ///
    /// # Errors
    /// Returns an error if the DSN is malformed or the initial connections fail.
    pub async fn connect(&self, dsn: &str, application_name: &str) -> Result<PgPool> {
        let options = PgConnectOptions::from_str(dsn)
            .context("Invalid database connection string")?
            .application_name(application_name);
        self.pool_options()
            .connect_with(options)
            .await
            .context("Failed to connect to database")
    }
}

/// One-line summary for startup logs.
/// DSN query parameters whose values are settings. Every other value is hidden.
const LOGGABLE_DSN_PARAMETERS: [&str; 6] = [
    "application_name",
    "connect_timeout",
    "dbname",
    "host",
    "port",
    "sslmode",
];

/// A database DSN reduced to what is safe in a log.
///
/// The userinfo password is replaced, and so is the value of every query parameter that
/// is not a known setting: libpq and sqlx both accept `?password=...`, and a parameter
/// this code does not know is treated as a secret. A value that is not a URL is not
/// echoed at all.
#[must_use]
pub fn loggable_dsn(dsn: &str) -> String {
    let Ok(mut parsed) = url::Url::parse(dsn) else {
        return "invalid-dsn".to_string();
    };
    if parsed.password().is_some() {
        let _ = parsed.set_password(Some("REDACTED"));
    }
    if parsed.query().is_some() {
        let shown: Vec<(String, String)> = parsed
            .query_pairs()
            .map(|(key, value)| {
                let value = if LOGGABLE_DSN_PARAMETERS.contains(&key.as_ref()) {
                    value.into_owned()
                } else {
                    "REDACTED".to_string()
                };
                (key.into_owned(), value)
            })
            .collect();
        parsed.query_pairs_mut().clear().extend_pairs(shown);
    }
    parsed.set_fragment(None);
    parsed.to_string()
}

impl fmt::Display for PoolConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "max={} min={} acquire={}ms idle={}s lifetime={}s",
            self.max_connections,
            self.min_connections,
            self.acquire_timeout.as_millis(),
            self.idle_timeout.as_secs(),
            self.max_lifetime.as_secs()
        )
    }
}

/// Close `pool` after the server and background workers stopped using it.
///
/// Waits at most [`POOL_CLOSE_TIMEOUT`] for checked-out connections to return;
/// any still open after that are dropped with the process.
pub async fn close(pool: &PgPool) {
    if tokio::time::timeout(POOL_CLOSE_TIMEOUT, pool.close())
        .await
        .is_err()
    {
        warn!("PostgreSQL pool did not close in time; remaining connections are dropped");
    }
}

#[cfg(test)]
mod tests {
    use super::{PoolConfig, loggable_dsn};

    /// libpq and sqlx accept the password in the userinfo or as a query parameter; a
    /// logged DSN shows neither, and hides any parameter it does not know to be a setting.
    #[test]
    fn loggable_dsn_hides_passwords_in_userinfo_and_query() {
        assert_eq!(
            loggable_dsn("postgres://app:userinfo-pw@db.internal:5432/permesi?sslmode=verify-full"),
            "postgres://app:REDACTED@db.internal:5432/permesi?sslmode=verify-full"
        );
        let shown = loggable_dsn(
            "postgres://db.internal/permesi?user=app&password=query-pw&sslpassword=key-pw&unknown=opaque-value&sslmode=require#frag-value",
        );
        assert_eq!(
            shown,
            "postgres://db.internal/permesi?user=REDACTED&password=REDACTED&sslpassword=REDACTED&unknown=REDACTED&sslmode=require"
        );
        for secret in ["query-pw", "key-pw", "opaque-value", "frag-value"] {
            assert!(!shown.contains(secret), "{secret}");
        }
        assert_eq!(loggable_dsn("host=db password=keyword-pw"), "invalid-dsn");
    }
    use std::time::Duration;

    fn config(
        max: u32,
        min: u32,
        acquire_ms: u64,
        idle_s: u64,
        lifetime_s: u64,
    ) -> anyhow::Result<PoolConfig> {
        PoolConfig::new(
            max,
            min,
            Duration::from_millis(acquire_ms),
            Duration::from_secs(idle_s),
            Duration::from_secs(lifetime_s),
        )
    }

    #[test]
    fn pool_config_accepts_service_defaults() {
        assert!(config(10, 2, 3_000, 600, 1_800).is_ok());
    }

    #[test]
    fn pool_config_rejects_out_of_range_values() {
        assert!(config(0, 0, 3_000, 600, 1_800).is_err());
        assert!(config(201, 2, 3_000, 600, 1_800).is_err());
        assert!(config(10, 11, 3_000, 600, 1_800).is_err());
        assert!(config(10, 2, 99, 600, 1_800).is_err());
        assert!(config(10, 2, 30_001, 600, 1_800).is_err());
        assert!(config(10, 2, 3_000, 600, 59).is_err());
        assert!(config(10, 2, 3_000, 600, 86_401).is_err());
    }

    #[test]
    fn pool_config_requires_idle_timeout_below_lifetime() {
        assert!(config(10, 2, 3_000, 9, 1_800).is_err());
        assert!(config(10, 2, 3_000, 1_800, 1_800).is_err());
        assert!(config(10, 2, 3_000, 1_799, 1_800).is_ok());
    }

    #[test]
    fn pool_options_carry_every_setting() -> anyhow::Result<()> {
        let config = config(12, 3, 2_500, 300, 900)?;
        let options = config.pool_options();
        assert_eq!(options.get_max_connections(), 12);
        assert_eq!(options.get_min_connections(), 3);
        assert_eq!(options.get_acquire_timeout(), Duration::from_millis(2_500));
        assert_eq!(options.get_idle_timeout(), Some(Duration::from_secs(300)));
        assert_eq!(options.get_max_lifetime(), Some(Duration::from_mins(15)));
        assert!(options.get_test_before_acquire());
        Ok(())
    }
}
