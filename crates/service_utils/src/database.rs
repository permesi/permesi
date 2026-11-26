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

/// DSN query parameters whose values are settings. Any other parameter is hidden whole.
const LOGGABLE_DSN_PARAMETERS: [&str; 6] = [
    "application_name",
    "connect_timeout",
    "dbname",
    "host",
    "port",
    "sslmode",
];

/// The values `sslmode` can take; any other value is hidden with the unknown parameters.
const LOGGABLE_SSL_MODES: [&str; 6] = [
    "disable",
    "allow",
    "prefer",
    "require",
    "verify-ca",
    "verify-full",
];

/// A database DSN reduced to what is safe in a log: scheme, host, port, database name
/// and the query parameters that are known settings.
///
/// The result is rebuilt from parts that passed a check, never copied from the input.
/// The userinfo is dropped: the services replace it with credentials from OpenBao before
/// connecting, and a secret placed there by mistake must not be printed. The host has
/// to be an IP literal or made of host name characters: in a `postgres` URL the parser
/// keeps `;`, `&`, `=`, `,` and percent-escapes in the host as written, so
/// `host;password=...` would otherwise be shown whole. The database name is shown only
/// as a single segment of plain characters, because a `/` or `?` typed before the `@`
/// ends the authority early and moves the password into the path or a query key; a
/// name that is anything else becomes `REDACTED`. A query parameter is shown only if
/// its name is a known setting and its value is plain, a keyword for `sslmode` and
/// digits for `port` and `connect_timeout`; the rest, names included, become one
/// `REDACTED` marker, since libpq and sqlx accept `?password=...` and an unencoded `&`
/// or `;` in a password turns part of it into a name or into the value of another
/// parameter. Only `postgres://` and `postgresql://` URLs are shown at all: without the
/// `//` the whole rest of the string parses as an opaque path. A value that holds a
/// character other than printable ASCII, once the whitespace around it is trimmed, is
/// not shown either, because a URL parser silently removes tabs and line breaks and
/// would join text from another line to the database name.
///
/// The limit of this function: plain text standing where a host, a database name or the
/// value of a known setting belongs is shown as that. No check can tell a database name
/// from a token made of the same characters.
#[must_use]
pub fn loggable_dsn(dsn: &str) -> String {
    const UNSHOWN: &str = "invalid-dsn";
    let plain = |text: &str, extra: &[u8]| {
        !text.is_empty()
            && text
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || extra.contains(&byte))
    };
    let dsn = dsn.trim();
    let authority = ["postgres://", "postgresql://"].iter().any(|prefix| {
        dsn.get(..prefix.len())
            .is_some_and(|start| start.eq_ignore_ascii_case(prefix))
    });
    let clean = dsn.bytes().all(|byte| byte.is_ascii_graphic());
    let Some(parsed) = url::Url::parse(dsn).ok().filter(|_| authority && clean) else {
        return UNSHOWN.to_string();
    };
    // A socket DSN has no host. Bracketed IPv6 is the only literal this scheme parses.
    let host = match parsed.host() {
        None => String::new(),
        Some(url::Host::Domain(name)) if name.is_empty() || plain(name, b"-_.") => name.to_string(),
        Some(url::Host::Domain(_)) => return UNSHOWN.to_string(),
        Some(literal) => literal.to_string(),
    };
    let port = parsed
        .port()
        .map_or_else(String::new, |port| format!(":{port}"));
    let database = match parsed.path().strip_prefix('/').unwrap_or_default() {
        "" => String::new(),
        name if plain(name, b"-_.") => format!("/{name}"),
        _ => "/REDACTED".to_string(),
    };
    let shown = |key: &str, value: &str| match key {
        "sslmode" => LOGGABLE_SSL_MODES.contains(&value),
        "port" | "connect_timeout" => plain(value, b""),
        _ => LOGGABLE_DSN_PARAMETERS.contains(&key) && plain(value, b"-_./"),
    };
    let mut pairs: Vec<String> = parsed
        .query_pairs()
        .filter(|(key, value)| shown(key, value))
        .map(|(key, value)| format!("{key}={value}"))
        .collect();
    if parsed.query_pairs().count() > pairs.len() {
        pairs.push("REDACTED".to_string());
    }
    let query = if pairs.is_empty() {
        String::new()
    } else {
        format!("?{}", pairs.join("&"))
    };
    format!("{}://{host}{port}{database}{query}", parsed.scheme())
}

/// One-line summary for startup logs.
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
    use std::time::Duration;

    /// libpq and sqlx accept the password in the userinfo or as a query parameter; a
    /// logged DSN shows neither, and hides any parameter it does not know to be a setting.
    #[test]
    fn loggable_dsn_hides_passwords_in_userinfo_and_query() {
        for (dsn, shown) in [
            (
                "postgres://app:userinfo-pw@db.internal:5432/permesi?sslmode=verify-full",
                "postgres://db.internal:5432/permesi?sslmode=verify-full",
            ),
            (
                "PostgreSQL://lone-userinfo-secret@db.internal/permesi",
                "postgresql://db.internal/permesi",
            ),
            (
                "postgres://db.internal/permesi?user=app&password=query-pw&sslpassword=key-pw&unknown=opaque-value&sslmode=require#frag-value",
                "postgres://db.internal/permesi?sslmode=require&REDACTED",
            ),
            (
                "postgres:///permesi?host=/var/run/postgresql",
                "postgres:///permesi?host=/var/run/postgresql",
            ),
            ("postgres://db.internal", "postgres://db.internal"),
            (
                "postgres://[::1]:5432/permesi?connect_timeout=5&port=5433",
                "postgres://[::1]:5432/permesi?connect_timeout=5&port=5433",
            ),
            // Whitespace around the value, as a secret file ending in a newline gives it,
            // is not part of the DSN.
            (
                " postgres://app:userinfo-pw@db.internal/permesi\n",
                "postgres://db.internal/permesi",
            ),
            // A database name that is not one plain segment is marked, not left out, so
            // the line does not read as a DSN that names no database.
            (
                "postgres://db.internal/permesi/",
                "postgres://db.internal/REDACTED",
            ),
        ] {
            assert_eq!(loggable_dsn(dsn), shown, "{dsn}");
        }
    }

    /// In a `postgres` URL the parser keeps `;`, `&`, `=`, `,` and percent-escapes in the
    /// host as written, and sqlx accepts every one of these. Nothing of such a value is
    /// shown; neither is one holding a character the parser would silently remove.
    #[test]
    fn loggable_dsn_shows_nothing_of_a_host_that_is_not_a_host_name() {
        for dsn in [
            "postgres://db.internal;password=host-secret",
            "postgres://app:userinfo-pw@db.internal;password=host-secret/permesi",
            "postgres://db.internal&sslmode=require&password=host-secret",
            "postgres://db.internal,password=host-secret/permesi",
            "postgres://db.internal=host-secret/permesi",
            "postgres://user%3Ahost-secret%40db.internal:5432/permesi",
            "postgres://db.internal%3Fpassword=host-secret",
            "postgres://db.internal%2Fpermesi%3Fpassword=host-secret",
            "postgres://db.internal%23host-secret",
            "postgres://db.internal\u{200b}host-secret/permesi",
            "postgres://db.internal\u{ad}host-secret/permesi",
        ] {
            assert_eq!(loggable_dsn(dsn), "invalid-dsn", "{dsn}");
        }
    }

    /// A known setting is shown only with a value that setting can take, so a secret
    /// placed in one is hidden with the unknown parameters.
    #[test]
    fn loggable_dsn_shows_a_known_setting_only_with_a_value_it_can_take() {
        for (dsn, shown) in [
            (
                "postgres://db.internal/permesi?sslmode=sslmode-secret",
                "postgres://db.internal/permesi?REDACTED",
            ),
            (
                "postgres://db.internal/permesi?port=port-secret&connect_timeout=timeout-secret",
                "postgres://db.internal/permesi?REDACTED",
            ),
            (
                "postgres://db.internal/permesi?sslmode=disable&port=5433",
                "postgres://db.internal/permesi?sslmode=disable&port=5433",
            ),
        ] {
            let logged = loggable_dsn(dsn);
            assert_eq!(logged, shown, "{dsn}");
            assert!(!logged.contains("secret"), "{dsn}");
        }
    }

    /// Each of these is accepted by sqlx or is a plausible slip, and each moves part of a
    /// secret to where a URL parser reports a path, a parameter name or the value of a
    /// harmless parameter. The logged form is rebuilt from checked parts, so none shows.
    #[test]
    fn loggable_dsn_shows_no_secret_that_slipped_out_of_the_userinfo_or_a_value() {
        for (dsn, shown) in [
            // An unencoded `&` in a password makes its tail a parameter name.
            (
                "postgres://db.internal:5432/permesi?password=first-half&second-half-secret",
                "postgres://db.internal:5432/permesi?REDACTED",
            ),
            // A bare secret after `?`.
            (
                "postgres://db.internal:5432/permesi?bare-secret",
                "postgres://db.internal:5432/permesi?REDACTED",
            ),
            // `;` as a separator, and a conninfo string inside a known parameter.
            (
                "postgres://db.internal:5432/permesi?sslmode=verify-full;password=semi-secret-pw",
                "postgres://db.internal:5432/permesi?REDACTED",
            ),
            (
                "postgres://db.internal:5432/permesi?dbname=permesi%20password=conninfo-secret-pw",
                "postgres://db.internal:5432/permesi?REDACTED",
            ),
            // A `/` or `?` before the `@` ends the authority early.
            (
                "postgres://app/slash-in-userinfo-secret@db.internal:5432/permesi",
                "postgres://app/REDACTED",
            ),
            (
                "postgres://app:5432/slash-after-digits-secret@db.internal:5432/permesi",
                "postgres://app:5432/REDACTED",
            ),
            (
                "postgres://app:5432?qmark-after-digits-secret@db.internal:5432/permesi",
                "postgres://app:5432?REDACTED",
            ),
            (
                "postgres://db.internal/permesi;path_token=matrix-secret",
                "postgres://db.internal/REDACTED",
            ),
        ] {
            let logged = loggable_dsn(dsn);
            assert_eq!(logged, shown, "{dsn}");
            assert!(!logged.contains("secret"), "{dsn}");
        }
    }

    /// sqlx accepts a DSN written without `//`, and anything with a colon parses as a URL
    /// of some scheme. In both the secret sits where no URL accessor reports a password,
    /// so nothing of such a value is shown.
    #[test]
    fn loggable_dsn_shows_nothing_of_a_value_that_is_not_a_postgres_url() {
        for dsn in [
            "postgres:app:dsn-password@db.internal:5432/permesi",
            "postgres:/app:dsn-password@db.internal:5432/permesi",
            "postgresql:dsn-password",
            "vault:v1:dsn-password",
            "https://app:dsn-password@db.internal/permesi",
            "host=db password=dsn-password",
            "dsn-password",
            "",
            // A parser drops tabs and line breaks and would join the next line to the name.
            "postgres://db.internal/permesi\ndsn-password",
            "postgres://db.internal/permesi\tdsn-password",
            "postgres://db.internal/permesi dsn-password",
            "postgres://db.internal/permesi?sslmode=require\u{0}dsn-password",
        ] {
            assert_eq!(loggable_dsn(dsn), "invalid-dsn", "{dsn}");
        }
    }

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
