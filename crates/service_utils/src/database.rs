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
//! Every connection also starts with a `statement_timeout` and a `lock_timeout`.
//! PostgreSQL's own default for both is no limit, so a statement that hangs, or one
//! queued behind a lock nobody releases, would hold its pool connection until
//! something else gave up. The pool sets both right after connecting, which covers
//! reconnects and every code path that never thought about a deadline. A transaction
//! that needs a different bound sets its own with `SET LOCAL`; that still overrides the
//! session value for that transaction only.
//!
//! Flow Overview: [`begin`] acquires a connection in the caller, then completes
//! BEGIN in an owned task. Cancelling the caller cannot interrupt `SQLx` before it
//! tracks the server transaction. An abandoned task result drops the tracked
//! transaction and schedules rollback before the connection can be reused.

use anyhow::{Result, bail};
use sqlx::{
    PgPool, Postgres, Transaction,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use std::{
    fmt,
    net::{IpAddr, ToSocketAddrs},
    str::FromStr,
    time::Duration,
};
use tracing::warn;

/// Upper bound on `max_connections` for one process.
pub const MAX_CONNECTIONS_LIMIT: u32 = 200;
const ACQUIRE_TIMEOUT_MIN: Duration = Duration::from_millis(100);
const ACQUIRE_TIMEOUT_MAX: Duration = Duration::from_secs(30);
const IDLE_TIMEOUT_MIN: Duration = Duration::from_secs(10);
const MAX_LIFETIME_MIN: Duration = Duration::from_mins(1);
const MAX_LIFETIME_MAX: Duration = Duration::from_hours(24);

/// Session `statement_timeout` both services start from (`--db-statement-timeout-ms`).
pub const DEFAULT_STATEMENT_TIMEOUT: Duration = Duration::from_secs(30);
/// Session `lock_timeout` both services start from (`--db-lock-timeout-ms`).
pub const DEFAULT_LOCK_TIMEOUT: Duration = Duration::from_secs(5);
const SESSION_TIMEOUT_MIN: Duration = Duration::from_millis(100);
const STATEMENT_TIMEOUT_MAX: Duration = Duration::from_mins(10);
const LOCK_TIMEOUT_MAX: Duration = Duration::from_mins(1);

/// Longest wait for pooled connections to close during shutdown.
pub const POOL_CLOSE_TIMEOUT: Duration = Duration::from_secs(4);

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
    statement_timeout: Duration,
    lock_timeout: Duration,
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
            statement_timeout: DEFAULT_STATEMENT_TIMEOUT,
            lock_timeout: DEFAULT_LOCK_TIMEOUT,
        })
    }

    /// Replace the session timeouts every pooled connection starts with.
    ///
    /// # Errors
    /// Returns an error when a value is outside its range or the lock timeout exceeds
    /// the statement timeout, which would let the statement limit fire first and hide
    /// that the wait was for a lock. Neither can be switched off.
    pub fn with_session_timeouts(
        mut self,
        statement_timeout: Duration,
        lock_timeout: Duration,
    ) -> Result<Self> {
        if !(SESSION_TIMEOUT_MIN..=STATEMENT_TIMEOUT_MAX).contains(&statement_timeout) {
            bail!("statement timeout must be between 100 ms and 10 min");
        }
        if !(SESSION_TIMEOUT_MIN..=LOCK_TIMEOUT_MAX).contains(&lock_timeout) {
            bail!("lock timeout must be between 100 ms and 60 s");
        }
        if lock_timeout > statement_timeout {
            bail!("lock timeout must not exceed the statement timeout");
        }
        self.statement_timeout = statement_timeout;
        self.lock_timeout = lock_timeout;
        Ok(self)
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

    #[must_use]
    pub const fn statement_timeout(&self) -> Duration {
        self.statement_timeout
    }

    #[must_use]
    pub const fn lock_timeout(&self) -> Duration {
        self.lock_timeout
    }

    /// Translate this configuration into sqlx pool options, setting every option.
    ///
    /// The session timeouts are applied in the pool's `after_connect` hook, not as
    /// startup parameters: a connection pooler in front of PostgreSQL commonly refuses
    /// the `options` startup parameter, and the hook also runs for every reconnect. A
    /// connection whose timeouts could not be set is not handed out.
    #[must_use]
    pub fn pool_options(&self) -> PgPoolOptions {
        let statement = format!("{}ms", self.statement_timeout.as_millis());
        let lock = format!("{}ms", self.lock_timeout.as_millis());
        PgPoolOptions::new()
            .max_connections(self.max_connections)
            .min_connections(self.min_connections)
            .acquire_timeout(self.acquire_timeout)
            .idle_timeout(self.idle_timeout)
            .max_lifetime(self.max_lifetime)
            .test_before_acquire(true)
            .after_connect(move |connection, _metadata| {
                let (statement, lock) = (statement.clone(), lock.clone());
                Box::pin(async move {
                    sqlx::query(
                        "SELECT set_config('statement_timeout', $1, false), \
                         set_config('lock_timeout', $2, false)",
                    )
                    .bind(statement)
                    .bind(lock)
                    .execute(connection)
                    .await
                    .map(|_| ())
                })
            })
    }

    /// Connect a pool to a checked [`ConnectionTarget`]; its connections report
    /// `application_name` to PostgreSQL.
    ///
    /// The target is the one the transport policy was decided on, so the pool cannot
    /// connect anywhere else. Errors never include the DSN or the credentials.
    ///
    /// # Errors
    /// Returns an error if the initial connections fail.
    pub async fn connect(
        &self,
        target: ConnectionTarget,
        application_name: &str,
    ) -> Result<PgPool> {
        let options = target.options.application_name(application_name);
        // A pinned name is tried at each loopback address it resolved to, in turn, as
        // the driver would have tried them: a server listening on `::1` only must stay
        // reachable through `localhost`. Only an address that did not answer moves on
        // to the next; any other answer is the server's. Each address can take up to
        // the acquire timeout.
        let mut attempts: Vec<PgConnectOptions> = target
            .loopback_candidates
            .iter()
            .map(|address| options.clone().hostaddr(*address))
            .collect();
        if attempts.is_empty() {
            attempts.push(options);
        }
        let last = attempts.len().saturating_sub(1);
        let mut failure = None;
        for (index, attempt) in attempts.into_iter().enumerate() {
            match self.pool_options().connect_with(attempt).await {
                Ok(pool) => return Ok(pool),
                // The pool retries a refused connection until its acquire timeout and
                // then reports the timeout, so both mean the address did not answer.
                Err(error @ (sqlx::Error::Io(_) | sqlx::Error::PoolTimedOut)) if index < last => {
                    failure = Some(error);
                }
                Err(error) => {
                    failure = Some(error);
                    break;
                }
            }
        }
        let failure = failure.map_or_else(
            || "connection failed".to_string(),
            |error| connection_failure(&error),
        );
        Err(anyhow::anyhow!("Failed to connect to database: {failure}"))
    }
}

/// What went wrong connecting, without the driver's or the server's text: a message
/// from PostgreSQL can quote a setting value taken from the DSN, and an I/O error can
/// name the address. The SQLSTATE is enough to look the failure up.
fn connection_failure(error: &sqlx::Error) -> String {
    match error {
        sqlx::Error::Database(database) => {
            format!(
                "the server refused the connection (SQLSTATE {})",
                shown_sqlstate(database.code().as_deref())
            )
        }
        sqlx::Error::Io(io) => format!("network error ({:?})", io.kind()),
        sqlx::Error::Tls(_) => "TLS negotiation or certificate verification failed".to_string(),
        sqlx::Error::PoolTimedOut => "timed out waiting for a connection".to_string(),
        sqlx::Error::Protocol(_) => "protocol error".to_string(),
        sqlx::Error::Configuration(_) => "invalid connection settings".to_string(),
        _ => "connection failed".to_string(),
    }
}

/// A SQLSTATE as sent by the peer, if it is one: five ASCII capitals or digits. The
/// driver stores whatever text the peer put in that field, so anything else is not shown.
fn shown_sqlstate(code: Option<&str>) -> &str {
    code.filter(|code| {
        code.len() == 5
            && code
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    })
    .unwrap_or("unknown")
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
        "port" | "connect_timeout" => {
            !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
        }
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

/// The DSN query parameters the driver acts on. It ignores any other, after logging
/// its name and value, so nothing else is accepted.
const ACCEPTED_DSN_PARAMETERS: [&str; 16] = [
    "sslmode",
    "ssl-mode",
    "sslrootcert",
    "ssl-root-cert",
    "ssl-ca",
    "sslcert",
    "ssl-cert",
    "sslkey",
    "ssl-key",
    "statement-cache-capacity",
    "host",
    "hostaddr",
    "port",
    "dbname",
    "application_name",
    "options",
];

/// A database connection that passed the transport policy, parsed once.
///
/// ## Flow Overview
/// 1. [`ConnectionTarget::parse`] checks the DSN text before the driver sees it: the
///    scheme, the host, and every query parameter. The driver logs an unknown parameter
///    with its value and repeats an invalid `sslmode` in its error, so a password typed
///    into the wrong place would reach the log; such a DSN is refused here with a
///    message that repeats none of it.
/// 2. The driver parses the DSN, `PG*` environment variables included, and the policy
///    is decided on the address it will dial, which `hostaddr` or `PGHOSTADDR` can make
///    different from the host.
/// 3. [`ConnectionTarget::with_credentials`] sets the user and password issued by
///    `OpenBao` on the typed options, and [`PoolConfig::connect`] connects with exactly
///    these options. Nothing is parsed a second time.
///
/// The policy: sqlx defaults to `sslmode=prefer`, which tries TLS, silently continues
/// without it when the server declines, and never checks the certificate, so anyone on
/// the path can read or answer for the database. A Unix socket and a loopback address
/// pass, since nothing leaves the machine. Any other address needs
/// `sslmode=verify-full` or `verify-ca`, unless the operator accepted the risk, as a
/// development cluster without database TLS does.
#[derive(Clone)]
pub struct ConnectionTarget {
    options: PgConnectOptions,
    relies_on_opt_out: bool,
    /// The loopback addresses a pinned `localhost` name resolved to, in the order they
    /// are tried; empty when the connection is not pinned.
    loopback_candidates: Vec<IpAddr>,
}

/// Shows nothing: the options hold the password once the credentials are set.
impl fmt::Debug for ConnectionTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectionTarget")
            .field("relies_on_opt_out", &self.relies_on_opt_out)
            .finish_non_exhaustive()
    }
}

impl ConnectionTarget {
    /// Check `dsn` and decide whether its connection may be made.
    ///
    /// # Errors
    /// Returns an error for a DSN that is malformed, names a parameter the driver does
    /// not act on, puts credentials in the query, or reaches an address that is not
    /// local without a verifying `sslmode` while `allow_unverified` is false. No message
    /// repeats any part of the DSN.
    pub fn parse(dsn: &str, allow_unverified: bool) -> Result<Self> {
        use sqlx::postgres::PgSslMode;
        let dial_address = checked_dsn(dsn)?;
        // The driver's own error can repeat a value, so it is not kept.
        let mut options = PgConnectOptions::from_str(&without_password_lookup(dsn))
            .map_err(|_| anyhow::anyhow!("Invalid database connection string"))?;
        // `PGDATABASE` and `PGOPTIONS` reach the startup packet without passing the DSN
        // checks; they are held to the same rule.
        if options
            .get_database()
            .is_some_and(|name| name.chars().any(char::is_control))
            || options
                .get_options()
                .is_some_and(|text| text.chars().any(char::is_control))
        {
            bail!("database settings hold a control character");
        }
        // The driver connects through a socket when one is named, or when its effective
        // host is a directory, which `PGHOST` or its own discovery can supply.
        let socket = options.get_socket().is_some() || options.get_host().starts_with('/');
        let verified = matches!(
            options.get_ssl_mode(),
            PgSslMode::VerifyFull | PgSslMode::VerifyCa
        );
        let mut loopback_candidates = Vec::new();
        let local = socket
            || match dial_address.or_else(environment_dial_address) {
                Some(address) => address.is_loopback(),
                None => match loopback_addresses(options.get_host(), options.get_port()) {
                    Some(addresses) => {
                        // The driver would resolve the name again for every connection,
                        // and a later answer could point anywhere. An unencrypted
                        // connection that is allowed for being local is pinned to a
                        // loopback address found now; the host still names the server.
                        // `PoolConfig::connect` tries each address found, as resolving
                        // the name would have, and keeps the one that answers.
                        if !verified {
                            if let Some(first) = addresses.first() {
                                options = options.hostaddr(*first);
                            }
                            loopback_candidates = addresses;
                        }
                        true
                    }
                    None => false,
                },
            };
        if !(local || verified || allow_unverified) {
            bail!(
                "database DSN reaches an address that is not local without \
                 sslmode=verify-full or verify-ca; add one, or accept an unverified \
                 connection explicitly with --db-allow-unverified-tls"
            )
        }
        Ok(Self {
            options,
            relies_on_opt_out: !(local || verified),
            loopback_candidates,
        })
    }

    /// Whether only the operator's opt-out let this connection through, so the caller
    /// can say so at every start.
    #[must_use]
    pub fn relies_on_opt_out(&self) -> bool {
        self.relies_on_opt_out
    }

    /// Set the user and password the pool connects with. They replace any userinfo of
    /// the DSN; the query cannot carry credentials at all.
    #[must_use]
    pub fn with_credentials(mut self, username: &str, password: &str) -> Self {
        self.options = self.options.username(username).password(password);
        self
    }
}

/// Checks the text of a DSN before the driver parses it and returns the `hostaddr` it
/// names, if any. The driver dials that address instead of the host.
fn checked_dsn(dsn: &str) -> Result<Option<IpAddr>> {
    const MALFORMED: &str = "Invalid database connection string";
    let dsn = dsn.trim();
    let authority = ["postgres://", "postgresql://"].iter().any(|prefix| {
        dsn.get(..prefix.len())
            .is_some_and(|start| start.eq_ignore_ascii_case(prefix))
    });
    if !authority || !dsn.bytes().all(|byte| byte.is_ascii_graphic()) {
        bail!(MALFORMED);
    }
    let parsed = url::Url::parse(dsn).map_err(|_| anyhow::anyhow!(MALFORMED))?;
    let plain = |text: &str, extra: &[u8]| {
        text.bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || extra.contains(&byte))
    };
    // A socket DSN has no host, or names the socket directory percent-encoded. An IP
    // literal is already parsed as one.
    let host_shaped = match parsed.host() {
        Some(url::Host::Domain(name)) => {
            plain(name, b"-_.")
                || (name.to_ascii_lowercase().starts_with("%2f") && plain(name, b"-_.%"))
        }
        _ => true,
    };
    if !host_shaped {
        bail!("database DSN host is not a host name, an IP address or a socket directory");
    }
    // Decoded text goes into the NUL-delimited startup packet; a control character there
    // could end one field and begin another.
    if decodes_to_control(parsed.path())
        || parsed
            .query_pairs()
            .any(|(key, value)| key.chars().chain(value.chars()).any(char::is_control))
    {
        bail!("database DSN has a control character in a decoded field");
    }
    let mut dial_address = None;
    for (key, value) in parsed.query_pairs() {
        match &*key {
            "user" | "password" => bail!(
                "database DSN carries credentials in its query; the service connects \
                 with the credentials OpenBao issues"
            ),
            "sslmode" | "ssl-mode"
                if !LOGGABLE_SSL_MODES.contains(&value.to_ascii_lowercase().as_str()) =>
            {
                bail!("database DSN has an sslmode that is not one PostgreSQL defines")
            }
            "port" | "statement-cache-capacity"
                if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) =>
            {
                bail!("database DSN has a numeric parameter that is not a number")
            }
            "hostaddr" => {
                dial_address =
                    Some(value.parse::<IpAddr>().map_err(|_| {
                        anyhow::anyhow!("database DSN hostaddr is not an IP address")
                    })?);
            }
            // The same shapes as a host in the authority: a name, an IP literal or a
            // socket directory. A comma is not a list of hosts to the driver.
            "host" if !host_value(&value) => {
                bail!("database DSN host is not a host name, an IP address or a socket directory")
            }
            // The driver ignores a bracketed option it cannot read, silently.
            key if key.starts_with("options[") => {
                let named = key
                    .strip_prefix("options[")
                    .and_then(|rest| rest.strip_suffix(']'))
                    .is_some_and(|name| !name.is_empty() && plain(name, b"-_."));
                if !named {
                    bail!("database DSN has an options[...] parameter without a setting name");
                }
            }
            key if ACCEPTED_DSN_PARAMETERS.contains(&key) => {}
            _ => bail!(
                "database DSN has a query parameter the service does not use; accepted \
                 are {}",
                ACCEPTED_DSN_PARAMETERS.join(", ")
            ),
        }
    }
    Ok(dial_address)
}

/// Whether a `host` query value is one the driver can use as the authority's host is: a
/// host name, an IP literal, or an absolute socket directory, which may hold any
/// character but a control character. The driver reads a comma or an appended port as
/// part of a name, so neither is accepted.
fn host_value(value: &str) -> bool {
    if value.starts_with('/') {
        return !value.chars().any(char::is_control);
    }
    if value
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<IpAddr>()
        .is_ok()
    {
        return true;
    }
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
}

/// Whether URL text, once its percent-escapes are decoded, holds a control character.
fn decodes_to_control(text: &str) -> bool {
    let mut bytes = Vec::with_capacity(text.len());
    let mut rest = text.as_bytes();
    while let Some((&first, tail)) = rest.split_first() {
        let escaped = match tail {
            [high, low, ..] if first == b'%' => std::str::from_utf8(&[*high, *low])
                .ok()
                .and_then(|hex| u8::from_str_radix(hex, 16).ok()),
            _ => None,
        };
        if let (Some(byte), Some(after)) = (escaped, tail.get(2..)) {
            bytes.push(byte);
            rest = after;
        } else {
            bytes.push(first);
            rest = tail;
        }
    }
    String::from_utf8_lossy(&bytes)
        .chars()
        .any(char::is_control)
}

/// The DSN as given, with a placeholder password added for the driver's parser when it
/// has none. Without a password the driver reads the password file while parsing, and
/// logs a malformed line of that file whole. The placeholder goes into the query, which a
/// hostless socket DSN has as well; a `password` there from the operator was refused by
/// [`checked_dsn`]. The services always replace the password with the one OpenBao
/// issues before connecting.
fn without_password_lookup(dsn: &str) -> String {
    let dsn = dsn.trim();
    let Ok(mut url) = url::Url::parse(dsn) else {
        return dsn.to_string();
    };
    // A DSN that carries a password keeps it, and the driver then reads no file.
    if url.password().is_none() {
        url.query_pairs_mut()
            .append_pair("password", "replaced-before-connecting");
    }
    url.into()
}

/// The dial address the driver takes from the environment when the DSN names none.
fn environment_dial_address() -> Option<IpAddr> {
    std::env::var("PGHOSTADDR").ok()?.parse().ok()
}

/// The loopback addresses a host the driver would resolve stays on, if it stays on this
/// machine: a loopback address itself, or `localhost` or a name under it that resolves,
/// here and now, to loopback addresses only. The spelling alone is not enough, since a
/// resolver can map such a name anywhere. IPv4 addresses come first.
fn loopback_addresses(host: &str, port: u16) -> Option<Vec<IpAddr>> {
    loopback_addresses_with(host, port, |name, port| {
        (name, port)
            .to_socket_addrs()
            .map_or_default(|addresses| addresses.map(|address| address.ip()).collect())
    })
}

/// [`loopback_addresses`] with the resolver passed in, so the rule can be tested against
/// answers this machine's resolver would never give.
fn loopback_addresses_with(
    host: &str,
    port: u16,
    resolve: impl Fn(&str, u16) -> Vec<IpAddr>,
) -> Option<Vec<IpAddr>> {
    let name = host.trim_end_matches('.').to_ascii_lowercase();
    if let Ok(address) = name
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<IpAddr>()
    {
        return address.is_loopback().then(|| vec![address]);
    }
    if name != "localhost" && !name.ends_with(".localhost") {
        return None;
    }
    let mut addresses = resolve(&name, port);
    if addresses.is_empty() || !addresses.iter().all(IpAddr::is_loopback) {
        return None;
    }
    // IPv4 first, as it is more often the address a database listens on; the rest
    // keep the resolver's order. Duplicates, one per socket type, are dropped.
    addresses.sort_by_key(|address| !address.is_ipv4());
    addresses.dedup();
    Some(addresses)
}

/// One-line summary for startup logs.
impl fmt::Display for PoolConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "max={} min={} acquire={}ms idle={}s lifetime={}s statement={}ms lock={}ms",
            self.max_connections,
            self.min_connections,
            self.acquire_timeout.as_millis(),
            self.idle_timeout.as_secs(),
            self.max_lifetime.as_secs(),
            self.statement_timeout.as_millis(),
            self.lock_timeout.as_millis()
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
    use super::{ConnectionTarget, PoolConfig, loggable_dsn};
    use sqlx::ConnectOptions;
    use std::{
        io,
        sync::{Arc, Mutex},
        time::Duration,
    };

    const PG_ENV: [&str; 7] = [
        "PGHOST",
        "PGHOSTADDR",
        "PGSSLMODE",
        "PGSSLROOTCERT",
        "PGPORT",
        "PGUSER",
        "PGPASSWORD",
    ];

    fn refusal(dsn: &str, allow_unverified: bool) -> Option<String> {
        ConnectionTarget::parse(dsn, allow_unverified)
            .err()
            .map(|error| format!("{error:#}"))
    }

    /// `sslmode=prefer`, the default, falls back to clear text and verifies nothing. Off
    /// the local machine only a verifying mode is accepted unless the operator opted in.
    #[test]
    fn unverified_database_tls_is_refused_off_the_local_machine() {
        temp_env::with_vars_unset(PG_ENV, || {
            for dsn in [
                "postgres://app@db.internal/permesi?sslmode=verify-full",
                "postgres://app@db.internal:5432/permesi?sslmode=verify-ca",
                "postgres://app@10.0.0.7/permesi?sslmode=verify-full&sslrootcert=/etc/ssl/ca.pem",
                "postgres://app@localhost/permesi",
                "postgres://app@LOCALHOST.:5432/permesi?sslmode=disable",
                "postgres://app@127.0.0.1:5432/permesi",
                "postgres://app@[::1]:5432/permesi",
                "postgres:///permesi?host=/var/run/postgresql",
                "postgres://app@%2Fvar%2Frun%2Fpostgresql/permesi",
            ] {
                assert_eq!(refusal(dsn, false), None, "{dsn}");
                // Nothing had to be waived, so nothing is announced.
                assert!(
                    ConnectionTarget::parse(dsn, true)
                        .is_ok_and(|target| !target.relies_on_opt_out()),
                    "{dsn}"
                );
            }
            for dsn in [
                "postgres://app@db.internal/permesi",
                "postgres://app:dsn-secret@db.internal:5432/permesi?sslmode=prefer",
                "postgres://app@db.internal/permesi?sslmode=require",
                "postgres://app@db.internal/permesi?sslmode=allow",
                "postgres://app@db.internal/permesi?sslmode=disable",
                "postgres://app@10.0.0.7/permesi",
                "postgres://app@[2001:db8::7]/permesi?sslmode=require",
                // Names that only look local.
                "postgres://app@localhost.example.com/permesi",
                "postgres://app@127.0.0.1.example.com/permesi",
                // The query can move the connection away from the host in the authority.
                "postgres://app@localhost/permesi?host=db.internal",
            ] {
                let refused = refusal(dsn, false);
                assert!(
                    refused.as_ref().is_some_and(
                        |error| error.contains("verify-full") && !error.contains("dsn-secret")
                    ),
                    "{dsn}: {refused:?}"
                );
                assert!(
                    ConnectionTarget::parse(dsn, true)
                        .is_ok_and(|target| target.relies_on_opt_out()),
                    "{dsn}"
                );
            }
            assert!(refusal("not a dsn", true).is_some());
        });
        // The pool honours PGSSLMODE, so the decision does too.
        temp_env::with_vars(
            [("PGSSLMODE", Some("verify-full")), ("PGHOST", None)],
            || assert_eq!(refusal("postgres://app@db.internal/permesi", false), None),
        );
    }

    /// The driver dials `hostaddr`, or `PGHOSTADDR`, when one is set, and the host only
    /// names the certificate. The check looked at the host, so a DSN that said
    /// `localhost` could connect anywhere without TLS. The decision is now about the
    /// address that is dialed, and it is the one the driver reports.
    #[test]
    fn dial_address_decides_what_is_local_not_the_host_name() {
        let driver_dials = |target: &ConnectionTarget| {
            target
                .options
                .to_url_lossy()
                .query_pairs()
                .find(|(key, _)| key == "hostaddr")
                .map(|(_, value)| value.into_owned())
        };
        temp_env::with_vars_unset(PG_ENV, || {
            for dsn in [
                "postgres://app@localhost/permesi?hostaddr=198.51.100.9",
                "postgres://app@localhost/permesi?hostaddr=198.51.100.9&sslmode=disable",
                "postgres://app@127.0.0.1/permesi?hostaddr=2001:db8::9",
                "postgres://app@[::1]/permesi?hostaddr=127.0.0.1&hostaddr=198.51.100.9",
            ] {
                let refused = refusal(dsn, false);
                assert!(
                    refused
                        .as_ref()
                        .is_some_and(|error| error.contains("verify-full")),
                    "{dsn}: {refused:?}"
                );
            }
            // The other way round: a remote name dialed on loopback stays on the machine.
            for (dsn, dialed) in [
                (
                    "postgres://app@db.internal/permesi?hostaddr=127.0.0.1",
                    "127.0.0.1",
                ),
                ("postgres://app@db.internal/permesi?hostaddr=::1", "::1"),
                (
                    "postgres://app@db.internal/permesi?hostaddr=198.51.100.9&hostaddr=127.0.0.1",
                    "127.0.0.1",
                ),
            ] {
                let target = ConnectionTarget::parse(dsn, false);
                assert_eq!(
                    target.as_ref().ok().and_then(driver_dials).as_deref(),
                    Some(dialed),
                    "{dsn}"
                );
            }
            for dsn in [
                "postgres://app@localhost/permesi?hostaddr=db.internal",
                "postgres://app@localhost/permesi?hostaddr=",
            ] {
                assert!(
                    refusal(dsn, true).is_some_and(|error| error.contains("hostaddr")),
                    "{dsn}"
                );
            }
        });
        temp_env::with_vars(
            [
                ("PGHOSTADDR", Some("198.51.100.9")),
                ("PGHOST", None),
                ("PGSSLMODE", None),
            ],
            || {
                let dsn = "postgres://app@localhost/permesi";
                assert!(refusal(dsn, false).is_some_and(|error| error.contains("verify-full")));
                let target = ConnectionTarget::parse(dsn, true);
                assert_eq!(
                    target.as_ref().ok().and_then(driver_dials).as_deref(),
                    Some("198.51.100.9"),
                    "the check and the driver read the same variable"
                );
                // The DSN's own address wins over the environment, as in the driver.
                assert_eq!(
                    refusal(
                        "postgres://app@db.internal/permesi?hostaddr=127.0.0.1",
                        false
                    ),
                    None
                );
            },
        );
    }

    /// A `localhost` name is local only if every address it resolves to is loopback.
    /// This machine's resolver maps every such name to loopback, which hid a check that
    /// trusted the spelling; here the resolver gives the answers a hostile one could.
    #[test]
    fn localhost_names_are_local_only_when_they_resolve_to_loopback() {
        use super::loopback_addresses_with;
        use std::net::IpAddr;
        let answers = |answer: &'static [&'static str]| {
            move |_: &str, _: u16| {
                answer
                    .iter()
                    .filter_map(|address| address.parse::<IpAddr>().ok())
                    .collect::<Vec<_>>()
            }
        };
        for (host, answer, local) in [
            ("localhost", &["127.0.0.1", "::1"][..], true),
            ("db.localhost.", &["127.0.0.5"], true),
            ("localhost", &["198.51.100.9"], false),
            ("db.localhost", &["127.0.0.1", "198.51.100.9"], false),
            ("db.localhost", &[], false),
            // Not a localhost name: never treated as local, whatever it resolves to.
            ("localhost.example.com", &["127.0.0.1"], false),
            ("db.internal", &["127.0.0.1"], false),
            // An address literal is decided without asking the resolver.
            ("[::1]", &["198.51.100.9"], true),
            ("198.51.100.9", &["127.0.0.1"], false),
        ] {
            let found = loopback_addresses_with(host, 5432, answers(answer));
            assert_eq!(found.is_some(), local, "{host} -> {answer:?}");
            assert!(
                found.is_none_or(|addresses| addresses.iter().all(std::net::IpAddr::is_loopback)),
                "{host}"
            );
        }
    }

    /// A loopback name is pinned to the address it resolved to when nothing else protects
    /// the connection; the driver would otherwise resolve it again for every connection.
    /// A directory as the effective host is a socket, as it is to the driver. Credentials
    /// placed so the driver does not read a password file are always replaced.
    #[test]
    fn local_connections_are_pinned_and_socket_hosts_are_local() -> anyhow::Result<()> {
        let dialed = |target: &ConnectionTarget| {
            target
                .options
                .to_url_lossy()
                .query_pairs()
                .find(|(key, _)| key == "hostaddr")
                .map(|(_, value)| value.into_owned())
        };
        temp_env::with_vars_unset(PG_ENV, || -> anyhow::Result<()> {
            let unencrypted = ConnectionTarget::parse("postgres://app@localhost/permesi", false)?;
            assert!(
                dialed(&unencrypted).is_some_and(|address| {
                    address
                        .parse::<std::net::IpAddr>()
                        .is_ok_and(|ip| ip.is_loopback())
                }),
                "{:?}",
                dialed(&unencrypted)
            );
            let verified = ConnectionTarget::parse(
                "postgres://app@localhost/permesi?sslmode=verify-full",
                false,
            )?;
            assert_eq!(
                dialed(&verified),
                None,
                "a verified connection needs no pin"
            );
            let literal = ConnectionTarget::parse("postgres://app@127.0.0.1/permesi", false)?;
            assert_eq!(dialed(&literal).as_deref(), Some("127.0.0.1"));
            Ok(())
        })?;
        temp_env::with_vars(
            [
                ("PGHOST", Some("/var/run/postgresql")),
                ("PGHOSTADDR", None),
                ("PGSSLMODE", None),
            ],
            || assert_eq!(refusal("postgres:///permesi", false), None),
        );
        Ok(())
    }

    /// Pinning `localhost` to one address broke a server listening on `::1` only: the
    /// driver used to try every address the name resolved to. Each address found is
    /// tried in turn now. The listener here speaks no PostgreSQL; reaching it at all,
    /// after `127.0.0.1` refused, is what is checked.
    #[tokio::test]
    async fn a_pinned_localhost_still_reaches_a_server_on_ipv6_loopback_only() -> anyhow::Result<()>
    {
        use std::net::ToSocketAddrs;
        let Ok(listener) = tokio::net::TcpListener::bind("[::1]:0").await else {
            eprintln!("IPv6 loopback is not available on this host");
            return Ok(());
        };
        let port = listener.local_addr()?.port();
        let resolves_both = ("localhost", port)
            .to_socket_addrs()
            .is_ok_and(|addresses| {
                let addresses: Vec<_> = addresses.map(|address| address.ip()).collect();
                addresses.iter().any(std::net::IpAddr::is_ipv4)
                    && addresses.iter().any(std::net::IpAddr::is_ipv6)
            });
        anyhow::ensure!(
            resolves_both,
            "this test needs localhost to resolve to both 127.0.0.1 and ::1"
        );
        let reached = tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            drop(stream);
            anyhow::Ok(())
        });
        let target = temp_env::with_vars_unset(PG_ENV, || {
            ConnectionTarget::parse(&format!("postgres://app@localhost:{port}/permesi"), false)
        })?;
        assert_eq!(
            target
                .loopback_candidates
                .first()
                .map(std::net::IpAddr::is_ipv4),
            Some(true)
        );
        let pool = PoolConfig::new(
            1,
            0,
            Duration::from_secs(3),
            Duration::from_secs(60),
            Duration::from_mins(5),
        )?;
        let failed = pool.connect(target, "pin-fallback").await;
        assert!(failed.is_err(), "the listener speaks no PostgreSQL");
        tokio::time::timeout(Duration::from_secs(5), reached)
            .await
            .map_err(|_| anyhow::anyhow!("::1 was never tried after 127.0.0.1 refused"))???;
        Ok(())
    }

    /// The driver reads the password file while parsing a DSN without a password, and
    /// logs a malformed line of it whole. Such a line can hold a real password.
    #[test]
    fn the_password_file_is_not_read() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        const MARKER: &str = "s3cr3tmarker";
        let file = std::env::temp_dir().join(format!("pgpass-{}", uuid::Uuid::new_v4()));
        std::fs::write(&file, format!("localhost:5432:*:app\\:{MARKER}\n"))?;
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600))?;
        let captured = Captured::default();
        let writer = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(move || writer.clone())
            .finish();
        let path = file.to_string_lossy().into_owned();
        tracing::subscriber::with_default(subscriber, || {
            temp_env::with_vars(
                [
                    ("PGPASSFILE", Some(path.as_str())),
                    ("PGPASSWORD", None),
                    ("PGHOST", None),
                    ("PGHOSTADDR", None),
                    ("PGSSLMODE", None),
                ],
                || {
                    for dsn in [
                        "postgres://app@localhost/permesi",
                        "postgres://localhost/permesi",
                        // A socket DSN has no authority to hold a password.
                        "postgres:///permesi?host=/var/run/postgresql",
                        "postgres:///permesi",
                    ] {
                        assert!(ConnectionTarget::parse(dsn, false).is_ok(), "{dsn}");
                    }
                },
            );
        });
        std::fs::remove_file(&file)?;
        let logged = captured
            .0
            .lock()
            .map_or_else(|_| Vec::new(), |buffer| buffer.clone());
        let logged = String::from_utf8_lossy(&logged);
        assert!(!logged.contains(MARKER), "logged: {logged}");
        Ok(())
    }

    /// Decoded fields end up in the NUL-delimited startup packet. A host in the query is
    /// held to the same shapes as one in the authority, a bracketed option needs a name,
    /// and the TLS mode is matched in any case, as the driver does.
    #[test]
    fn decoded_fields_and_query_hosts_are_checked_like_the_authority() {
        temp_env::with_vars_unset(PG_ENV, || {
            for dsn in [
                "postgres://app@localhost/perm%00esi",
                "postgres://app@localhost/permesi%0Aforged",
                "postgres://app@localhost/permesi?options=-c%00x",
                "postgres://app@localhost/permesi?application_name=a%1Fb",
                "postgres://app@localhost/permesi?host=db.internal,localhost",
                "postgres://app@localhost/permesi?host=db;password=x",
                "postgres://app@localhost/permesi?options[=x",
                "postgres://app@localhost/permesi?options[]=x",
                "postgres://app@localhost/permesi?options[search_path=x",
                // A control outside ASCII, escaped in the path.
                "postgres://app@localhost/perm%C2%85esi",
                "postgres://app@localhost/permesi?host=",
                "postgres://app@localhost/permesi?host=db.internal:5432",
                "postgres://app@localhost/permesi?host=/var/run/post%0Agres",
            ] {
                assert!(refusal(dsn, true).is_some(), "{dsn}");
            }
            for dsn in [
                "postgres://app@localhost/permesi?host=/var/run/postgresql",
                // A socket directory may hold a space, as in the authority form.
                "postgres://app@localhost/permesi?host=/run/my%20postgres",
                "postgres://app@%2Frun%2Fmy%20postgres/permesi",
                "postgres://app@localhost/permesi?host=[::1]",
                "postgres://app@db.internal/permesi?sslmode=VERIFY-FULL",
                "postgres://app@db.internal/permesi?ssl-mode=Verify-Ca",
            ] {
                assert_eq!(refusal(dsn, false), None, "{dsn}");
            }
        });
    }

    /// A SQLSTATE field is shown only in its defined form; a peer can put any text there.
    #[test]
    fn only_a_well_formed_sqlstate_is_shown() {
        use super::shown_sqlstate;
        for (code, shown) in [
            (Some("22023"), "22023"),
            (Some("57P01"), "57P01"),
            (Some("2202"), "unknown"),
            (Some("220234"), "unknown"),
            (Some("22o23"), "unknown"),
            (Some("s3cr3tmarker"), "unknown"),
            (Some("2202\n"), "unknown"),
            (None, "unknown"),
        ] {
            assert_eq!(shown_sqlstate(code), shown, "{code:?}");
        }
    }

    /// The path is decoded before its control characters are looked for, escapes for
    /// characters outside ASCII included. The database-name check after parsing would
    /// also refuse these, so this checks the first line of defence on its own.
    #[test]
    fn escaped_control_characters_are_found_after_decoding() {
        use super::decodes_to_control;
        for text in [
            "/perm%00esi",
            "/perm%0Aesi",
            "/perm%7Fesi",
            "/perm%C2%85esi",
            "/%c2%9f",
        ] {
            assert!(decodes_to_control(text), "{text}");
        }
        for text in [
            "/permesi",
            "/perm%20esi",
            "/caf%C3%A9",
            "/100%",
            "/%zz",
            "/%4",
        ] {
            assert!(!decodes_to_control(text), "{text}");
        }
    }

    /// The connection error carries the kind of failure and nothing of its text.
    #[test]
    fn connection_failures_name_no_value() {
        use super::connection_failure;
        const MARKER: &str = "s3cr3tmarker";
        for (error, says) in [
            (
                sqlx::Error::Configuration(MARKER.into()),
                "invalid connection settings",
            ),
            (sqlx::Error::Protocol(MARKER.to_string()), "protocol error"),
            (
                sqlx::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    MARKER,
                )),
                "ConnectionRefused",
            ),
            (sqlx::Error::Tls(MARKER.into()), "TLS"),
            (sqlx::Error::PoolTimedOut, "timed out"),
        ] {
            let shown = connection_failure(&error);
            assert!(shown.contains(says) && !shown.contains(MARKER), "{shown}");
        }
    }

    /// Collects what is logged while a closure runs.
    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl io::Write for Captured {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if let Ok(mut buffer) = self.0.lock() {
                buffer.extend_from_slice(bytes);
            }
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// The driver logs a parameter it does not know with its value, and repeats an
    /// invalid `sslmode` in its error. A password in the wrong place took either path
    /// into the log. Such a DSN is now refused before the driver sees it, and neither the
    /// error nor anything logged repeats a name or a value from it.
    #[test]
    fn unsupported_dsn_is_refused_without_repeating_any_of_it() {
        const MARKER: &str = "s3cr3tmarker";
        let captured = Captured::default();
        let writer = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(move || writer.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            temp_env::with_vars_unset(PG_ENV, || {
                for dsn in [
                    format!("postgres://app@localhost/permesi?sslpassword={MARKER}"),
                    format!("postgres://app@localhost/permesi?{MARKER}=1"),
                    format!("postgres://app@localhost/permesi?connect_timeout={MARKER}"),
                    format!("postgres://app@localhost/permesi?sslmode={MARKER}"),
                    format!("postgres://app@localhost/permesi?ssl-mode={MARKER}"),
                    format!("postgres://app@localhost/permesi?port={MARKER}"),
                    format!("postgres://app@localhost/permesi?statement-cache-capacity={MARKER}"),
                    format!("postgres://app@localhost/permesi?hostaddr={MARKER}"),
                    format!("postgres://app@localhost/permesi?password={MARKER}"),
                    format!("postgres://app@localhost/permesi?user={MARKER}"),
                    format!("postgres://app@localhost:{MARKER}/permesi"),
                    format!("postgres://app@db.internal,{MARKER}/permesi?sslmode=verify-full"),
                    format!("postgres://app@db.internal;password={MARKER}/permesi"),
                    format!("mysql://app:{MARKER}@localhost/permesi"),
                    format!("postgres://app@localhost/permesi?sslmode=disable \n{MARKER}"),
                ] {
                    for allow_unverified in [false, true] {
                        let refused = refusal(&dsn, allow_unverified);
                        assert!(
                            refused
                                .as_ref()
                                .is_some_and(|error| !error.contains(MARKER)),
                            "{dsn}: {refused:?}"
                        );
                    }
                }
                // The check names what is wrong, without the value. This is the check's own
                // message, not the driver's, whose error would repeat the value.
                for (dsn, says) in [
                    (
                        format!("postgres://app@localhost/permesi?sslmode={MARKER}"),
                        "sslmode",
                    ),
                    (
                        format!("postgres://app@localhost/permesi?{MARKER}=1"),
                        "query parameter",
                    ),
                    (
                        format!("postgres://app@localhost/permesi?password={MARKER}"),
                        "credentials",
                    ),
                ] {
                    let refused = refusal(&dsn, true).unwrap_or_default();
                    assert!(refused.contains(says), "{dsn}: {refused}");
                }
                // What the driver does act on is still accepted.
                for dsn in [
                    "postgres://app@localhost/permesi?sslmode=disable&application_name=x&port=5433",
                    "postgres://app@localhost/permesi?options=-c%20search_path%3Dpublic",
                    "postgres://app@localhost/permesi?options[search_path]=public",
                    "postgres://app@localhost/permesi?statement-cache-capacity=0&dbname=other",
                ] {
                    assert_eq!(refusal(dsn, false), None, "{dsn}");
                }
            });
        });
        let logged = captured
            .0
            .lock()
            .map_or_else(|_| Vec::new(), |buffer| buffer.clone());
        let logged = String::from_utf8_lossy(&logged);
        assert!(!logged.contains(MARKER), "logged: {logged}");
        assert!(
            !logged.contains("unrecognized"),
            "the driver saw a parameter it ignores: {logged}"
        );
    }

    /// The pool connects as the user OpenBao issued. A user or password in the DSN's
    /// userinfo is replaced, the query cannot carry any, and a socket DSN, which has no
    /// authority to put a user into, works like any other.
    #[test]
    fn issued_credentials_replace_those_of_the_dsn() -> anyhow::Result<()> {
        temp_env::with_vars_unset(PG_ENV, || -> anyhow::Result<()> {
            for dsn in [
                "postgres://dsn-user:dsn-password@localhost:5432/permesi",
                "postgres://localhost/permesi",
                "postgres:///permesi?host=/var/run/postgresql",
                "postgres:///permesi",
            ] {
                let target = ConnectionTarget::parse(dsn, false)?
                    .with_credentials("leased-user", "leased-pw");
                assert_eq!(target.options.get_username(), "leased-user", "{dsn}");
                let url = target.options.to_url_lossy();
                assert_eq!(url.password(), Some("leased%2Dpw"), "{dsn}");
                assert!(!format!("{target:?}").contains("leased"), "{dsn}");
            }
            Ok(())
        })
    }

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
            // A number is digits. Letters and digits, with no punctuation to give it
            // away, were shown as the port or the timeout.
            (
                "postgres://db.internal/permesi?port=ABC123&connect_timeout=ABCD",
                "postgres://db.internal/permesi?REDACTED",
            ),
            (
                "postgres://db.internal/permesi?port=&connect_timeout=30",
                "postgres://db.internal/permesi?connect_timeout=30&REDACTED",
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

    /// The session timeouts have defaults, are bounded on both sides, cannot be turned
    /// off, and keep the lock wait within the statement limit.
    #[test]
    fn session_timeouts_default_and_are_validated() -> anyhow::Result<()> {
        let config = config(10, 2, 3_000, 600, 1_800)?;
        assert_eq!(config.statement_timeout(), Duration::from_secs(30));
        assert_eq!(config.lock_timeout(), Duration::from_secs(5));
        assert_eq!(
            config.to_string(),
            "max=10 min=2 acquire=3000ms idle=600s lifetime=1800s statement=30000ms lock=5000ms"
        );

        let set = config.with_session_timeouts(Duration::from_secs(2), Duration::from_secs(2))?;
        assert_eq!(set.statement_timeout(), Duration::from_secs(2));
        assert_eq!(set.lock_timeout(), Duration::from_secs(2));

        for (statement_ms, lock_ms) in [
            (0, 5_000),
            (99, 99),
            (600_001, 5_000),
            (30_000, 0),
            (30_000, 60_001),
            (1_000, 1_001),
        ] {
            assert!(
                config
                    .with_session_timeouts(
                        Duration::from_millis(statement_ms),
                        Duration::from_millis(lock_ms)
                    )
                    .is_err(),
                "{statement_ms}/{lock_ms}"
            );
        }
        Ok(())
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
