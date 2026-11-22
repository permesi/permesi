//! Background renewal tasks for OpenBao tokens and database leases.
//!
//! This module keeps the application's access to OpenBao and the database valid
//! by renewing leases before they expire, and turns the two ways a lease can end
//! into an orderly restart while the credentials still work.
//!
//! Flow Overview:
//! 1. `try_renew` determines the connectivity mode (Agent vs Direct).
//! 2. In Direct (TCP) mode, it spawns a task to renew the application's OpenBao token.
//! 3. In all modes, it spawns a task to renew the dynamic database lease.
//! 4. After a successful renewal the task sleeps for a jittered 70-90% of the
//!    lease, so replicas do not renew in step.
//! 5. A failed renewal is retried with capped exponential backoff for as long as
//!    the current lease leaves time to drain; an OpenBao restart or leader change
//!    in the renewal window is therefore survived instead of stopping every
//!    replica that happened to renew then. When time runs out, a `*RenewalFailed`
//!    signal requests a fail-closed shutdown.
//! 6. OpenBao caps every lease at its max TTL: a renewal then returns less than
//!    a full lease, and that shorter duration is all that is left. The task
//!    recognises the first such renewal, waits until one drain margin before the
//!    final expiry and sends a `*Exhausted` signal, so the process restarts (and
//!    logs in again) with working credentials instead of polling a dying lease
//!    and draining with revoked ones. The margin is fixed by the full lease, not
//!    by what is left, and no renewal is scheduled inside it.
//! 7. Services may also reuse `ShutdownSignal` for fail-closed runtime probes
//!    (for example database liveness checks).

use crate::globals::GlobalArgs;
use anyhow::{Result, anyhow};
use openbao_client::OpenBaoTransport;
use rand::{RngExt, rngs::StdRng};
use secrecy::{ExposeSecret, SecretString};
use tokio::{
    sync::mpsc,
    time::{Duration, Instant, sleep, sleep_until, timeout},
};
use tracing::{debug, error, info, instrument, warn};

/// Validity kept in hand before a lease's final expiry, sized for the HTTP drain,
/// worker stop and pool close that follow a shutdown signal.
const DRAIN_MARGIN: Duration = Duration::from_mins(1);
/// Renewal attempts made even when the lease leaves no time to wait.
const MIN_ATTEMPTS: u32 = 3;
/// Ceiling for the doubling retry backoff.
const MAX_BACKOFF: Duration = Duration::from_secs(30);
/// Floor for the wait between renewals, so a near-zero lease cannot spin.
const MIN_RENEW_INTERVAL: Duration = Duration::from_secs(1);
/// OpenBao reports leases in whole seconds; a renewal within this much of the
/// longest lease seen still counts as a full one.
const EXTENSION_TOLERANCE: Duration = Duration::from_secs(1);

/// Reason for triggering a process shutdown from a renewal task or runtime probe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShutdownSignal {
    /// The OpenBao auth token could not be renewed after retrying.
    TokenRenewalFailed,
    /// The OpenBao database lease could not be renewed after retrying.
    DbLeaseRenewalFailed,
    /// The OpenBao auth token reached its max TTL and is about to expire.
    TokenExhausted,
    /// The OpenBao database lease reached its max TTL and is about to expire.
    DbLeaseExhausted,
    /// A service-level database liveness probe failed and requested shutdown.
    DatabaseHealthcheckFailed,
}

impl ShutdownSignal {
    /// Human-readable reason for logs and shutdown errors.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ShutdownSignal::TokenRenewalFailed => "openbao_token_renewal_failed",
            ShutdownSignal::DbLeaseRenewalFailed => "openbao_db_lease_renewal_failed",
            ShutdownSignal::TokenExhausted => "openbao_token_max_ttl_reached",
            ShutdownSignal::DbLeaseExhausted => "openbao_db_lease_max_ttl_reached",
            ShutdownSignal::DatabaseHealthcheckFailed => "database_healthcheck_failed",
        }
    }
}

/// Spawn background tasks to keep OpenBao and database leases renewed.
///
/// If running in Agent mode, the OpenBao token renewal is skipped as the Agent
/// handles its own authentication. Database renewal is always performed by the
/// application to ensure connection continuity.
///
/// # Errors
/// Returns an error if the tasks cannot be initialized.
#[instrument(skip(globals, tx))]
pub async fn try_renew(
    globals: &GlobalArgs,
    tx: mpsc::UnboundedSender<ShutdownSignal>,
) -> Result<()> {
    // In Agent Proxy mode, the Agent handles its own auth token renewal.
    // The app only needs to renew its own (TCP mode) token.
    if globals.openbao_transport.is_agent_proxy() {
        info!("OpenBao agent proxy mode enabled; skipping token renewals");
    } else {
        tokio::spawn(renew_until_shutdown(
            globals.openbao_transport.clone(),
            globals.openbao_token.clone(),
            Lease::Token,
            Some(globals.openbao_token_lease_duration)
                .filter(|seconds| *seconds > 0)
                .map(Duration::from_secs),
            tx.clone(),
        ));
    }

    tokio::spawn(renew_until_shutdown(
        globals.openbao_transport.clone(),
        globals.openbao_token.clone(),
        Lease::Database {
            lease_id: globals.openbao_db_lease_id.clone(),
            increment: globals.openbao_db_lease_duration,
        },
        Some(Duration::from_secs(globals.openbao_db_lease_duration)),
        tx,
    ));

    Ok(())
}

/// What a renewal task keeps alive.
enum Lease {
    Token,
    Database { lease_id: String, increment: u64 },
}

impl Lease {
    const fn name(&self) -> &'static str {
        match self {
            Self::Token => "token",
            Self::Database { .. } => "DB lease",
        }
    }

    const fn failed(&self) -> ShutdownSignal {
        match self {
            Self::Token => ShutdownSignal::TokenRenewalFailed,
            Self::Database { .. } => ShutdownSignal::DbLeaseRenewalFailed,
        }
    }

    const fn exhausted(&self) -> ShutdownSignal {
        match self {
            Self::Token => ShutdownSignal::TokenExhausted,
            Self::Database { .. } => ShutdownSignal::DbLeaseExhausted,
        }
    }

    async fn renew(&self, transport: &OpenBaoTransport, token: Option<&str>) -> Result<u64> {
        match self {
            Self::Token => transport.renew_token(token, None).await,
            Self::Database {
                lease_id,
                increment,
            } => transport.renew_db_lease(token, lease_id, *increment).await,
        }
    }
}

/// What to do after a successful renewal, measured from when it was requested.
#[derive(Debug, PartialEq, Eq)]
enum Plan {
    /// A full lease was granted: renew again after this long.
    RenewAfter(Duration),
    /// The lease is at its max TTL: request shutdown after this long.
    ShutdownAfter(Duration),
}

/// Decide the next step from the lease a renewal returned.
///
/// `full` is the longest lease this task has held. OpenBao grants the role's
/// TTL on every renewal until the max TTL is closer than that, and from then on
/// only what remains. So the first renewal shorter than `full` already fixes the
/// final expiry, and waiting for a later, even shorter one could only wake inside
/// the drain margin. Shutdown is requested one margin before that expiry, at once
/// if less than a margin is left.
///
/// A full lease is renewed after `jitter_percent` of the time it has outside the
/// margin, so the renewal always starts with part of that time left for retries.
fn plan(lease: Duration, full: Duration, jitter_percent: u64) -> Plan {
    let margin = drain_margin(full.max(lease));
    let usable = lease.saturating_sub(margin);
    if lease + EXTENSION_TOLERANCE < full {
        return Plan::ShutdownAfter(usable);
    }
    let wait = Duration::from_secs(usable.as_secs() * jitter_percent / 100);
    Plan::RenewAfter(wait.max(MIN_RENEW_INTERVAL))
}

/// Validity to keep in hand before expiry for a lease whose full duration is
/// `full`: the drain margin, or half of a lease too short to afford it. It is
/// derived from the full lease so it does not shrink as the lease runs down.
fn drain_margin(full: Duration) -> Duration {
    DRAIN_MARGIN.min(full / 2)
}

/// Whether a lease is long enough to reserve the whole drain margin. Shorter
/// ones (seconds-long leases in tests) cannot, and fall back to a fixed number
/// of attempts.
fn reserves_margin(full: Duration) -> bool {
    full >= DRAIN_MARGIN * 2
}

/// Whether a failed renewal may be retried after `backoff`.
///
/// `time_left` is the lease's remaining validity outside its drain margin. While
/// it outlasts the backoff, retrying costs nothing. Once it does not, a lease
/// that reserves its margin stops at once; only when the margin cannot be
/// reserved, or the expiry is unknown, are `MIN_ATTEMPTS` made regardless.
fn may_retry(attempt: u32, backoff: Duration, time_left: Option<Duration>, reserved: bool) -> bool {
    time_left.is_some_and(|left| backoff < left)
        || (attempt < MIN_ATTEMPTS && !(reserved && time_left.is_some()))
}

/// Keep one lease renewed until it fails for good or reaches its max TTL, then
/// send the matching shutdown signal and stop.
///
/// `initial` is the lease the credential was issued with, when known. Every
/// deadline is measured from the moment a renewal was requested, so a slow
/// response never makes the lease look longer than it is.
async fn renew_until_shutdown(
    transport: OpenBaoTransport,
    token: SecretString,
    lease: Lease,
    initial: Option<Duration>,
    tx: mpsc::UnboundedSender<ShutdownSignal>,
) {
    let mut rng = rand::make_rng::<StdRng>();
    // An empty token means Agent mode: the Agent injects its own.
    let token = Some(token.expose_secret()).filter(|token| !token.is_empty());
    let name = lease.name();
    // Longest lease held so far; the issued lease only sizes the margin until
    // the first renewal reports what a full one is.
    let mut full = Duration::ZERO;
    let issued = initial.unwrap_or_default();
    // When the current lease runs out, once that is known.
    let mut expiry = initial.map(|lease| Instant::now() + lease);

    loop {
        let mut attempt = 1;
        let mut backoff = Duration::from_secs(1);
        let (requested, granted) = loop {
            let requested = Instant::now();
            // What the lease can still spend on renewal before its drain margin.
            let budget = expiry.map(|expiry| {
                expiry
                    .saturating_duration_since(requested)
                    .saturating_sub(drain_margin(full.max(issued)))
            });
            // A request that stalls must not eat the margin: it gets what is left
            // of the budget. Leases too short to reserve one keep the transport's
            // own timeout for their guaranteed attempts.
            let reserved = reserves_margin(full.max(issued));
            let result = match budget {
                Some(budget) if reserved || attempt > MIN_ATTEMPTS => {
                    match timeout(budget, lease.renew(&transport, token)).await {
                        Ok(result) => result,
                        Err(_) => Err(anyhow!("no answer before the drain margin")),
                    }
                }
                _ => lease.renew(&transport, token).await,
            };
            match result {
                Ok(seconds) => break (requested, Duration::from_secs(seconds)),
                Err(e) => {
                    let time_left = budget.map(|budget| budget.saturating_sub(requested.elapsed()));
                    if !may_retry(attempt, backoff, time_left, reserved) {
                        error!(attempts = attempt, "Failed to renew {name}: {e}");
                        let _ = tx.send(lease.failed());
                        return;
                    }
                    warn!(
                        attempt,
                        retry_in_seconds = backoff.as_secs(),
                        "Failed to renew {name}: {e}"
                    );
                    sleep(backoff).await;
                    attempt += 1;
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                }
            }
        };

        full = full.max(granted);
        expiry = Some(requested + granted);

        match plan(granted, full, rng.random_range(70..90)) {
            Plan::RenewAfter(wait) => {
                info!(
                    lease_duration = granted.as_secs(),
                    next_renew_seconds = wait.as_secs(),
                    "OpenBao {name} renewed"
                );
                debug!("Will renew {name} in {} seconds", wait.as_secs());
                sleep_until(requested + wait).await;
            }
            Plan::ShutdownAfter(wait) => {
                warn!(
                    remaining_seconds = granted.as_secs(),
                    shutdown_in_seconds = wait.as_secs(),
                    "OpenBao {name} reached its max TTL; restarting before it expires"
                );
                sleep_until(requested + wait).await;
                let _ = tx.send(lease.exhausted());
                return;
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{
        DRAIN_MARGIN, MAX_BACKOFF, MIN_RENEW_INTERVAL, Plan, ShutdownSignal, drain_margin,
        may_retry, plan, reserves_margin, try_renew,
    };
    use crate::globals::GlobalArgs;
    use anyhow::{Result, bail};
    use openbao_client::{OpenBaoTarget, OpenBaoTransport};
    use secrecy::SecretString;
    use serde_json::json;
    use std::net::TcpListener;
    use tokio::{
        sync::mpsc,
        time::{Duration, timeout},
    };
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const DB_LEASE_DURATION_SECONDS: u64 = 2;
    const DB_LEASE_ID: &str = "lease-1";

    fn can_bind_localhost() -> bool {
        TcpListener::bind("127.0.0.1:0").is_ok()
    }

    fn create_global_args(url: &str) -> GlobalArgs {
        let target = OpenBaoTarget::parse(url).unwrap();
        let transport = OpenBaoTransport::from_target("test", target).unwrap();
        GlobalArgs::new(url.to_string(), transport)
    }

    async fn wait_for_shutdown(
        rx: &mut mpsc::UnboundedReceiver<ShutdownSignal>,
    ) -> Result<ShutdownSignal> {
        match timeout(Duration::from_secs(15), rx.recv()).await {
            Ok(Some(signal)) => Ok(signal),
            Ok(None) => bail!("shutdown channel disconnected unexpectedly"),
            Err(_) => bail!("expected shutdown signal after 3 failed renew attempts"),
        }
    }

    #[tokio::test]
    async fn try_renew_token_failure_triggers_shutdown() -> Result<()> {
        if !can_bind_localhost() {
            eprintln!("Skipping test: cannot bind localhost");
            return Ok(());
        }
        let server = MockServer::start().await;
        let token = SecretString::from("openbao-token".to_string());

        Mock::given(method("POST"))
            .and(path("/v1/auth/token/renew-self"))
            .and(header("X-Vault-Token", "openbao-token"))
            .and(body_json(json!({ "increment": 0 })))
            .respond_with(ResponseTemplate::new(500).set_body_json(json!({
                "errors": ["boom"]
            })))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/v1/sys/leases/renew"))
            .and(header("X-Vault-Token", "openbao-token"))
            .and(body_json(json!({
                "increment": DB_LEASE_DURATION_SECONDS,
                "lease_id": DB_LEASE_ID
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "lease_duration": DB_LEASE_DURATION_SECONDS
            })))
            .mount(&server)
            .await;

        let mut globals = create_global_args(&server.uri());
        globals.set_token(token);
        globals.openbao_db_lease_id = DB_LEASE_ID.to_string();
        globals.openbao_db_lease_duration = DB_LEASE_DURATION_SECONDS;

        let (tx, mut rx) = mpsc::unbounded_channel();
        try_renew(&globals, tx).await?;

        let signal = wait_for_shutdown(&mut rx).await?;
        if signal != ShutdownSignal::TokenRenewalFailed {
            bail!("expected token renewal failure, got {signal:?}");
        }

        let Some(requests) = server.received_requests().await else {
            bail!("wiremock request recording is disabled");
        };

        let token_renew_requests = requests
            .iter()
            .filter(|request| request.url.path() == "/v1/auth/token/renew-self")
            .count();
        if token_renew_requests != 3 {
            bail!("expected 3 token renew attempts, got {token_renew_requests}");
        }
        Ok(())
    }

    #[tokio::test]
    async fn try_renew_db_lease_failure_triggers_shutdown() -> Result<()> {
        if !can_bind_localhost() {
            eprintln!("Skipping test: cannot bind localhost");
            return Ok(());
        }
        let server = MockServer::start().await;
        let token = SecretString::from("openbao-token".to_string());

        Mock::given(method("POST"))
            .and(path("/v1/auth/token/renew-self"))
            .and(header("X-Vault-Token", "openbao-token"))
            .and(body_json(json!({ "increment": 0 })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "auth": { "lease_duration": DB_LEASE_DURATION_SECONDS }
            })))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/v1/sys/leases/renew"))
            .and(header("X-Vault-Token", "openbao-token"))
            .and(body_json(json!({
                "increment": DB_LEASE_DURATION_SECONDS,
                "lease_id": DB_LEASE_ID
            })))
            .respond_with(ResponseTemplate::new(500).set_body_json(json!({
                "errors": ["boom"]
            })))
            .mount(&server)
            .await;

        let mut globals = create_global_args(&server.uri());
        globals.set_token(token);
        globals.openbao_db_lease_id = DB_LEASE_ID.to_string();
        globals.openbao_db_lease_duration = DB_LEASE_DURATION_SECONDS;

        let (tx, mut rx) = mpsc::unbounded_channel();
        try_renew(&globals, tx).await?;

        let signal = wait_for_shutdown(&mut rx).await?;
        if signal != ShutdownSignal::DbLeaseRenewalFailed {
            bail!("expected DB lease renewal failure, got {signal:?}");
        }

        let Some(requests) = server.received_requests().await else {
            bail!("wiremock request recording is disabled");
        };

        let lease_renew_requests = requests
            .iter()
            .filter(|request| request.url.path() == "/v1/sys/leases/renew")
            .count();
        if lease_renew_requests != 3 {
            bail!("expected 3 DB lease renew attempts, got {lease_renew_requests}");
        }
        Ok(())
    }

    const HOUR: Duration = Duration::from_hours(1);

    #[test]
    fn plan_renews_a_full_lease_at_the_jittered_fraction_of_its_usable_time() {
        // 59 of the 60 minutes are usable; 80% of that is 2832 s.
        assert_eq!(
            plan(HOUR, HOUR, 80),
            Plan::RenewAfter(Duration::from_secs(2832))
        );
        // The first renewal defines what a full lease is.
        assert_eq!(
            plan(HOUR, Duration::ZERO, 70),
            Plan::RenewAfter(Duration::from_secs(2478))
        );
        // Whole-second rounding is not a shortened lease.
        assert!(matches!(
            plan(Duration::from_secs(3599), HOUR, 80),
            Plan::RenewAfter(_)
        ));
    }

    #[test]
    fn plan_treats_the_first_shortened_lease_as_the_final_one() {
        // Review trace: an hour-long lease renewed 406 s before max TTL. Renewing
        // again at 89% would have woken 45 s before expiry, inside the margin.
        assert_eq!(
            plan(Duration::from_secs(406), HOUR, 89),
            Plan::ShutdownAfter(Duration::from_secs(346))
        );
        assert_eq!(
            plan(Duration::from_mins(15), HOUR, 80),
            Plan::ShutdownAfter(Duration::from_mins(14))
        );
    }

    #[test]
    fn plan_requests_shutdown_at_once_inside_the_drain_margin() {
        // The margin comes from the full lease; it does not halve with what is left.
        assert_eq!(
            plan(Duration::from_secs(45), HOUR, 80),
            Plan::ShutdownAfter(Duration::ZERO)
        );
        assert_eq!(
            plan(Duration::ZERO, HOUR, 80),
            Plan::ShutdownAfter(Duration::ZERO)
        );
    }

    #[test]
    fn plan_always_leaves_retry_time_before_the_drain_margin() {
        // Second review trace: leases of 2 to 23 minutes used to wake exactly at
        // the margin, so the first failed attempt already spent it.
        for (minutes, jitter) in [(2, 89), (5, 89), (12, 89), (15, 89), (60, 89)] {
            let lease = Duration::from_mins(minutes);
            let wait = match plan(lease, lease, jitter) {
                Plan::RenewAfter(wait) => wait,
                Plan::ShutdownAfter(_) => Duration::MAX,
            };
            // `None` when the renewal would wake inside the margin (or not at all).
            let budget = lease
                .checked_sub(wait)
                .and_then(|left| left.checked_sub(DRAIN_MARGIN));
            assert!(
                budget.is_some_and(|budget| budget >= Duration::from_secs(6)),
                "{minutes} min lease wakes with {budget:?} before the margin"
            );
        }
        // A lease too short for the margin keeps half of itself.
        let short = Duration::from_secs(20);
        assert_eq!(
            plan(short, short, 89),
            Plan::RenewAfter(Duration::from_secs(8))
        );
    }

    #[test]
    fn plan_never_schedules_a_renewal_sooner_than_the_floor() {
        // A one-second lease used to compute a zero wait and spin.
        let second = Duration::from_secs(1);
        assert_eq!(
            plan(second, second, 70),
            Plan::RenewAfter(MIN_RENEW_INTERVAL)
        );
    }

    #[test]
    fn drain_margin_follows_the_full_lease_not_what_is_left() {
        assert_eq!(drain_margin(HOUR), DRAIN_MARGIN);
        assert_eq!(drain_margin(Duration::from_mins(2)), DRAIN_MARGIN);
        assert_eq!(
            drain_margin(Duration::from_secs(20)),
            Duration::from_secs(10)
        );
        assert!(reserves_margin(Duration::from_mins(2)));
        assert!(!reserves_margin(Duration::from_secs(119)));
    }

    #[test]
    fn may_retry_makes_the_minimum_attempts_when_no_margin_can_be_reserved() {
        // Unknown expiry (first token renewal without a login lease).
        assert!(may_retry(1, Duration::from_secs(1), None, true));
        assert!(may_retry(2, Duration::from_secs(2), None, false));
        assert!(!may_retry(3, Duration::from_secs(4), None, true));
        // A seconds-long lease cannot reserve a margin either.
        assert!(may_retry(
            2,
            Duration::from_secs(2),
            Some(Duration::ZERO),
            false
        ));
        assert!(!may_retry(
            3,
            Duration::from_secs(4),
            Some(Duration::ZERO),
            false
        ));
    }

    #[test]
    fn may_retry_never_spends_a_reserved_margin() {
        // Out of budget on the first failure: the guaranteed attempts used to run
        // anyway, 3 s (or 93 s against a stalled server) into the margin.
        assert!(!may_retry(
            1,
            Duration::from_secs(1),
            Some(Duration::ZERO),
            true
        ));
        assert!(!may_retry(
            2,
            Duration::from_secs(2),
            Some(Duration::from_secs(2)),
            true
        ));
    }

    #[test]
    fn may_retry_continues_while_the_lease_can_still_cover_the_drain() {
        let ten_minutes = Some(Duration::from_mins(10));
        assert!(may_retry(3, Duration::from_secs(4), ten_minutes, true));
        assert!(may_retry(40, MAX_BACKOFF, ten_minutes, true));
        // The next retry would land inside the drain margin: stop now.
        assert!(!may_retry(
            9,
            MAX_BACKOFF,
            Some(Duration::from_secs(30)),
            true
        ));
    }

    #[tokio::test]
    async fn try_renew_capped_token_requests_shutdown_before_expiry() -> Result<()> {
        if !can_bind_localhost() {
            eprintln!("Skipping test: cannot bind localhost");
            return Ok(());
        }
        let server = MockServer::start().await;

        // The first renewal grants a full lease; every later one returns only
        // the second that is left, as OpenBao does at max TTL.
        Mock::given(method("POST"))
            .and(path("/v1/auth/token/renew-self"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "auth": { "lease_duration": 3 }
            })))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/auth/token/renew-self"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "auth": { "lease_duration": 1 }
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/sys/leases/renew"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "lease_duration": 3600
            })))
            .mount(&server)
            .await;

        let mut globals = create_global_args(&server.uri());
        globals.set_token(SecretString::from("openbao-token".to_string()));
        globals.openbao_db_lease_id = DB_LEASE_ID.to_string();
        globals.openbao_db_lease_duration = 3600;

        let (tx, mut rx) = mpsc::unbounded_channel();
        try_renew(&globals, tx).await?;

        let signal = wait_for_shutdown(&mut rx).await?;
        if signal != ShutdownSignal::TokenExhausted {
            bail!("expected token exhaustion, got {signal:?}");
        }

        let Some(requests) = server.received_requests().await else {
            bail!("wiremock request recording is disabled");
        };
        let token_renew_requests = requests
            .iter()
            .filter(|request| request.url.path() == "/v1/auth/token/renew-self")
            .count();
        if token_renew_requests != 2 {
            bail!("a capped lease must not be polled; got {token_renew_requests} renewals");
        }
        Ok(())
    }
}
