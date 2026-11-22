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
//! 6. OpenBao caps every lease at its max TTL: renewals then stop extending it and
//!    return only what is left. The task recognises that, waits until a drain
//!    margin before the final expiry and sends a `*Exhausted` signal, so the
//!    process restarts (and logs in again) with working credentials instead of
//!    polling a dying lease and draining with revoked ones.
//! 7. Services may also reuse `ShutdownSignal` for fail-closed runtime probes
//!    (for example database liveness checks).

use crate::globals::GlobalArgs;
use anyhow::Result;
use openbao_client::OpenBaoTransport;
use rand::{RngExt, rngs::StdRng};
use secrecy::{ExposeSecret, SecretString};
use tokio::{
    sync::mpsc,
    time::{Duration, Instant, sleep},
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
/// OpenBao reports leases in whole seconds; allow that much rounding when
/// deciding whether a renewal extended the expiry.
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
            None,
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

/// What to do after a successful renewal.
#[derive(Debug, PartialEq, Eq)]
enum Plan {
    /// The lease was extended: renew again after this long.
    RenewAfter(Duration),
    /// The lease is at its max TTL: request shutdown after this long.
    ShutdownAfter(Duration),
}

/// Decide the next step from the lease a renewal returned.
///
/// `remaining_before` is what the previous lease still had when the renewal was
/// sent and `peak` the longest lease seen so far. A renewal that returns less
/// than the peak without moving the expiry forward means OpenBao has capped the
/// lease at its max TTL, so the returned duration is all that is left. A full
/// lease that was simply renewed early (as at startup) is not mistaken for that.
fn plan(
    lease: Duration,
    remaining_before: Option<Duration>,
    peak: Duration,
    jitter_percent: u64,
) -> Plan {
    let capped = lease < peak
        && remaining_before.is_some_and(|remaining| lease <= remaining + EXTENSION_TOLERANCE);
    if capped {
        return Plan::ShutdownAfter(lease.saturating_sub(drain_margin(lease)));
    }
    let wait = Duration::from_secs(lease.as_secs() * jitter_percent / 100);
    Plan::RenewAfter(wait.max(MIN_RENEW_INTERVAL))
}

/// Margin kept before expiry: the full drain margin, or half of a lease too
/// short to afford it.
fn drain_margin(lease: Duration) -> Duration {
    DRAIN_MARGIN.min(lease / 2)
}

/// Whether a failed renewal may be retried after `backoff`.
///
/// The first `MIN_ATTEMPTS` are always made. Beyond that a retry is worthwhile
/// only while the lease would still have its drain margin when the retry runs;
/// without a known expiry (the first token renewal) there is nothing to wait for.
fn may_retry(attempt: u32, backoff: Duration, time_left: Option<Duration>) -> bool {
    attempt < MIN_ATTEMPTS || time_left.is_some_and(|left| backoff < left)
}

/// Keep one lease renewed until it fails for good or reaches its max TTL, then
/// send the matching shutdown signal and stop.
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
    let mut peak = initial.unwrap_or_default();
    // When the current lease runs out, once that is known.
    let mut expiry = initial.map(|lease| Instant::now() + lease);

    loop {
        let mut attempt = 1;
        let mut backoff = Duration::from_secs(1);
        let granted = loop {
            match lease.renew(&transport, token).await {
                Ok(seconds) => break Duration::from_secs(seconds),
                Err(e) => {
                    let time_left = expiry.map(|expiry| {
                        let left = expiry.saturating_duration_since(Instant::now());
                        left.saturating_sub(drain_margin(left))
                    });
                    if !may_retry(attempt, backoff, time_left) {
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

        let now = Instant::now();
        let remaining_before = expiry.map(|expiry| expiry.saturating_duration_since(now));
        peak = peak.max(granted);
        expiry = Some(now + granted);

        match plan(granted, remaining_before, peak, rng.random_range(70..90)) {
            Plan::RenewAfter(wait) => {
                info!(
                    lease_duration = granted.as_secs(),
                    next_renew_seconds = wait.as_secs(),
                    "OpenBao {name} renewed"
                );
                debug!("Will renew {name} in {} seconds", wait.as_secs());
                sleep(wait).await;
            }
            Plan::ShutdownAfter(wait) => {
                warn!(
                    remaining_seconds = granted.as_secs(),
                    shutdown_in_seconds = wait.as_secs(),
                    "OpenBao {name} reached its max TTL; restarting before it expires"
                );
                sleep(wait).await;
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
        MAX_BACKOFF, MIN_RENEW_INTERVAL, Plan, ShutdownSignal, may_retry, plan, try_renew,
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
    fn plan_renews_an_extended_lease_at_the_jittered_fraction() {
        // Renewed with 12 minutes left and a full hour granted again.
        let next = plan(HOUR, Some(Duration::from_mins(12)), HOUR, 80);
        assert_eq!(next, Plan::RenewAfter(Duration::from_mins(48)));
    }

    #[test]
    fn plan_does_not_mistake_an_early_full_renewal_for_the_cap() {
        // Startup renews a fresh lease at once: nothing is extended, but the
        // lease is as long as it has ever been.
        let next = plan(HOUR, Some(HOUR), HOUR, 70);
        assert_eq!(next, Plan::RenewAfter(Duration::from_mins(42)));
        // The first token renewal has no previous expiry to compare with.
        let next = plan(HOUR, None, HOUR, 70);
        assert_eq!(next, Plan::RenewAfter(Duration::from_mins(42)));
    }

    #[test]
    fn plan_keeps_renewing_while_a_shortened_lease_still_moves_the_expiry() {
        // Close to max TTL: 15 minutes granted with 12 left is still an extension.
        let next = plan(
            Duration::from_mins(15),
            Some(Duration::from_mins(12)),
            HOUR,
            80,
        );
        assert_eq!(next, Plan::RenewAfter(Duration::from_mins(12)));
    }

    #[test]
    fn plan_requests_shutdown_one_drain_margin_before_a_capped_lease_expires() {
        // The renewal returned only what was left: the lease is at its max TTL.
        let left = Duration::from_mins(3);
        let next = plan(left, Some(left), HOUR, 80);
        assert_eq!(next, Plan::ShutdownAfter(Duration::from_mins(2)));
        // Whole-second rounding must not hide the cap.
        let next = plan(left, Some(Duration::from_millis(179_400)), HOUR, 80);
        assert_eq!(next, Plan::ShutdownAfter(Duration::from_mins(2)));
    }

    #[test]
    fn plan_keeps_half_of_a_capped_lease_shorter_than_the_drain_margin() {
        let left = Duration::from_secs(20);
        let next = plan(left, Some(left), HOUR, 80);
        assert_eq!(next, Plan::ShutdownAfter(Duration::from_secs(10)));
        let next = plan(Duration::ZERO, Some(Duration::ZERO), HOUR, 80);
        assert_eq!(next, Plan::ShutdownAfter(Duration::ZERO));
    }

    #[test]
    fn plan_never_schedules_a_renewal_sooner_than_the_floor() {
        // A one-second lease used to compute a zero wait and spin.
        let next = plan(Duration::from_secs(1), None, Duration::from_secs(1), 70);
        assert_eq!(next, Plan::RenewAfter(MIN_RENEW_INTERVAL));
    }

    #[test]
    fn may_retry_always_makes_the_minimum_attempts() {
        assert!(may_retry(1, Duration::from_secs(1), None));
        assert!(may_retry(2, Duration::from_secs(2), Some(Duration::ZERO)));
        assert!(!may_retry(3, Duration::from_secs(4), None));
        assert!(!may_retry(3, Duration::from_secs(4), Some(Duration::ZERO)));
    }

    #[test]
    fn may_retry_continues_while_the_lease_can_still_cover_the_drain() {
        let ten_minutes = Some(Duration::from_mins(10));
        assert!(may_retry(3, Duration::from_secs(4), ten_minutes));
        assert!(may_retry(40, MAX_BACKOFF, ten_minutes));
        // The next retry would land inside the drain margin: stop now.
        assert!(!may_retry(9, MAX_BACKOFF, Some(Duration::from_secs(30))));
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
