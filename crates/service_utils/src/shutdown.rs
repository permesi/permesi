//! Shutdown triggers shared by the Permesi services.
//!
//! A service stops for one of two reasons. Either the platform asks it to stop
//! (SIGTERM from Kubernetes or systemd, SIGINT from a terminal), or it fails
//! closed because an OpenBao renewal or database probe sent a [`ShutdownSignal`].
//! Both start the same bounded drain so in-flight requests can finish, but they
//! end differently: a platform-requested stop is a clean exit, while a
//! fail-closed stop is reported as an error so the supervisor restarts the
//! process with fresh credentials.
//!
//! Without these handlers SIGTERM uses the default disposition and kills the
//! process immediately: requests in flight are cut off, a Unix socket file is
//! left behind, and batched telemetry is never flushed.
//!
//! Installing the handlers also means a later signal no longer kills the process, so
//! the drain has to end by itself. It ends when the last connection closes, when the
//! configured drain time is over, or as soon as a second signal arrives
//! ([`drain_ended`]): an operator who asks twice gets the stop without waiting. At
//! that point the requests still in a handler are abandoned ([`Cutoff`]), so no work
//! runs on into the steps that follow.
//!
//! ## How long a stop takes
//! After the drain come three bounded steps: up to 4 s for background workers
//! ([`WORKER_STOP_TIMEOUT`]), up to 4 s to close the database pool, and, in a build
//! that exports traces, the flush of the telemetry exporter, which its own timeouts
//! limit to about 5 s. With the default 20 s drain that is at most 28 s without
//! telemetry export and about 33 s with it, so the supervisor's grace period should be
//! 35 s or more; the Helm charts set 60 s. A second signal shortens only the drain: the
//! steps after it are short, release what the process holds, and always run.

use crate::openbao::renew::ShutdownSignal;
use axum::{
    Router,
    extract::Request,
    http::{HeaderValue, StatusCode, header::CACHE_CONTROL},
    middleware::Next,
    response::IntoResponse,
};
use std::time::Duration;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

/// Longest wait for a cancelled background worker after the drain.
pub const WORKER_STOP_TIMEOUT: Duration = Duration::from_secs(4);

/// Ends the requests that are still in a handler when the drain is over.
///
/// Stopping the listener does not stop the handlers: the server's connection tasks
/// outlive the future that accepted them, so a request that entered before the drain
/// limit could finish after the service had returned from serving, alongside the
/// worker and pool shutdown. [`Cutoff::guard`] puts every request of a router under
/// one switch, and [`Cutoff::cut`] drops the handlers still running, which rolls back
/// their open transactions, and answers their callers with `503`.
#[derive(Clone, Debug, Default)]
pub struct Cutoff(CancellationToken);

impl Cutoff {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Put every request to `router` under this cutoff. Apply it outermost, so nothing
    /// of a request keeps running once it is cut.
    pub fn guard<S>(&self, router: Router<S>) -> Router<S>
    where
        S: Clone + Send + Sync + 'static,
    {
        let cutoff = self.0.clone();
        router.layer(axum::middleware::from_fn(
            move |request: Request, next: Next| {
                let cutoff = cutoff.clone();
                async move {
                    tokio::select! {
                        response = next.run(request) => response,
                        () = cutoff.cancelled() => (
                            StatusCode::SERVICE_UNAVAILABLE,
                            [(CACHE_CONTROL, HeaderValue::from_static("no-store"))],
                        )
                            .into_response(),
                    }
                }
            },
        ))
    }

    /// Abandon every request still in a handler, and any that arrives afterwards.
    pub fn cut(&self) {
        self.0.cancel();
    }
}

/// Resolve when a drain that has just started must stop waiting for connections:
/// after `limit`, or as soon as the operating system signals again.
///
/// Call it once the drain has begun. The signal that started the drain was consumed by
/// [`requested`], so any signal seen here is a further one.
pub async fn drain_ended(limit: Duration) {
    tokio::select! {
        () = tokio::time::sleep(limit) => {
            warn!("Graceful drain timed out; closing remaining connections");
        }
        () = os_signal() => {
            warn!("Shutdown signalled again; closing remaining connections now");
        }
    }
}

/// Wait until the process should stop and report why.
///
/// Returns the fail-closed signal when one arrived, or `None` when the operating
/// system requested the stop. If every signal sender is dropped, only OS signals
/// can end the wait; a closed channel is never treated as a request to stop.
pub async fn requested(signals: &mut UnboundedReceiver<ShutdownSignal>) -> Option<ShutdownSignal> {
    let fail_closed = async {
        match signals.recv().await {
            Some(signal) => signal,
            None => std::future::pending().await,
        }
    };

    tokio::select! {
        signal = fail_closed => {
            info!(reason = signal.as_str(), "Gracefully shutting down");
            Some(signal)
        }
        () = os_signal() => {
            info!("Shutdown requested by the operating system; draining connections");
            None
        }
    }
}

/// Resolve when the process receives SIGINT or SIGTERM.
///
/// If one handler cannot be installed the failure is logged and only the other
/// signal can stop the process, instead of shutting down immediately.
pub async fn os_signal() {
    let interrupt = async {
        if let Err(err) = tokio::signal::ctrl_c().await {
            error!(error = %err, "failed to listen for SIGINT");
            std::future::pending::<()>().await;
        }
    };

    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                let _ = signal.recv().await;
            }
            Err(err) => {
                error!(error = %err, "failed to listen for SIGTERM");
                std::future::pending::<()>().await;
            }
        }
    };

    tokio::select! {
        () = interrupt => {}
        () = terminate => {}
    }
}

#[cfg(test)]
mod tests {
    use super::{ShutdownSignal, drain_ended, requested};
    use tokio::{
        sync::mpsc,
        time::{Duration, timeout},
    };

    /// Tests that listen for OS signals share the process: a SIGTERM sent by one
    /// reaches every listener, so they must not overlap.
    static OS_SIGNAL_TESTS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    #[tokio::test]
    async fn requested_returns_fail_closed_signal() {
        let _serial = OS_SIGNAL_TESTS.lock().await;
        let (tx, mut rx) = mpsc::unbounded_channel();
        let _ = tx.send(ShutdownSignal::DbLeaseRenewalFailed);

        let signal = timeout(Duration::from_secs(1), requested(&mut rx)).await;
        assert_eq!(
            signal.ok(),
            Some(Some(ShutdownSignal::DbLeaseRenewalFailed))
        );
    }

    /// Deliver SIGTERM to this test process. Callers must hold a SIGTERM
    /// listener first so the default disposition cannot kill the test binary.
    fn send_sigterm_to_self() -> std::io::Result<()> {
        let status = std::process::Command::new("kill")
            .args(["-TERM", &std::process::id().to_string()])
            .status()?;
        if status.success() {
            Ok(())
        } else {
            Err(std::io::Error::other("kill -TERM failed"))
        }
    }

    #[tokio::test]
    async fn requested_returns_none_on_sigterm() -> std::io::Result<()> {
        let _serial = OS_SIGNAL_TESTS.lock().await;
        let _guard = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        let (_tx, mut rx) = mpsc::unbounded_channel::<ShutdownSignal>();

        let waiter = tokio::spawn(async move { requested(&mut rx).await });
        tokio::time::sleep(Duration::from_millis(100)).await;
        send_sigterm_to_self()?;

        let signal = timeout(Duration::from_secs(2), waiter).await;
        assert!(
            matches!(signal, Ok(Ok(None))),
            "SIGTERM must end the wait with None"
        );
        Ok(())
    }

    /// With no further signal the drain lasts exactly as long as configured.
    #[tokio::test(start_paused = true)]
    async fn drain_ends_at_its_limit() {
        let _serial = OS_SIGNAL_TESTS.lock().await;
        let started = tokio::time::Instant::now();
        drain_ended(Duration::from_secs(20)).await;
        assert_eq!(started.elapsed(), Duration::from_secs(20));
    }

    /// The regression: once the handlers are installed a second SIGTERM used to be
    /// swallowed, and the process kept draining for the full limit.
    #[tokio::test]
    async fn drain_ends_at_once_when_signalled_again() -> std::io::Result<()> {
        let _serial = OS_SIGNAL_TESTS.lock().await;
        let _guard = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        let (_tx, mut rx) = mpsc::unbounded_channel::<ShutdownSignal>();

        // The first signal starts the shutdown.
        let waiter = tokio::spawn(async move { requested(&mut rx).await });
        tokio::time::sleep(Duration::from_millis(100)).await;
        send_sigterm_to_self()?;
        assert!(matches!(
            timeout(Duration::from_secs(2), waiter).await,
            Ok(Ok(None))
        ));

        // The drain would last a minute; the second signal ends it.
        let started = std::time::Instant::now();
        let drain = tokio::spawn(drain_ended(Duration::from_mins(1)));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!drain.is_finished(), "the drain ended without a signal");
        send_sigterm_to_self()?;
        assert!(timeout(Duration::from_secs(2), drain).await.is_ok());
        assert!(started.elapsed() < Duration::from_secs(5));
        Ok(())
    }

    #[tokio::test]
    async fn requested_ignores_closed_channel() {
        let _serial = OS_SIGNAL_TESTS.lock().await;
        let (tx, mut rx) = mpsc::unbounded_channel::<ShutdownSignal>();
        drop(tx);

        let waited = timeout(Duration::from_millis(100), requested(&mut rx)).await;
        assert!(
            waited.is_err(),
            "a closed channel must not trigger shutdown"
        );
    }
}
