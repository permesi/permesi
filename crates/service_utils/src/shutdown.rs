//! Shutdown triggers shared by the Permesi services.
//!
//! A service stops for one of two reasons. Either the platform asks it to stop
//! (SIGTERM from Kubernetes or systemd, SIGINT from a terminal), or it fails
//! closed because a Vault renewal or database probe sent a [`ShutdownSignal`].
//! Both start the same bounded drain so in-flight requests can finish, but they
//! end differently: a platform-requested stop is a clean exit, while a
//! fail-closed stop is reported as an error so the supervisor restarts the
//! process with fresh credentials.
//!
//! Without these handlers SIGTERM uses the default disposition and kills the
//! process immediately: requests in flight are cut off, a Unix socket file is
//! left behind, and batched telemetry is never flushed.

use crate::vault::renew::ShutdownSignal;
use std::time::Duration;
use tokio::sync::mpsc::UnboundedReceiver;
use tracing::{error, info};

/// Longest time in-flight requests may take to finish once a shutdown starts.
pub const DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

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
    use super::{ShutdownSignal, requested};
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
