//! Cached dependency checks for public health probes.
//!
//! ## Flow Overview
//! A single worker samples the database and the service-specific check under a
//! deadline. HTTP handlers read the last observation. Stale or missing samples
//! report unavailable. Database authentication failures trigger credential renewal by restart.

use crate::openbao::renew::ShutdownSignal;
use sqlx::{Connection, PgPool};
use std::{
    future::Future,
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, watch};
use tracing::debug;

#[derive(Debug, Clone)]
pub struct Observation(watch::Receiver<Option<Instant>>);

impl Default for Observation {
    fn default() -> Self {
        Self(watch::channel(None).1)
    }
}

impl Observation {
    /// Report readiness only while a successful background sample is fresh.
    #[must_use]
    pub fn healthy(&self) -> bool {
        self.0
            .borrow()
            .is_some_and(|at| at.elapsed() < Duration::from_secs(15))
    }

    /// Start one serial monitor per router. Dropping all receivers stops the worker.
    pub fn monitor<F, Fut>(
        pool: PgPool,
        shutdown: mpsc::UnboundedSender<ShutdownSignal>,
        check: F,
    ) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = bool> + Send,
    {
        let (tx, rx) = watch::channel(None);
        tokio::spawn(async move {
            let mut clock = tokio::time::interval(Duration::from_secs(5));
            clock.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! { () = tx.closed() => break, _ = clock.tick() => {} }
                let started = Instant::now();
                let observed = tokio::time::timeout(Duration::from_secs(4), async {
                    let db = async {
                        let result = ping(&pool, started).await;
                        if result.as_ref().is_err_and(should_shutdown_on_db_error) {
                            let _ = shutdown.send(ShutdownSignal::DatabaseHealthcheckFailed);
                        }
                        result.is_ok()
                    };
                    let (connected, extra) = tokio::join!(db, check());
                    connected && extra
                })
                .await
                .unwrap_or(false);
                if tx.send(observed.then_some(started)).is_err() {
                    break;
                }
            }
        });
        Self(rx)
    }
}
/// Measure the pool wait independently of the service-specific probe.
async fn ping(pool: &PgPool, started: Instant) -> Result<(), sqlx::Error> {
    let mut conn = pool.acquire().await?;
    debug!(
        pool_wait_ms = started.elapsed().as_millis(),
        "health database acquire"
    );
    conn.ping().await
}

/// Returns true when a database error indicates expired/revoked credentials.
///
/// This intentionally targets authentication class failures so transient
/// network/database outages do not force restart loops.
fn should_shutdown_on_db_error(error: &sqlx::Error) -> bool {
    if let sqlx::Error::Database(db_error) = error {
        if let Some(code) = db_error.code()
            && matches!(code.as_ref(), "28P01" | "28000")
        {
            return true;
        }

        return db_error
            .message()
            .to_ascii_lowercase()
            .contains("password authentication failed");
    }

    error
        .to_string()
        .to_ascii_lowercase()
        .contains("password authentication failed for user")
}

#[cfg(test)]
mod tests {
    use super::should_shutdown_on_db_error;
    use sqlx::error::{DatabaseError, ErrorKind};
    use std::{borrow::Cow, error::Error as StdError, fmt};

    #[derive(Debug)]
    struct TestDbError {
        code: Option<&'static str>,
        message: &'static str,
    }

    impl fmt::Display for TestDbError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", self.message)
        }
    }

    impl StdError for TestDbError {}

    impl DatabaseError for TestDbError {
        fn message(&self) -> &str {
            self.message
        }

        fn code(&self) -> Option<Cow<'_, str>> {
            self.code.map(Cow::Borrowed)
        }

        fn as_error(&self) -> &(dyn StdError + Send + Sync + 'static) {
            self
        }

        fn as_error_mut(&mut self) -> &mut (dyn StdError + Send + Sync + 'static) {
            self
        }

        fn into_error(self: Box<Self>) -> Box<dyn StdError + Send + Sync + 'static> {
            self
        }

        fn kind(&self) -> ErrorKind {
            ErrorKind::Other
        }
    }

    #[test]
    fn auth_failure_requests_shutdown() {
        let error = sqlx::Error::Protocol(
            "password authentication failed for user \"openbao-user\"".into(),
        );
        assert!(should_shutdown_on_db_error(&error));
    }

    #[test]
    fn sqlstate_28p01_requests_shutdown() {
        let error = sqlx::Error::Database(Box::new(TestDbError {
            code: Some("28P01"),
            message: "auth failed",
        }));
        assert!(should_shutdown_on_db_error(&error));
    }

    #[test]
    fn sqlstate_28000_requests_shutdown() {
        let error = sqlx::Error::Database(Box::new(TestDbError {
            code: Some("28000"),
            message: "invalid authorization",
        }));
        assert!(should_shutdown_on_db_error(&error));
    }

    #[test]
    fn non_auth_sqlstate_does_not_request_shutdown() {
        let error = sqlx::Error::Database(Box::new(TestDbError {
            code: Some("08006"),
            message: "connection failure",
        }));
        assert!(!should_shutdown_on_db_error(&error));
    }

    #[test]
    fn auth_message_without_code_requests_shutdown() {
        let error = sqlx::Error::Database(Box::new(TestDbError {
            code: None,
            message: "password authentication failed for user \"openbao-user\"",
        }));
        assert!(should_shutdown_on_db_error(&error));
    }

    #[test]
    fn timeout_failure_does_not_request_shutdown() {
        let error = sqlx::Error::PoolTimedOut;
        assert!(!should_shutdown_on_db_error(&error));
    }
}
