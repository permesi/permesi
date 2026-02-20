//! Health probe handlers for genesis.
//!
//! This module exposes three probe endpoints:
//! - `/live`: process liveness only (no dependency checks)
//! - `/ready`: database-aware readiness for orchestrators
//! - `/health`: database-aware status with detailed JSON payload

use crate::GIT_COMMIT_HASH;
use axum::{
    body::Body,
    extract::Extension,
    http::{HeaderMap, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Json},
};
use serde::{Deserialize, Serialize};
use sqlx::{Connection, PgPool};
use tokio::sync::mpsc;
use tokio::time::{Duration, timeout};
use tracing::{Instrument, debug, error, info_span, warn};
use utoipa::ToSchema;

const HEALTH_DB_TIMEOUT_SECONDS: u64 = 2;

#[derive(ToSchema, Serialize, Deserialize, Debug)]
pub struct Health {
    commit: String,
    name: String,
    version: String,
    database: String,
}

#[derive(Debug, Clone, Copy)]
struct DatabaseProbeStatus {
    db_healthy: bool,
    db_auth_error: bool,
}

#[utoipa::path(
    get,
    path= "/live",
    responses (
        (status = 200, description = "Process is alive")
    ),
    tag = "health",
)]
/// Report process liveness without checking external dependencies.
pub async fn live() -> impl IntoResponse {
    StatusCode::OK
}

#[utoipa::path(
    get,
    path= "/ready",
    responses (
        (status = 200, description = "Service is ready to receive traffic"),
        (status = 503, description = "Service dependencies are not ready")
    ),
    tag = "health",
)]
/// Report readiness based on database connectivity.
pub async fn ready(
    pool: Extension<PgPool>,
    shutdown_tx: Extension<mpsc::UnboundedSender<crate::vault::renew::ShutdownSignal>>,
) -> impl IntoResponse {
    let status = evaluate_database_probe(&pool.0).await;
    maybe_signal_shutdown(status, &shutdown_tx.0);
    log_db_probe_status(status);

    if status.db_healthy {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

#[utoipa::path(
    get,
    path= "/health",
    responses (
        (status = 200, description = "Database connection is healthy", body = Health),
        (status = 503, description = "Database connection is unhealthy", body = Health)
    ),
    tag = "health",
)]
/// Perform a detailed health check for genesis.
///
/// When the database probe fails due to credential/auth errors, this handler
/// requests graceful shutdown so the supervisor can restart with fresh Vault
/// DB credentials.
pub async fn health(
    method: Method,
    pool: Extension<PgPool>,
    shutdown_tx: Extension<mpsc::UnboundedSender<crate::vault::renew::ShutdownSignal>>,
) -> impl IntoResponse {
    let status = evaluate_database_probe(&pool.0).await;
    maybe_signal_shutdown(status, &shutdown_tx.0);
    log_db_probe_status(status);

    let health = Health {
        commit: GIT_COMMIT_HASH.to_string(),
        name: env!("CARGO_PKG_NAME").to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        database: if status.db_healthy {
            "ok".to_string()
        } else {
            "error".to_string()
        },
    };

    let body = if method == Method::GET {
        Json(&health).into_response()
    } else {
        Body::empty().into_response()
    };

    let short_hash = if health.commit.len() > 7 {
        &health.commit[0..7]
    } else {
        ""
    };

    let headers = format!("{}:{}:{}", health.name, health.version, short_hash)
        .parse::<HeaderValue>()
        .map(|x_app_header_value| {
            debug!("X-App header: {:?}", x_app_header_value);

            let mut headers = HeaderMap::new();
            headers.insert("X-App", x_app_header_value);
            headers
        })
        .map_err(|err| {
            debug!("Failed to parse X-App header: {}", err);
        })
        .unwrap_or_else(|()| HeaderMap::new());

    if status.db_healthy {
        (StatusCode::OK, headers, body)
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, headers, body)
    }
}

/// Probe database connectivity used by `/ready` and `/health`.
async fn evaluate_database_probe(pool: &PgPool) -> DatabaseProbeStatus {
    let acquire_span = info_span!(
        "db.acquire",
        db.system = "postgresql",
        db.operation = "ACQUIRE"
    );
    let mut db_auth_error = false;

    let db_healthy = if let Ok(result) =
        timeout(Duration::from_secs(HEALTH_DB_TIMEOUT_SECONDS), async {
            match pool.acquire().instrument(acquire_span).await {
                Ok(mut conn) => {
                    let ping_span =
                        info_span!("db.ping", db.system = "postgresql", db.operation = "PING");
                    match conn.ping().instrument(ping_span).await {
                        Ok(()) => true,
                        Err(error) => {
                            db_auth_error = should_shutdown_on_db_error(&error);
                            error!("Failed to ping database: {}", error);
                            false
                        }
                    }
                }

                Err(error) => {
                    db_auth_error = should_shutdown_on_db_error(&error);
                    error!("Failed to acquire database connection: {}", error);
                    false
                }
            }
        })
        .await
    {
        result
    } else {
        warn!("Database health check timed out");
        false
    };

    DatabaseProbeStatus {
        db_healthy,
        db_auth_error,
    }
}

/// Trigger graceful shutdown when DB authentication errors imply stale Vault creds.
fn maybe_signal_shutdown(
    status: DatabaseProbeStatus,
    shutdown_tx: &mpsc::UnboundedSender<crate::vault::renew::ShutdownSignal>,
) {
    if !status.db_healthy && status.db_auth_error {
        let _ = shutdown_tx.send(crate::vault::renew::ShutdownSignal::DatabaseHealthcheckFailed);
    }
}

/// Emit probe diagnostics without changing probe outcomes.
fn log_db_probe_status(status: DatabaseProbeStatus) {
    if status.db_healthy {
        debug!("Database connection is healthy");
    } else {
        debug!("Database connection is unhealthy");
    }
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
        let error =
            sqlx::Error::Protocol("password authentication failed for user \"vault-user\"".into());
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
            message: "password authentication failed for user \"vault-user\"",
        }));
        assert!(should_shutdown_on_db_error(&error));
    }

    #[test]
    fn timeout_failure_does_not_request_shutdown() {
        let error = sqlx::Error::PoolTimedOut;
        assert!(!should_shutdown_on_db_error(&error));
    }
}
