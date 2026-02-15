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
use tracing::{Instrument, debug, error, info_span};
use utoipa::ToSchema;

#[derive(ToSchema, Serialize, Deserialize, Debug)]
pub struct Health {
    commit: String,
    name: String,
    version: String,
    database: String,
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
/// Perform a health check for genesis.
///
/// When the database probe fails due to credential/auth errors, this handler
/// requests graceful shutdown so the supervisor can restart with fresh Vault
/// DB credentials.
pub async fn health(
    method: Method,
    pool: Extension<PgPool>,
    shutdown_tx: Extension<mpsc::UnboundedSender<crate::vault::renew::ShutdownSignal>>,
) -> impl IntoResponse {
    let acquire_span = info_span!(
        "db.acquire",
        db.system = "postgresql",
        db.operation = "ACQUIRE"
    );
    let mut should_shutdown = false;
    let result = match pool.0.acquire().instrument(acquire_span).await {
        Ok(mut conn) => {
            let ping_span = info_span!("db.ping", db.system = "postgresql", db.operation = "PING");
            match conn.ping().instrument(ping_span).await {
                Ok(()) => Ok(()),
                Err(error) => {
                    should_shutdown = should_shutdown_on_db_error(&error);
                    error!("Failed to ping database: {}", error);

                    Err(StatusCode::SERVICE_UNAVAILABLE)
                }
            }
        }

        Err(error) => {
            should_shutdown = should_shutdown_on_db_error(&error);
            error!("Failed to acquire database connection: {}", error);

            Err(StatusCode::SERVICE_UNAVAILABLE)
        }
    };
    if result.is_err() && should_shutdown {
        let _ = shutdown_tx
            .0
            .send(crate::vault::renew::ShutdownSignal::DatabaseHealthcheckFailed);
    }

    // Create a health struct
    let health = Health {
        commit: GIT_COMMIT_HASH.to_string(),
        name: env!("CARGO_PKG_NAME").to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        database: if result.is_ok() {
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

    // Create headers using the map method
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
        });

    // Unwrap the headers or provide a default value (empty headers) in case of an error
    let headers = headers.unwrap_or_else(|()| HeaderMap::new());

    match result {
        Ok(()) => {
            debug!("Database connection is healthy");

            (StatusCode::OK, headers, body)
        }

        Err(status_code) => {
            debug!("Database connection is unhealthy");

            (status_code, headers, body)
        }
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
