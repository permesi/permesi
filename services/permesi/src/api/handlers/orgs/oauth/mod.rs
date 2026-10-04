//! Session-authenticated OAuth management adapters under the existing tenant hierarchy.
//!
//! Flow Overview:
//! Require a full session, resolve active org membership, require owner/admin for
//! mutations, resolve active project/environment/application, then call the OAuth
//! service with that trusted context. Inaccessible resources return 404. Global
//! Principal capabilities never bypass org membership or become delegated scopes.
//! DTOs expose registration fields only; credentials and grant metadata are excluded.

pub(crate) mod clients;
pub(crate) mod scopes;
mod types;

use axum::{
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use sqlx::PgPool;

use super::storage::{resolve_environment, resolve_org_context, resolve_project};
use crate::{
    api::handlers::auth::principal::require_auth,
    oauth::service::{ApplicationContext, Error},
};
use types::ApplicationPath;

impl IntoResponse for Error {
    /// Maps domain failures to existing HTTP conventions without logging submitted values.
    fn into_response(self) -> Response {
        match self {
            Self::NotFound => StatusCode::NOT_FOUND.into_response(),
            Self::Invalid(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
            Self::Conflict => {
                (StatusCode::CONFLICT, "OAuth configuration already exists.").into_response()
            }
            Self::Database(error) => persistence_status(&error).into_response(),
        }
    }
}

/// Logs only a database error code and returns 500, excluding SQL details and values.
fn persistence_status(error: &sqlx::Error) -> StatusCode {
    tracing::error!(
        code = ?error.as_database_error().and_then(sqlx::error::DatabaseError::code),
        "OAuth database operation failed"
    );
    StatusCode::INTERNAL_SERVER_ERROR
}

/// Resolves a session's active application ancestry; writes require trusted owner/admin
/// org roles. Non-members, inactive memberships, and unauthorized writes return 404.
/// No global Principal capability or caller-provided application ID can bypass ancestry.
async fn resolve_application(
    pool: &PgPool,
    headers: &HeaderMap,
    path: &ApplicationPath,
    write: bool,
) -> Result<ApplicationContext, StatusCode> {
    let principal = require_auth(headers, pool).await?;
    let org = resolve_org_context(pool, principal.user_id, &path.org_slug)
        .await
        .map_err(|error| persistence_status(&error))?
        .ok_or(StatusCode::NOT_FOUND)?;
    if write && !org.can_manage() {
        return Err(StatusCode::NOT_FOUND);
    }
    let project = resolve_project(pool, org.id(), &path.project_slug)
        .await
        .map_err(|error| persistence_status(&error))?
        .ok_or(StatusCode::NOT_FOUND)?;
    let environment = resolve_environment(pool, project.id(), &path.env_slug)
        .await
        .map_err(|error| persistence_status(&error))?
        .ok_or(StatusCode::NOT_FOUND)?;
    let application_id = sqlx::query_scalar(
        "SELECT id FROM applications WHERE environment_id = $1 AND id = $2 AND deleted_at IS NULL",
    )
    .bind(environment.id())
    .bind(path.app_id)
    .fetch_optional(pool)
    .await
    .map_err(|error| persistence_status(&error))?
    .ok_or(StatusCode::NOT_FOUND)?;
    Ok(ApplicationContext::resolved(application_id))
}

#[cfg(test)]
mod tests;
