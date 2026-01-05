//! Role-based user management endpoints.
//!
//! Flow Overview:
//! 1) Authenticate the request via session cookie.
//! 2) Enforce role-based access for /users routes.
//! 3) Perform read or allow-listed updates for the requested user.

use axum::{
    Json,
    extract::{Extension, Path},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use tracing::error;
use utoipa::ToSchema;
use uuid::Uuid;

use super::auth::principal::{Permission, Principal};

#[derive(Debug, Serialize, ToSchema)]
pub struct UserSummary {
    pub id: String,
    pub email: String,
    pub display_name: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct UserDetail {
    pub id: String,
    pub email: String,
    pub display_name: Option<String>,
    pub locale: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct UserUpdateRequest {
    pub display_name: Option<String>,
    pub locale: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct UserRoleRequest {
    pub role: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct UserRoleResponse {
    pub id: String,
    pub role: String,
    pub assigned_at: String,
}

#[utoipa::path(
    get,
    path = "/v1/users",
    responses(
        (status = 200, description = "List users (role-based).", body = [UserSummary]),
        (status = 401, description = "Missing or invalid session cookie."),
        (status = 403, description = "Forbidden."),
    ),
    tag = "users"
)]
pub async fn list_users(
    Extension(_principal): Extension<Principal>,
    pool: Extension<PgPool>,
) -> impl IntoResponse {
    match fetch_user_summaries(&pool).await {
        Ok(list) => (StatusCode::OK, Json(list)).into_response(),
        Err(err) => {
            error!("Failed to list users: {err}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[utoipa::path(
    get,
    path = "/v1/users/{id}",
    params(
        ("id" = String, Path, description = "User id")
    ),
    responses(
        (status = 200, description = "User detail (role-based).", body = UserDetail),
        (status = 400, description = "Invalid user id."),
        (status = 401, description = "Missing or invalid session cookie."),
        (status = 403, description = "Forbidden."),
        (status = 404, description = "User not found."),
    ),
    tag = "users"
)]
pub async fn get_user(
    Path(id): Path<String>,
    Extension(_principal): Extension<Principal>,
    pool: Extension<PgPool>,
) -> impl IntoResponse {
    let user_id = match Uuid::parse_str(id.trim()) {
        Ok(id) => id,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    match fetch_user_detail(&pool, user_id).await {
        Ok(Some(detail)) => (StatusCode::OK, Json(detail)).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(err) => {
            error!("Failed to fetch user detail: {err}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[utoipa::path(
    patch,
    path = "/v1/users/{id}",
    request_body = UserUpdateRequest,
    responses(
        (status = 200, description = "User updated (editor/admin).", body = UserDetail),
        (status = 400, description = "Invalid input."),
        (status = 401, description = "Missing or invalid session cookie."),
        (status = 403, description = "Forbidden."),
        (status = 404, description = "User not found."),
    ),
    tag = "users"
)]
pub async fn patch_user(
    Path(id): Path<String>,
    Extension(principal): Extension<Principal>,
    pool: Extension<PgPool>,
    Json(payload): Json<UserUpdateRequest>,
) -> impl IntoResponse {
    let user_id = match Uuid::parse_str(id.trim()) {
        Ok(id) => id,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    let display_name = normalize_optional(payload.display_name);
    let locale = normalize_optional(payload.locale);

    if display_name.is_none() && locale.is_none() {
        return (StatusCode::BAD_REQUEST, "No updates provided.").into_response();
    }

    match update_user_profile(&pool, &principal, user_id, display_name, locale).await {
        Ok(Some(detail)) => (StatusCode::OK, Json(detail)).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(err) => err.into_response(),
    }
}

#[utoipa::path(
    delete,
    path = "/v1/users/{id}",
    responses(
        (status = 204, description = "User deleted (admin-only)."),
        (status = 400, description = "Invalid user id."),
        (status = 401, description = "Missing or invalid session cookie."),
        (status = 403, description = "Forbidden."),
        (status = 404, description = "User not found."),
    ),
    tag = "users"
)]
pub async fn delete_user(
    Path(id): Path<String>,
    Extension(principal): Extension<Principal>,
    pool: Extension<PgPool>,
) -> impl IntoResponse {
    let user_id = match Uuid::parse_str(id.trim()) {
        Ok(id) => id,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    match delete_user_record(&pool, &principal, user_id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(err) => err.into_response(),
    }
}

#[utoipa::path(
    put,
    path = "/v1/users/{id}/role",
    request_body = UserRoleRequest,
    responses(
        (status = 200, description = "Role updated (admin-only).", body = UserRoleResponse),
        (status = 400, description = "Invalid role."),
        (status = 401, description = "Missing or invalid session cookie."),
        (status = 403, description = "Forbidden."),
        (status = 404, description = "User not found."),
    ),
    tag = "users"
)]
pub async fn set_user_role(
    Path(id): Path<String>,
    Extension(principal): Extension<Principal>,
    pool: Extension<PgPool>,
    Json(payload): Json<UserRoleRequest>,
) -> impl IntoResponse {
    let user_id = match Uuid::parse_str(id.trim()) {
        Ok(id) => id,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    let role = normalize_role(payload.role);
    if role.is_empty() {
        return (StatusCode::BAD_REQUEST, "Role is required.").into_response();
    }

    match assign_user_role(&pool, &principal, user_id, role).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(err) => err.into_response(),
    }
}

#[derive(Debug)]
enum ServiceError {
    Forbidden,
    BadRequest(&'static str),
    NotFound,
    Database(sqlx::Error),
}

impl IntoResponse for ServiceError {
    fn into_response(self) -> Response {
        match self {
            Self::Forbidden => StatusCode::FORBIDDEN.into_response(),
            Self::NotFound => StatusCode::NOT_FOUND.into_response(),
            Self::BadRequest(message) => (StatusCode::BAD_REQUEST, message).into_response(),
            Self::Database(err) => {
                error!("Failed to handle user request: {err}");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    }
}

fn ensure_permission(principal: &Principal, permission: Permission) -> Result<(), ServiceError> {
    if principal.allows(permission) {
        Ok(())
    } else {
        Err(ServiceError::Forbidden)
    }
}

async fn fetch_user_summaries(pool: &PgPool) -> Result<Vec<UserSummary>, sqlx::Error> {
    let query = r"
        SELECT id, email, display_name
        FROM users
        ORDER BY created_at DESC
    ";
    let rows = sqlx::query(query).fetch_all(pool).await?;
    Ok(rows
        .into_iter()
        .map(|row| UserSummary {
            id: row.get::<Uuid, _>("id").to_string(),
            email: row.get("email"),
            display_name: row.get("display_name"),
        })
        .collect())
}

async fn fetch_user_detail(pool: &PgPool, user_id: Uuid) -> Result<Option<UserDetail>, sqlx::Error> {
    let query = r#"
        SELECT
            u.id::text AS id,
            u.email,
            u.display_name,
            u.locale,
            r.role,
            to_char(u.created_at AT TIME ZONE 'utc', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS created_at,
            to_char(u.updated_at AT TIME ZONE 'utc', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS updated_at
        FROM users u
        LEFT JOIN user_roles r ON r.user_id = u.id
        WHERE u.id = $1
        LIMIT 1
    "#;
    let row = sqlx::query(query).bind(user_id).fetch_optional(pool).await?;
    Ok(row.map(|row| UserDetail {
        id: row.get("id"),
        email: row.get("email"),
        display_name: row.get("display_name"),
        locale: row.get("locale"),
        role: row.get("role"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    }))
}

async fn update_user_profile(
    pool: &PgPool,
    principal: &Principal,
    user_id: Uuid,
    display_name: Option<String>,
    locale: Option<String>,
) -> Result<Option<UserDetail>, ServiceError> {
    ensure_permission(principal, Permission::UsersWrite)?;
    let query = r#"
        UPDATE users
        SET
            display_name = COALESCE($1, display_name),
            locale = COALESCE($2, locale)
        WHERE id = $3
        RETURNING
            id::text AS id,
            email,
            display_name,
            locale,
            to_char(created_at AT TIME ZONE 'utc', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS created_at,
            to_char(updated_at AT TIME ZONE 'utc', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS updated_at
    "#;
    let row = sqlx::query(query)
        .bind(display_name)
        .bind(locale)
        .bind(user_id)
        .fetch_optional(pool)
        .await
        .map_err(ServiceError::Database)?;
    Ok(row.map(|row| UserDetail {
        id: row.get("id"),
        email: row.get("email"),
        display_name: row.get("display_name"),
        locale: row.get("locale"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    }))
}

async fn delete_user_record(
    pool: &PgPool,
    principal: &Principal,
    user_id: Uuid,
) -> Result<bool, ServiceError> {
    ensure_permission(principal, Permission::UsersDelete)?;
    let query = "DELETE FROM users WHERE id = $1";
    let result = sqlx::query(query)
        .bind(user_id)
        .execute(pool)
        .await
        .map_err(ServiceError::Database)?;
    Ok(result.rows_affected() > 0)
}

async fn assign_user_role(
    pool: &PgPool,
    principal: &Principal,
    user_id: Uuid,
    role: String,
) -> Result<UserRoleResponse, ServiceError> {
    ensure_permission(principal, Permission::UsersAssignRole)?;
    let mut tx = pool.begin().await.map_err(ServiceError::Database)?;

    let target_exists = sqlx::query("SELECT 1 FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(ServiceError::Database)?;
    if target_exists.is_none() {
        return Err(ServiceError::NotFound);
    }

    let role_exists = sqlx::query("SELECT 1 FROM roles WHERE name = $1")
        .bind(&role)
        .fetch_optional(&mut *tx)
        .await
        .map_err(ServiceError::Database)?;
    if role_exists.is_none() {
        return Err(ServiceError::BadRequest("Unknown role."));
    }

    let previous_role = sqlx::query("SELECT role FROM user_roles WHERE user_id = $1")
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(ServiceError::Database)?
        .map(|row| row.get::<String, _>("role"));

    let row = sqlx::query(
        r#"
        INSERT INTO user_roles (user_id, role, assigned_by, assigned_at)
        VALUES ($1, $2, $3, NOW())
        ON CONFLICT (user_id)
        DO UPDATE SET role = EXCLUDED.role, assigned_by = EXCLUDED.assigned_by, assigned_at = NOW()
        RETURNING
            role,
            to_char(assigned_at AT TIME ZONE 'utc', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS assigned_at
        "#,
    )
    .bind(user_id)
    .bind(&role)
    .bind(principal.user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(ServiceError::Database)?;

    if previous_role.as_deref() != Some(role.as_str()) {
        let _ = sqlx::query(
            r#"
            INSERT INTO role_audit_log (actor_id, target_id, previous_role, new_role)
            VALUES ($1, $2, $3, $4)
            "#,
        )
        .bind(principal.user_id)
        .bind(user_id)
        .bind(previous_role.as_deref())
        .bind(&role)
        .execute(&mut *tx)
        .await
        .map_err(ServiceError::Database)?;
    }

    tx.commit().await.map_err(ServiceError::Database)?;

    Ok(UserRoleResponse {
        id: user_id.to_string(),
        role: row.get("role"),
        assigned_at: row.get("assigned_at"),
    })
}

fn normalize_optional(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn normalize_role(value: String) -> String {
    value.trim().to_lowercase()
}
