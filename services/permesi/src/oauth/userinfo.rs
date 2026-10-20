//! OIDC `UserInfo` disclosure from exact, hash-only access-token issuance receipts.
//!
//! Flow Overview: the HTTP adapter accepts a bounded Bearer token in the Authorization
//! header. SHA-256 of that exact token locates a receipt committed with Vault signing;
//! RS256 and every authority claim are then checked against the receipt. Neither an
//! unverified JWT field nor a fabricated database receipt supplies identity or scope.
//! Current user, grant, membership,
//! client and ancestor state must still permit disclosure. Only the issued `openid`,
//! `profile` and `email` scopes select claims; internal principal permissions never do.

use serde::Serialize;
use sha2::{Digest as _, Sha256};
use sqlx::{PgPool, Row as _, postgres::PgRow};
use utoipa::ToSchema;
use uuid::Uuid;

use super::oidc::{AccessClaims, AccessVerifyError, OAuthState};

/// Minimal public subject and optional registry-authorized profile claims.
#[derive(Serialize, ToSchema)]
pub(crate) struct UserInfo {
    pub sub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
}

/// Distinguishes a denied token from a storage failure without reflecting token contents.
pub(crate) enum UserInfoError {
    InvalidToken,
    Limited,
    Unavailable,
}

/// Resolves only a live, originally issued OIDC access token under current authority.
pub(crate) async fn resolve(
    pool: &PgPool,
    oauth: &OAuthState,
    token: &str,
) -> Result<UserInfo, UserInfoError> {
    let issuer = oauth
        .config
        .issuer
        .as_deref()
        .ok_or(UserInfoError::Unavailable)?;
    let audience = oauth
        .config
        .audience
        .as_deref()
        .ok_or(UserInfoError::Unavailable)?;
    let hash = Sha256::digest(token.as_bytes()).to_vec();
    let row = load_receipt(pool, issuer, audience, &hash).await?;
    let db_now: chrono::DateTime<chrono::Utc> = row
        .try_get("db_now")
        .map_err(|_| UserInfoError::Unavailable)?;
    let claims = oauth
        .verify_access_token(token, db_now.timestamp())
        .await
        .map_err(|error| match error {
            AccessVerifyError::Invalid => UserInfoError::InvalidToken,
            AccessVerifyError::Unavailable => UserInfoError::Unavailable,
        })?;
    let scopes = check_receipt(&row, &claims)?;
    let email: String = row
        .try_get("email")
        .map_err(|_| UserInfoError::Unavailable)?;
    let name: Option<String> = row
        .try_get("display_name")
        .map_err(|_| UserInfoError::Unavailable)?;
    let verified: bool = row
        .try_get("email_verified")
        .map_err(|_| UserInfoError::Unavailable)?;
    let profile = scopes.iter().any(|scope| scope == "profile");
    let email_allowed = scopes.iter().any(|scope| scope == "email");
    Ok(UserInfo {
        sub: claims.sub.to_string(),
        name: if profile { name } else { None },
        email: email_allowed.then_some(email),
        email_verified: email_allowed.then_some(verified),
    })
}

/// Loads only a currently authorized receipt and user profile by exact token hash.
async fn load_receipt(
    pool: &PgPool,
    issuer: &str,
    audience: &str,
    hash: &[u8],
) -> Result<PgRow, UserInfoError> {
    sqlx::query(
        "SELECT clock_timestamp() AS db_now,i.user_id,u.email::text AS email,u.display_name,
                u.email_verified_at IS NOT NULL AS email_verified,i.scope_names,
                i.access_jti,c.client_id AS public_client_id,i.application_id,
                i.organization_id,i.grant_id,i.issued_at,i.access_expires_at
         FROM oauth_token_issuances i
         JOIN users u ON u.id=i.user_id AND u.status='active'
            AND u.authorization_revision=i.authorization_revision
         JOIN oauth_grants g ON g.id=i.grant_id AND g.user_id=i.user_id AND g.revoked_at IS NULL
         JOIN org_memberships m ON m.user_id=i.user_id AND m.org_id=i.organization_id AND m.status='active'
         JOIN oauth_clients c ON c.id=i.client_id AND c.application_id=i.application_id
            AND c.deleted_at IS NULL AND c.disabled_at IS NULL
         JOIN applications a ON a.id=i.application_id AND a.deleted_at IS NULL
         JOIN environments e ON e.id=a.environment_id AND e.deleted_at IS NULL
         JOIN projects p ON p.id=e.project_id AND p.deleted_at IS NULL
         JOIN organizations o ON o.id=p.org_id AND o.id=i.organization_id AND o.deleted_at IS NULL
         WHERE i.access_token_hash=$1 AND i.issuer=$2 AND i.audience=$3
           AND i.issued_at<=clock_timestamp() AND i.access_expires_at>clock_timestamp()
           AND 'openid'=ANY(i.scope_names)
         LIMIT 1",
    )
    .bind(hash)
    .bind(issuer)
    .bind(audience)
    .fetch_optional(pool)
    .await
    .map_err(|_| UserInfoError::Unavailable)?
    .ok_or(UserInfoError::InvalidToken)
}

/// Authorizes only exact signed claims from this receipt, including scopes and tenant.
/// Internal principal roles/scopes never participate in this delegated decision.
fn check_receipt(row: &PgRow, claims: &AccessClaims) -> Result<Vec<String>, UserInfoError> {
    let subject: Uuid = row
        .try_get("user_id")
        .map_err(|_| UserInfoError::Unavailable)?;
    let scopes: Vec<String> = row
        .try_get("scope_names")
        .map_err(|_| UserInfoError::Unavailable)?;
    let jti: Uuid = row
        .try_get("access_jti")
        .map_err(|_| UserInfoError::Unavailable)?;
    let client: Uuid = row
        .try_get("public_client_id")
        .map_err(|_| UserInfoError::Unavailable)?;
    let application: Uuid = row
        .try_get("application_id")
        .map_err(|_| UserInfoError::Unavailable)?;
    let organization: Uuid = row
        .try_get("organization_id")
        .map_err(|_| UserInfoError::Unavailable)?;
    let grant: Uuid = row
        .try_get("grant_id")
        .map_err(|_| UserInfoError::Unavailable)?;
    let issued_at: chrono::DateTime<chrono::Utc> = row
        .try_get("issued_at")
        .map_err(|_| UserInfoError::Unavailable)?;
    let expires_at: chrono::DateTime<chrono::Utc> = row
        .try_get("access_expires_at")
        .map_err(|_| UserInfoError::Unavailable)?;
    if claims.sub != subject
        || claims.jti != jti
        || claims.client_id != client
        || claims.application_id != application
        || claims.organization_id != organization
        || claims.grant_id != grant
        || claims.iat != issued_at.timestamp()
        || claims.exp != expires_at.timestamp()
        || claims.scope != scopes.join(" ")
    {
        return Err(UserInfoError::InvalidToken);
    }
    Ok(scopes)
}
