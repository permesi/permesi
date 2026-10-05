//! Transaction-owned code redemption for the token service and security tests.
//!
//! Flow Overview: hash external code, lock active client/ancestry, lock the matching
//! unused code, verify exact context/redirect/S256, recheck membership and consent,
//! then atomically mark consumed. The caller owns the transaction and must commit
//! consumption with token issuance; rollback restores usability after failed issuance.
//! This API does not authenticate confidential clients and is not an HTTP endpoint.
//! Future token adapters must authenticate the client before invoking this function.

use chrono::{DateTime, Utc};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

use super::{
    crypto::{CodeVerifier, PkceChallenge, SecretValue},
    storage::{current_scopes, grant_covers, lock_client, registered_redirect, set_lock_timeout},
};
use crate::oauth::{config::OAuthConfig, scope::OAuthScope};

/// Client/resource binding supplied by the authenticated token adapter.
/// The organization must be resolved from this client's server-side application ancestry.
pub struct RedemptionInput<'a> {
    pub code: &'a str,
    pub client_id: Uuid,
    pub redirect_uri: &'a str,
    pub code_verifier: &'a str,
    pub organization_id: Uuid,
}

/// Verified code snapshot, usable only when consumption and token issuance commit together.
/// No raw authorization code, verifier, session cookie, or internal Principal scope appears.
pub struct RedeemedCode {
    pub client_id: Uuid,
    pub user_id: Uuid,
    pub application_id: Uuid,
    pub organization_id: Uuid,
    pub grant_id: Uuid,
    pub scopes: Vec<OAuthScope>,
    pub nonce: Option<String>,
    pub issuer: String,
    pub audience: String,
    pub auth_time: DateTime<Utc>,
}

/// Value-free failure shared by wrong, expired, reused or no-longer-authorized codes.
#[derive(Debug, thiserror::Error)]
#[error("invalid_grant")]
pub struct RedemptionError;

/// Validates and consumes a code within the caller's transaction. Row locks and the
/// final guarded UPDATE permit exactly one concurrent committed redemption across replicas.
/// Wrong bindings and failed PKCE never consume a valid code. Client authentication
/// remains the caller's responsibility, and no tokens are issued by this helper.
/// The configured lock timeout applies to the caller's entire remaining transaction;
/// token adapters must preserve it or choose a stricter bound through issuance.
///
/// # Errors
/// Returns the same value-free error for all invalid codes or database failures.
pub async fn redeem_authorization_code(
    tx: &mut Transaction<'_, Postgres>,
    config: &OAuthConfig,
    input: RedemptionInput<'_>,
) -> Result<RedeemedCode, RedemptionError> {
    redeem(tx, config, input).await.map_err(|_| RedemptionError)
}

/// Keeps every code check under one transaction and excludes SQL/secret values from errors.
async fn redeem(
    tx: &mut Transaction<'_, Postgres>,
    config: &OAuthConfig,
    input: RedemptionInput<'_>,
) -> Result<RedeemedCode, super::Error> {
    set_lock_timeout(tx, config).await?;
    let invalid = || super::Error::protocol(super::ProtocolError::InvalidGrant);
    let code = SecretValue::parse(input.code).map_err(|_| invalid())?;
    let verifier = CodeVerifier::parse(input.code_verifier).map_err(|_| invalid())?;
    let context = lock_client(tx, input.client_id).await?;
    if context.organization_id != input.organization_id
        || !registered_redirect(tx, &context, input.redirect_uri).await?
    {
        return Err(invalid());
    }
    let row = sqlx::query("SELECT * FROM oauth_authorization_codes WHERE code_hash=$1 AND client_id=$2 AND application_id=$3 AND organization_id=$4 AND redirect_uri=$5 AND issuer=$6 AND audience=$7 AND consumed_at IS NULL AND expires_at>clock_timestamp() FOR UPDATE")
        .bind(code.hash()).bind(context.id).bind(context.application_id).bind(context.organization_id).bind(input.redirect_uri).bind(&config.issuer).bind(&config.audience)
        .fetch_optional(&mut **tx).await?.ok_or_else(invalid)?;
    let challenge = PkceChallenge::parse(
        row.try_get("code_challenge")?,
        row.try_get("code_challenge_method")?,
    )
    .map_err(|_| invalid())?;
    if !challenge.matches(&verifier) {
        return Err(invalid());
    }
    let user_id: Uuid = row.try_get("user_id")?;
    let grant_id: Uuid = row.try_get("grant_id")?;
    let grant = sqlx::query_scalar::<_, Uuid>("SELECT g.id FROM oauth_grants g JOIN users u ON u.id=g.user_id JOIN org_memberships m ON m.user_id=g.user_id AND m.org_id=g.organization_id WHERE g.id=$1 AND g.user_id=$2 AND g.client_id=$3 AND g.application_id=$4 AND g.organization_id=$5 AND g.revoked_at IS NULL AND u.status='active' AND m.status='active' FOR SHARE OF g,u,m")
        .bind(grant_id).bind(user_id).bind(context.id).bind(context.application_id).bind(context.organization_id)
        .fetch_optional(&mut **tx).await?;
    if grant.is_none() {
        return Err(invalid());
    }
    let ids: Vec<Uuid> = row.try_get("scope_ids")?;
    let names: Vec<String> = row.try_get("scope_names")?;
    current_scopes(tx, context.id, context.application_id, &ids, &names).await?;
    if !grant_covers(tx, grant_id, &ids).await? {
        return Err(invalid());
    }
    let scopes = names
        .into_iter()
        .map(OAuthScope::parse)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| invalid())?;
    let changed = sqlx::query("UPDATE oauth_authorization_codes SET consumed_at=clock_timestamp() WHERE code_hash=$1 AND consumed_at IS NULL AND expires_at>clock_timestamp()")
        .bind(code.hash()).execute(&mut **tx).await?;
    if changed.rows_affected() != 1 {
        return Err(invalid());
    }
    Ok(RedeemedCode {
        client_id: input.client_id,
        user_id,
        application_id: context.application_id,
        organization_id: context.organization_id,
        grant_id,
        scopes,
        nonce: row.try_get("nonce")?,
        issuer: row.try_get("issuer")?,
        audience: row.try_get("audience")?,
        auth_time: row.try_get("auth_time")?,
    })
}
