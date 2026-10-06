//! Durable tenant-bound refresh families with strict single-use rotation and replay revocation.
//!
//! Flow Overview: explicit offline consent at code exchange creates one immutable family
//! and a hashed 256-bit root token. Each refresh authenticates the client first, locks the
//! user before the family (matching password/recovery revocation), rechecks current tenant,
//! grant and every originally consented registry edge, consumes the old token and stores a
//! hashed successor. Signing and immutable receipts commit with rotation. Reuse commits
//! family revocation before returning `invalid_grant`, including a concurrent loser's reuse.
//! No grace window or process-local state exists. Lost responses require reauthorization.

use chrono::{DateTime, Utc};
use secrecy::{ExposeSecret as _, SecretString};
use sqlx::{Postgres, Row, Transaction, postgres::PgRow};
use uuid::Uuid;

use super::{
    TokenError,
    claims::TokenResponse,
    request::{CodeRequest, RefreshRequest},
};
use crate::oauth::{
    authorization::{
        crypto::SecretValue,
        redemption::RedeemedCode,
        storage::{current_scopes, grant_covers, lock_client},
    },
    oidc::OAuthState,
    scope::OAuthScope,
};

/// A denied terminal transition must be committed rather than silently rolled back with an error.
pub(super) enum Outcome {
    Ready {
        code: Box<RedeemedCode>,
        replacement: SecretString,
    },
    Revoked,
}

/// Creates a family only from a consumed offline code with exact prompt=consent bindings.
pub(super) async fn create(
    tx: &mut Transaction<'_, Postgres>,
    oauth: &OAuthState,
    request: &CodeRequest,
) -> Result<SecretString, TokenError> {
    let code =
        SecretValue::parse(request.code.expose_secret()).map_err(|_| TokenError::InvalidGrant)?;
    let family: Uuid = sqlx::query_scalar("INSERT INTO oauth_refresh_families
        (source_code_hash,client_id,application_id,organization_id,user_id,grant_id,authorization_revision,
         scope_ids,scope_names,issuer,audience,auth_time,issued_at,expires_at,idle_ttl_seconds)
        SELECT c.code_hash,c.client_id,c.application_id,c.organization_id,c.user_id,c.grant_id,c.authorization_revision,
         c.scope_ids,c.scope_names,c.issuer,c.audience,c.auth_time,statement_timestamp(),statement_timestamp()+$2*INTERVAL '1 second',$3
        FROM oauth_authorization_codes c WHERE c.code_hash=$1 AND c.consumed_at IS NOT NULL RETURNING id")
        .bind(code.hash()).bind(oauth.config.tokens.refresh_absolute_ttl).bind(oauth.config.tokens.refresh_idle_ttl)
        .fetch_one(&mut **tx).await?;
    insert_token(tx, oauth, family, None).await
}

/// Stores only a token hash, with idle expiry capped by the immutable absolute family limit.
async fn insert_token(
    tx: &mut Transaction<'_, Postgres>,
    oauth: &OAuthState,
    family: Uuid,
    previous: Option<&[u8]>,
) -> Result<SecretString, TokenError> {
    let token = SecretValue::generate().map_err(|_| TokenError::Unavailable)?;
    let inserted = sqlx::query("INSERT INTO oauth_refresh_tokens (token_hash,family_id,previous_hash,issued_at,expires_at)
        SELECT $1,id,$3,statement_timestamp(),LEAST(expires_at,statement_timestamp()+LEAST(idle_ttl_seconds,$4)*INTERVAL '1 second')
        FROM oauth_refresh_families WHERE id=$2 AND revoked_at IS NULL AND expires_at>clock_timestamp()")
        .bind(token.hash()).bind(family).bind(previous).bind(oauth.config.tokens.refresh_idle_ttl)
        .execute(&mut **tx).await?;
    if inserted.rows_affected() != 1 {
        return Err(TokenError::InvalidGrant);
    }
    Ok(SecretString::from(token.expose().to_owned()))
}

/// Reads identity first, locks that user before family state, and never burns another client's token.
pub(super) async fn rotate(
    tx: &mut Transaction<'_, Postgres>,
    oauth: &OAuthState,
    client: Uuid,
    request: &RefreshRequest,
) -> Result<Outcome, TokenError> {
    let token =
        SecretValue::parse(request.token.expose_secret()).map_err(|_| TokenError::InvalidGrant)?;
    let context = lock_client(tx, client).await.map_err(|e| {
        if e.database {
            TokenError::Unavailable
        } else {
            TokenError::InvalidClient
        }
    })?;
    let identity: Option<(Uuid,Uuid)> = sqlx::query_as("SELECT f.id,f.user_id FROM oauth_refresh_tokens t JOIN oauth_refresh_families f ON f.id=t.family_id WHERE t.token_hash=$1 AND f.client_id=$2 AND f.application_id=$3 AND f.organization_id=$4")
        .bind(token.hash()).bind(context.id).bind(context.application_id).bind(context.organization_id)
        .fetch_optional(&mut **tx).await?;
    let (family, user) = identity.ok_or(TokenError::InvalidGrant)?;
    let current: Option<(String, Uuid)> = sqlx::query_as(
        "SELECT status::text,authorization_revision FROM users WHERE id=$1 FOR SHARE",
    )
    .bind(user)
    .fetch_optional(&mut **tx)
    .await?;
    let row = sqlx::query("SELECT *,expires_at>clock_timestamp() AS alive FROM oauth_refresh_families WHERE id=$1 FOR UPDATE")
        .bind(family).fetch_optional(&mut **tx).await?.ok_or(TokenError::InvalidGrant)?;
    if row
        .try_get::<Option<DateTime<Utc>>, _>("revoked_at")?
        .is_some()
        || !row.try_get::<bool, _>("alive")?
    {
        return Err(TokenError::InvalidGrant);
    }
    let proof = sqlx::query("SELECT consumed_at,expires_at>clock_timestamp() AS alive FROM oauth_refresh_tokens WHERE token_hash=$1 AND family_id=$2 FOR UPDATE")
        .bind(token.hash()).bind(family).fetch_optional(&mut **tx).await?.ok_or(TokenError::InvalidGrant)?;
    if proof
        .try_get::<Option<DateTime<Utc>>, _>("consumed_at")?
        .is_some()
    {
        revoke(tx, family, "reuse").await?;
        return Ok(Outcome::Revoked);
    }
    if !proof.try_get::<bool, _>("alive")? {
        return Err(TokenError::InvalidGrant);
    }
    let revision: Uuid = row.try_get("authorization_revision")?;
    if current
        .as_ref()
        .is_none_or(|(status, epoch)| status != "active" || *epoch != revision)
        || row.try_get::<String, _>("issuer")?
            != oauth
                .config
                .issuer
                .as_deref()
                .ok_or(TokenError::Unavailable)?
        || row.try_get::<String, _>("audience")?
            != oauth
                .config
                .audience
                .as_deref()
                .ok_or(TokenError::Unavailable)?
    {
        revoke(tx, family, "authority").await?;
        return Ok(Outcome::Revoked);
    }
    let authority = current_authority(tx, &row, client).await;
    let mut code = match authority {
        Ok(Some(code)) => code,
        Ok(None) => {
            revoke(tx, family, "authority").await?;
            return Ok(Outcome::Revoked);
        }
        Err(error) => return Err(error),
    };
    if let Some(scopes) = &request.scopes {
        validate_subset(scopes, &code.scopes)?;
        code.scopes.clone_from(scopes);
    }
    let changed = sqlx::query("UPDATE oauth_refresh_tokens SET consumed_at=clock_timestamp() WHERE token_hash=$1 AND consumed_at IS NULL AND expires_at>clock_timestamp()")
        .bind(token.hash()).execute(&mut **tx).await?;
    if changed.rows_affected() != 1 {
        return Err(TokenError::InvalidGrant);
    }
    let replacement = insert_token(tx, oauth, family, Some(&token.hash())).await?;
    Ok(Outcome::Ready {
        code: Box::new(code),
        replacement,
    })
}

/// Rechecks all original consent, registry identities and current membership without internal roles.
async fn current_authority(
    tx: &mut Transaction<'_, Postgres>,
    row: &PgRow,
    public_client: Uuid,
) -> Result<Option<RedeemedCode>, TokenError> {
    let grant: Uuid = row.try_get("grant_id")?;
    let client: Uuid = row.try_get("client_id")?;
    let app: Uuid = row.try_get("application_id")?;
    let org: Uuid = row.try_get("organization_id")?;
    let user: Uuid = row.try_get("user_id")?;
    let valid: Option<Uuid> = sqlx::query_scalar("SELECT g.id FROM oauth_grants g JOIN org_memberships m ON m.user_id=g.user_id AND m.org_id=g.organization_id WHERE g.id=$1 AND g.client_id=$2 AND g.application_id=$3 AND g.organization_id=$4 AND g.user_id=$5 AND g.revoked_at IS NULL AND m.status='active' FOR SHARE OF g,m")
        .bind(grant).bind(client).bind(app).bind(org).bind(user).fetch_optional(&mut **tx).await?;
    if valid.is_none() {
        return Ok(None);
    }
    let ids: Vec<Uuid> = row.try_get("scope_ids")?;
    let names: Vec<String> = row.try_get("scope_names")?;
    if let Err(error) = current_scopes(tx, client, app, &ids, &names).await {
        return if error.database {
            Err(TokenError::Unavailable)
        } else {
            Ok(None)
        };
    }
    if !grant_covers(tx, grant, &ids)
        .await
        .map_err(|_| TokenError::Unavailable)?
    {
        return Ok(None);
    }
    let scopes = names
        .into_iter()
        .map(OAuthScope::parse)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| TokenError::InvalidGrant)?;
    Ok(Some(RedeemedCode {
        client_id: public_client,
        user_id: user,
        application_id: app,
        organization_id: org,
        grant_id: grant,
        scopes,
        nonce: None,
        issuer: row.try_get("issuer")?,
        audience: row.try_get("audience")?,
        auth_time: row.try_get("auth_time")?,
    }))
}

/// Authorizes only a nonempty subset, retaining protocol scope dependencies and exact casing.
fn validate_subset(requested: &[OAuthScope], allowed: &[OAuthScope]) -> Result<(), TokenError> {
    let openid = requested.iter().any(|s| s.as_str() == "openid");
    if requested.is_empty()
        || requested.iter().any(|s| !allowed.contains(s))
        || (!openid
            && requested.iter().any(|s| {
                matches!(
                    s.as_str(),
                    "profile" | "email" | "address" | "phone" | "offline_access"
                )
            }))
    {
        return Err(TokenError::InvalidScope);
    }
    Ok(())
}

/// Irreversibly revokes the locked family; callers commit this even when returning `invalid_grant`.
async fn revoke(
    tx: &mut Transaction<'_, Postgres>,
    family: Uuid,
    reason: &str,
) -> Result<(), TokenError> {
    sqlx::query("UPDATE oauth_refresh_families SET revoked_at=clock_timestamp(),revocation_reason=$2 WHERE id=$1 AND revoked_at IS NULL")
        .bind(family).bind(reason).execute(&mut **tx).await?;
    Ok(())
}

/// Prevents returning an already expired refresh successor after slow signing or SQL work.
pub(super) async fn check_output(
    tx: &mut Transaction<'_, Postgres>,
    response: &TokenResponse,
) -> Result<(), TokenError> {
    let Some(token) = &response.refresh_token else {
        return Ok(());
    };
    let value = SecretValue::parse(token.expose_secret()).map_err(|_| TokenError::Unavailable)?;
    let alive: bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM oauth_refresh_tokens t JOIN oauth_refresh_families f ON f.id=t.family_id WHERE t.token_hash=$1 AND t.consumed_at IS NULL AND t.expires_at>clock_timestamp() AND f.revoked_at IS NULL AND f.expires_at>clock_timestamp())")
        .bind(value.hash()).fetch_one(&mut **tx).await?;
    if !alive {
        return Err(TokenError::Unavailable);
    }
    Ok(())
}
