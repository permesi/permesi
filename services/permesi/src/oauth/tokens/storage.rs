//! Hash-only, immutable issuance receipts in the same transaction as code consumption.
//!
//! A unique code hash prevents a second issuance receipt. Context comes from the locked
//! consumed code, not from the HTTP form. Receipts survive redirect retirement but never
//! contain bearer material; the runtime role can only insert/read, and bounded retention
//! uses the existing privileged cleanup function.

use super::{
    TokenError,
    claims::Issued,
    request::{CodeRequest, RefreshRequest},
};
use secrecy::ExposeSecret as _;
use sha2::{Digest as _, Sha256};
use sqlx::{Postgres, Transaction};

/// Records hashes only after successful signing; expired output cannot be committed.
pub(super) async fn record(
    tx: &mut Transaction<'_, Postgres>,
    request: &CodeRequest,
    issued: &Issued,
) -> Result<(), TokenError> {
    let code_hash = Sha256::digest(request.code.expose_secret().as_bytes()).to_vec();
    let access_hash =
        Sha256::digest(issued.response.access_token.expose_secret().as_bytes()).to_vec();
    let id_hash = issued
        .response
        .id_token
        .as_ref()
        .map(|v| Sha256::digest(v.expose_secret().as_bytes()).to_vec());
    let result = sqlx::query("INSERT INTO oauth_token_issuances
        (access_jti,code_hash,access_token_hash,id_token_hash,grant_id,client_id,application_id,organization_id,user_id,issuer,audience,issued_at,access_expires_at,id_expires_at)
        SELECT $1,c.code_hash,$3,$4,c.grant_id,c.client_id,c.application_id,c.organization_id,c.user_id,c.issuer,c.audience,$5,$6,$7
        FROM oauth_authorization_codes c WHERE c.code_hash=$2 AND c.consumed_at IS NOT NULL
        AND $6>clock_timestamp() AND ($7::timestamptz IS NULL OR $7>clock_timestamp())")
        .bind(issued.jti).bind(code_hash).bind(access_hash).bind(id_hash).bind(issued.created_at)
        .bind(issued.access_expires_at).bind(issued.id_expires_at).execute(&mut **tx).await?;
    if result.rows_affected() != 1 {
        return Err(TokenError::Unavailable);
    }
    Ok(())
}

/// Records an immutable refresh-source receipt after rotation and signing, with no bearer plaintext.
pub(super) async fn record_refresh(
    tx: &mut Transaction<'_, Postgres>,
    request: &RefreshRequest,
    issued: &Issued,
) -> Result<(), TokenError> {
    let source = Sha256::digest(request.token.expose_secret().as_bytes()).to_vec();
    let access = Sha256::digest(issued.response.access_token.expose_secret().as_bytes()).to_vec();
    let result = sqlx::query("INSERT INTO oauth_token_issuances
        (access_jti,refresh_hash,access_token_hash,grant_id,client_id,application_id,organization_id,user_id,issuer,audience,issued_at,access_expires_at)
        SELECT $1,t.token_hash,$3,f.grant_id,f.client_id,f.application_id,f.organization_id,f.user_id,f.issuer,f.audience,$4,$5
        FROM oauth_refresh_tokens t JOIN oauth_refresh_families f ON f.id=t.family_id
        WHERE t.token_hash=$2 AND t.consumed_at IS NOT NULL AND $5>clock_timestamp()")
        .bind(issued.jti).bind(source).bind(access).bind(issued.created_at).bind(issued.access_expires_at)
        .execute(&mut **tx).await?;
    if result.rows_affected() != 1 {
        return Err(TokenError::Unavailable);
    }
    Ok(())
}
