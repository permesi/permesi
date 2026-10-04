//! Shared credential authority and transaction-owned locks; SQL selects never return plaintext.

use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

use super::{AuthenticatedClient, CredentialError, SecretMetadata};
use crate::oauth::service::ApplicationContext;

/// Bounds individual lock attempts and whole statements with the configured OAuth limit.
pub(super) async fn timeout(
    tx: &mut Transaction<'_, Postgres>,
    timeout_ms: i64,
) -> Result<(), CredentialError> {
    crate::oauth::locking::deadline(tx, timeout_ms).await?;
    Ok(())
}

/// Rechecks tenant ancestry and current owner/admin writes; caller-supplied roles never count.
/// Client locks serialize mutations with lifecycle changes, while parent locks prevent deletion.
pub(super) async fn management_client(
    tx: &mut Transaction<'_, Postgres>,
    context: &ApplicationContext,
    client: Uuid,
    write: bool,
    active: bool,
) -> Result<Uuid, CredentialError> {
    if write
        && !crate::oauth::locking::lock_owned_client(tx, context.application_id, client).await?
    {
        return Err(CredentialError::NotFound);
    }
    let query = if write {
        "SELECT c.id,c.client_type,c.disabled_at,o.id AS organization_id FROM oauth_clients c JOIN applications a ON a.id=c.application_id JOIN environments e ON e.id=a.environment_id JOIN projects p ON p.id=e.project_id JOIN organizations o ON o.id=p.org_id WHERE c.application_id=$1 AND c.client_id=$2 AND c.deleted_at IS NULL AND a.deleted_at IS NULL AND e.deleted_at IS NULL AND p.deleted_at IS NULL AND o.deleted_at IS NULL FOR UPDATE OF c FOR SHARE OF a,e,p,o"
    } else {
        "SELECT c.id,c.client_type,c.disabled_at,o.id AS organization_id FROM oauth_clients c JOIN applications a ON a.id=c.application_id JOIN environments e ON e.id=a.environment_id JOIN projects p ON p.id=e.project_id JOIN organizations o ON o.id=p.org_id WHERE c.application_id=$1 AND c.client_id=$2 AND c.deleted_at IS NULL AND a.deleted_at IS NULL AND e.deleted_at IS NULL AND p.deleted_at IS NULL AND o.deleted_at IS NULL"
    };
    let row = sqlx::query(query)
        .bind(context.application_id)
        .bind(client)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or(CredentialError::NotFound)?;
    let org: Uuid = row.try_get("organization_id")?;
    let member = sqlx::query_scalar::<_, Uuid>("SELECT m.user_id FROM org_memberships m JOIN users u ON u.id=m.user_id
        WHERE m.org_id=$1 AND m.user_id=$2 AND m.status='active' AND u.status='active' FOR SHARE OF m,u")
        .bind(org).bind(context.user_id).fetch_optional(&mut **tx).await?.ok_or(CredentialError::NotFound)?;
    if write {
        sqlx::query_scalar::<_, Uuid>(
            "SELECT user_id FROM org_member_roles WHERE user_id=$1
            AND org_id=$2 AND role_name IN ('owner','admin') ORDER BY role_name LIMIT 1 FOR SHARE",
        )
        .bind(member)
        .bind(org)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or(CredentialError::NotFound)?;
    }
    if row.try_get::<&str, _>("client_type")? != "confidential"
        || (active
            && row
                .try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("disabled_at")?
                .is_some())
    {
        return Err(CredentialError::Invalid);
    }
    Ok(row.try_get("id")?)
}

/// Reads the at-most-two usable metadata records; the client lock guards mutation races.
pub(super) async fn live(
    tx: &mut Transaction<'_, Postgres>,
    client: Uuid,
) -> Result<Vec<SecretMetadata>, CredentialError> {
    Ok(sqlx::query_as("SELECT id,created_at,expires_at FROM oauth_client_secrets WHERE client_id=$1
        AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>clock_timestamp()) ORDER BY created_at,id")
        .bind(client).fetch_all(&mut **tx).await?)
}

/// Retires the previous current credential without extending any existing deadline.
pub(super) async fn retire(
    tx: &mut Transaction<'_, Postgres>,
    secret: Uuid,
    grace: i64,
) -> Result<SecretMetadata, CredentialError> {
    Ok(sqlx::query_as("UPDATE oauth_client_secrets SET expires_at=clock_timestamp()+($2*INTERVAL '1 second')
        WHERE id=$1 AND expires_at IS NULL AND revoked_at IS NULL RETURNING id,created_at,expires_at")
        .bind(secret).bind(grace).fetch_one(&mut **tx).await?)
}

/// Stores only a PHC hash and returns reviewed metadata; the unique current index is a backstop.
pub(super) async fn insert(
    tx: &mut Transaction<'_, Postgres>,
    client: Uuid,
    id: Uuid,
    hash: &str,
) -> Result<SecretMetadata, CredentialError> {
    Ok(sqlx::query_as("INSERT INTO oauth_client_secrets(id,client_id,secret_hash,created_at) VALUES($1,$2,$3,clock_timestamp())
        RETURNING id,created_at,expires_at").bind(id).bind(client).bind(hash).fetch_one(&mut **tx).await?)
}

/// Soft-revokes an owned record; foreign-client IDs return not found and revoked IDs are idempotent.
pub(super) async fn revoke(
    tx: &mut Transaction<'_, Postgres>,
    client: Uuid,
    secret: Uuid,
) -> Result<(), CredentialError> {
    let result = sqlx::query("UPDATE oauth_client_secrets SET revoked_at=COALESCE(revoked_at,clock_timestamp()) WHERE client_id=$1 AND id=$2")
        .bind(client).bind(secret).execute(&mut **tx).await?;
    if result.rows_affected() == 0 {
        return Err(CredentialError::NotFound);
    }
    Ok(())
}

/// Loads a candidate PHC without locks; expensive verification grants no authority until rechecked.
pub(super) async fn verification_hash(
    tx: &mut Transaction<'_, Postgres>,
    client: Uuid,
    secret: Uuid,
) -> Result<String, CredentialError> {
    sqlx::query_scalar("SELECT s.secret_hash FROM oauth_client_secrets s JOIN oauth_clients c ON c.id=s.client_id
        WHERE c.client_id=$1 AND s.id=$2 AND s.revoked_at IS NULL AND (s.expires_at IS NULL OR s.expires_at>clock_timestamp())")
        .bind(client).bind(secret).fetch_optional(&mut **tx).await?.ok_or(CredentialError::InvalidCredentials)
}

/// Locks and reloads all current authority after hashing. The final expiry query runs AFTER
/// lock acquisition so a wait cannot authenticate a credential whose overlap just expired.
pub(super) async fn verified_client(
    tx: &mut Transaction<'_, Postgres>,
    client: Uuid,
    secret: Uuid,
    hash: &str,
) -> Result<AuthenticatedClient, CredentialError> {
    crate::oauth::locking::client(tx, client, false).await?;
    let row = sqlx::query("SELECT c.id,c.application_id,o.id AS organization_id FROM oauth_clients c
        JOIN applications a ON a.id=c.application_id JOIN environments e ON e.id=a.environment_id
        JOIN projects p ON p.id=e.project_id JOIN organizations o ON o.id=p.org_id
        WHERE c.client_id=$1 AND c.client_type='confidential' AND c.disabled_at IS NULL AND c.deleted_at IS NULL
        AND a.deleted_at IS NULL AND e.deleted_at IS NULL AND p.deleted_at IS NULL AND o.deleted_at IS NULL FOR SHARE OF c,a,e,p,o")
        .bind(client).fetch_optional(&mut **tx).await?.ok_or(CredentialError::InvalidCredentials)?;
    let internal_id: Uuid = row.try_get("id")?;
    sqlx::query_scalar::<_, Uuid>("SELECT id FROM oauth_client_secrets WHERE id=$1 AND client_id=$2 AND secret_hash=$3 FOR SHARE")
        .bind(secret).bind(internal_id).bind(hash).fetch_optional(&mut **tx).await?.ok_or(CredentialError::InvalidCredentials)?;
    let valid: bool = sqlx::query_scalar(
        "SELECT revoked_at IS NULL AND (expires_at IS NULL OR expires_at>clock_timestamp())
        FROM oauth_client_secrets WHERE id=$1",
    )
    .bind(secret)
    .fetch_one(&mut **tx)
    .await?;
    if !valid {
        return Err(CredentialError::InvalidCredentials);
    }
    Ok(AuthenticatedClient {
        client,
        application: row.try_get("application_id")?,
        organization: row.try_get("organization_id")?,
    })
}
