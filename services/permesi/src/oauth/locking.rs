//! Transaction-scoped client coordination shared by authorization and management.
//!
//! Flow Overview: readers acquire a shared PostgreSQL advisory lock before authority
//! row locks; writers check application ownership before acquiring the exclusive lock. Unlike overlapping
//! row-share holders, queued advisory writers prevent later readers from bypassing
//! revocation. Row locks still protect ancestry and database integrity. The stable
//! domain-separated public-client key works across replicas; collisions only serialize
//! unrelated clients and confer no authority.

use sha2::{Digest, Sha256};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

/// Bounds each lock attempt and entire statement, without changing session-wide policy.
pub(crate) async fn deadline(
    tx: &mut Transaction<'_, Postgres>,
    timeout_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "SELECT set_config('lock_timeout',$1,true),set_config('statement_timeout',$1,true)",
    )
    .bind(format!("{timeout_ms}ms"))
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Checks immutable application ownership before joining a client's exclusive queue.
/// The caller must resolve session/tenant permissions and recheck the locked row afterward.
/// Foreign or deleted registrations return false without touching another tenant's lock.
pub(crate) async fn lock_owned_client(
    tx: &mut Transaction<'_, Postgres>,
    application: Uuid,
    public_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let owned: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM oauth_clients WHERE application_id=$1 AND client_id=$2 AND deleted_at IS NULL)")
        .bind(application).bind(public_id).fetch_one(&mut **tx).await?;
    if owned {
        client(tx, public_id, true).await?;
    }
    Ok(owned)
}

/// Coordinates current-client authority until the caller's transaction finishes.
/// This lock grants no permission; all client/tenant predicates must still be checked.
pub(crate) async fn client(
    tx: &mut Transaction<'_, Postgres>,
    public_id: Uuid,
    exclusive: bool,
) -> Result<(), sqlx::Error> {
    let mut hash = Sha256::new();
    hash.update(b"permesi/oauth/client-authority/v1\0");
    hash.update(public_id.as_bytes());
    let digest = hash.finalize();
    let mut bytes = [0; 8];
    for (target, source) in bytes.iter_mut().zip(digest.iter()) {
        *target = *source;
    }
    let query = if exclusive {
        "SELECT pg_advisory_xact_lock($1)"
    } else {
        "SELECT pg_advisory_xact_lock_shared($1)"
    };
    sqlx::query(query)
        .bind(i64::from_be_bytes(bytes))
        .execute(&mut **tx)
        .await?;
    Ok(())
}
