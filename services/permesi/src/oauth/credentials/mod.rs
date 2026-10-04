//! Confidential-client credential lifecycle, separate from user consent and token issuance.
//!
//! Flow Overview: session management resolves a tenant application, hashing runs in
//! bounded blocking workers without database locks after a short preflight, then a PostgreSQL transaction rechecks
//! membership/ancestry and serializes one current plus one retiring credential. Only
//! issuance returns plaintext. Verification reloads and locks current shared authority
//! after hashing; the caller retains the transaction through eventual code redemption.
//! Worker permits are availability controls, never replica-local credential state.

mod crypto;
mod storage;

use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use clap::ArgMatches;
use secrecy::SecretString;
use sqlx::{PgPool, Postgres, Transaction};
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use uuid::Uuid;

use super::service::ApplicationContext;
use crypto::{ClientSecret, hash_secret, verify_secret};

/// Validated nonsecret hashing/rotation policy; management works with OIDC disabled.
#[derive(Clone, Debug)]
pub struct CredentialConfig {
    grace_seconds: i64,
    lock_timeout_ms: i64,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    workers: usize,
}

impl CredentialConfig {
    /// Revalidates bounded clap inputs before dispatch constructs application state.
    pub(crate) fn from_matches(matches: &ArgMatches) -> Result<Self> {
        let get = |name| {
            matches
                .get_one::<u32>(name)
                .copied()
                .context("missing credential policy")
        };
        let policy = Self {
            lock_timeout_ms: *matches
                .get_one::<i64>("oauth-lock-timeout-ms")
                .context("missing lock timeout")?,
            grace_seconds: *matches
                .get_one::<i64>("oauth-client-secret-grace-seconds")
                .context("missing credential grace")?,
            memory_kib: get("oauth-client-secret-memory-kib")?,
            iterations: get("oauth-client-secret-iterations")?,
            parallelism: get("oauth-client-secret-parallelism")?,
            workers: usize::try_from(get("oauth-client-secret-hash-workers")?)?,
        };
        ensure!(
            (1..=10000).contains(&policy.lock_timeout_ms)
                && (1..=3600).contains(&policy.grace_seconds)
                && (19456..=65536).contains(&policy.memory_kib)
                && (2..=6).contains(&policy.iterations)
                && (1..=4).contains(&policy.parallelism)
                && (1..=8).contains(&policy.workers),
            "invalid credential policy"
        );
        Ok(policy)
    }

    /// Inert fixtures use the production defaults without reading deployment environment.
    #[cfg(test)]
    pub(crate) fn for_tests() -> Self {
        Self {
            lock_timeout_ms: 1000,
            grace_seconds: 900,
            memory_kib: 19456,
            iterations: 2,
            parallelism: 1,
            workers: 2,
        }
    }
}

/// Value-free failures; database details never reach credential API responses.
#[derive(Debug, thiserror::Error)]
pub enum CredentialError {
    #[error("Credential resource inaccessible.")]
    NotFound,
    #[error("Credential operation is not permitted for this client.")]
    Invalid,
    #[error("Credential state changed or rotation overlap is still active.")]
    Conflict,
    #[error("Invalid client credentials.")]
    InvalidCredentials,
    #[error("Credential service temporarily unavailable.")]
    Unavailable,
    #[error("Credential persistence failed.")]
    Database(#[from] sqlx::Error),
}

/// Public credential metadata contains neither the PHC hash nor random secret material.
#[derive(Clone)]
pub(crate) struct SecretMetadata {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

impl sqlx::FromRow<'_, sqlx::postgres::PgRow> for SecretMetadata {
    /// Decodes the reviewed metadata columns without selecting credential hashes.
    fn from_row(row: &sqlx::postgres::PgRow) -> std::result::Result<Self, sqlx::Error> {
        use sqlx::Row;
        Ok(Self {
            id: row.try_get("id")?,
            created_at: row.try_get("created_at")?,
            expires_at: row.try_get("expires_at")?,
        })
    }
}

/// Plaintext exists only for the successful issuance response; no Debug implementation.
pub(crate) struct IssuedSecret {
    pub credential: SecretMetadata,
    pub client_secret: SecretString,
    pub previous: Option<SecretMetadata>,
}

/// Proof of client authentication only, with no user, consent, or OAuth scope authority.
/// The issuing transaction must remain open through redemption and token issuance.
pub struct AuthenticatedClient {
    client: Uuid,
    application: Uuid,
    organization: Uuid,
}

impl AuthenticatedClient {
    /// Returns the authenticated public client identifier for binding checks.
    #[must_use]
    pub const fn client_id(&self) -> Uuid {
        self.client
    }
    /// Returns the current application binding, never selected by secret input.
    #[must_use]
    pub const fn application_id(&self) -> Uuid {
        self.application
    }
    /// Returns the verified owning organization, not a user-wide tenant grant.
    #[must_use]
    pub const fn organization_id(&self) -> Uuid {
        self.organization
    }
}

/// Cloneable worker capacity and policy; PostgreSQL owns all credential lifecycle state.
#[derive(Clone)]
pub struct CredentialService {
    config: CredentialConfig,
    workers: Arc<Semaphore>,
    /// Test scheduling barriers prove rechecks after released preflight authority.
    #[cfg(test)]
    pub(crate) after_preflight: Option<Arc<tokio::sync::Barrier>>,
    /// Test scheduling barriers permit revocation/expiry before authentication rechecks.
    #[cfg(test)]
    pub(crate) after_verification: Option<Arc<tokio::sync::Barrier>>,
}

impl CredentialService {
    /// Constructs process-local CPU capacity, without storing credential authority locally.
    pub(crate) fn new(config: CredentialConfig) -> Self {
        Self {
            workers: Arc::new(Semaphore::new(config.workers)),
            config,
            #[cfg(test)]
            after_preflight: None,
            #[cfg(test)]
            after_verification: None,
        }
    }

    /// Rejects saturation immediately; no unbounded waiting queue or locks held for a permit.
    fn permit(&self) -> std::result::Result<OwnedSemaphorePermit, CredentialError> {
        self.workers
            .clone()
            .try_acquire_owned()
            .map_err(|_| CredentialError::Unavailable)
    }

    /// Holds all CPU permits so integration tests can verify authentication saturation.
    #[cfg(test)]
    pub(crate) fn saturate_for_test(
        &self,
    ) -> std::result::Result<OwnedSemaphorePermit, CredentialError> {
        let count = u32::try_from(self.config.workers).map_err(|_| CredentialError::Unavailable)?;
        self.workers
            .clone()
            .try_acquire_many_owned(count)
            .map_err(|_| CredentialError::Unavailable)
    }

    /// Lists only current/unexpired retiring metadata for an active tenant member.
    pub(crate) async fn list(
        &self,
        pool: &PgPool,
        context: &ApplicationContext,
        client: Uuid,
    ) -> std::result::Result<Vec<SecretMetadata>, CredentialError> {
        let mut tx = pool.begin().await?;
        storage::timeout(&mut tx, self.config.lock_timeout_ms).await?;
        let id = storage::management_client(&mut tx, context, client, false, false).await?;
        let rows = storage::live(&mut tx, id).await?;
        tx.commit().await?;
        Ok(rows)
    }

    /// Creates/rotates one high-entropy credential; preflight precedes hashing without locks.
    /// A stale expected current ID or live overlap returns conflict without changing state.
    pub(crate) async fn issue(
        &self,
        pool: &PgPool,
        context: &ApplicationContext,
        client: Uuid,
        expected: Option<Uuid>,
    ) -> std::result::Result<IssuedSecret, CredentialError> {
        // Reject inaccessible/unsupported/stale states before expensive hashing. Final
        // mutation reloads everything because the short preflight releases its locks.
        let mut preflight = pool.begin().await?;
        storage::timeout(&mut preflight, self.config.lock_timeout_ms).await?;
        let id = storage::management_client(&mut preflight, context, client, true, true).await?;
        let rows = storage::live(&mut preflight, id).await?;
        reviewed_current(&rows, expected)?;
        preflight.commit().await?;
        #[cfg(test)]
        if let Some(barrier) = &self.after_preflight {
            barrier.wait().await;
            barrier.wait().await;
        }
        let permit = self.permit()?;
        let policy = self.config.clone();
        let (id, raw, hash) = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            hash_secret(&policy)
        })
        .await
        .map_err(|_| CredentialError::Unavailable)??;
        let mut tx = pool.begin().await?;
        storage::timeout(&mut tx, self.config.lock_timeout_ms).await?;
        let client_id = storage::management_client(&mut tx, context, client, true, true).await?;
        let rows = storage::live(&mut tx, client_id).await?;
        let previous = match reviewed_current(&rows, expected)? {
            Some(current) => {
                Some(storage::retire(&mut tx, current.id, self.config.grace_seconds).await?)
            }
            None => None,
        };
        let credential = storage::insert(&mut tx, client_id, id, &hash).await?;
        tx.commit().await?;
        Ok(IssuedSecret {
            credential,
            client_secret: raw,
            previous,
        })
    }

    /// Revokes an owned credential at commit; repeated revocation succeeds.
    pub(crate) async fn revoke(
        &self,
        pool: &PgPool,
        context: &ApplicationContext,
        client: Uuid,
        secret: Uuid,
    ) -> std::result::Result<(), CredentialError> {
        let mut tx = pool.begin().await?;
        storage::timeout(&mut tx, self.config.lock_timeout_ms).await?;
        let id = storage::management_client(&mut tx, context, client, true, false).await?;
        storage::revoke(&mut tx, id, secret).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Verifies a confidential credential and locks client, ancestry and credential authority.
    /// Callers must throttle before this helper and retain the SAME transaction through code
    /// redemption/token issuance. This does not authorize any user, grant or delegated scope.
    ///
    /// # Errors
    /// Returns generic invalid credentials, capacity exhaustion, or a value-free database failure.
    pub async fn authenticate(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        client_id: Uuid,
        supplied: &str,
    ) -> std::result::Result<AuthenticatedClient, CredentialError> {
        let secret = ClientSecret::parse(supplied)?;
        let secret_id = secret.id;
        storage::timeout(tx, self.config.lock_timeout_ms).await?;
        let hash = storage::verification_hash(tx, client_id, secret.id).await?;
        let original_hash = hash.clone();
        let permit = self.permit()?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            verify_secret(&secret, &hash)
        })
        .await
        .map_err(|_| CredentialError::Unavailable)??;
        #[cfg(test)]
        if let Some(barrier) = &self.after_verification {
            barrier.wait().await;
            barrier.wait().await;
        }
        storage::verified_client(tx, client_id, secret_id, &original_hash).await
    }
}

/// Checks only expected credential state, never tenant authorization or secret possession.
/// Creation may preserve one retiring credential; rotation may not widen or extend overlap.
fn reviewed_current(
    rows: &[SecretMetadata],
    expected: Option<Uuid>,
) -> std::result::Result<Option<&SecretMetadata>, CredentialError> {
    let current = rows.iter().find(|row| row.expires_at.is_none());
    let retiring = rows.iter().any(|row| row.expires_at.is_some());
    match (expected, current) {
        (None, None) => Ok(None),
        (Some(expected), Some(current)) if expected == current.id && !retiring => Ok(Some(current)),
        _ => Err(CredentialError::Conflict),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn credential_workers_fail_closed_without_waiting_for_capacity() -> Result<()> {
        let service = CredentialService::new(CredentialConfig::for_tests());
        let _first = service.permit()?;
        let _second = service.permit()?;
        assert!(matches!(
            service.permit(),
            Err(CredentialError::Unavailable)
        ));
        let pool =
            sqlx::postgres::PgPoolOptions::new().connect_lazy("postgres://localhost/permesi")?;
        pool.close().await;
        let context = ApplicationContext::resolved(Uuid::new_v4(), Uuid::new_v4());
        assert!(matches!(
            service.issue(&pool, &context, Uuid::new_v4(), None).await,
            Err(CredentialError::Database(_))
        ));
        assert!(matches!(
            service.list(&pool, &context, Uuid::new_v4()).await,
            Err(CredentialError::Database(_))
        ));
        Ok(())
    }
}
