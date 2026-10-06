//! Shared, encrypted, single-attempt OPAQUE login and reauthentication exchanges.
//!
//! Flow Overview: start seals the library's server transcript under a domain-separated
//! key derived from the Vault OPAQUE seed, then inserts it under a hashed random UUID.
//! Finish atomically deletes the row before verifying the proof. PostgreSQL owns time
//! and serializes capacity decisions; no exchange cache or replica affinity exists.
//! AEAD binds identity, password-record revision, purpose, original reauthentication
//! session, issuance/expiry and configured server ID. Database errors fail closed.
//!
//! This is transient protocol state, never a password or a Permesi session token.
//! Ciphertext may survive in PostgreSQL backups/WAL: encryption under a long-lived seed
//! does not promise cryptographic erasure or forward secrecy for archived transcripts.

use anyhow::{Context, Result, anyhow};
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use opaque_ke::{ServerLogin, ServerSetup};
use opaque_rand_chacha::ChaCha20Rng;
use opaque_rand_core::SeedableRng;
use secrecy::{ExposeSecret, SecretBox, SecretSlice, zeroize::Zeroizing};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Row, Transaction, postgres::PgRow};
use std::time::Duration;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use super::super::state::OpaqueSuite;

const KEY_LABEL: &[u8] = b"permesi/opaque-exchange/encryption-key/v1";

/// Server-derived identity and the exact registered credential used at start.
pub(in crate::api::handlers::auth) struct ExchangeIdentity {
    pub(in crate::api::handlers::auth) user_id: Uuid,
    pub(in crate::api::handlers::auth) credential_hash: [u8; 32],
}

/// Login cannot elevate a session; reauthentication belongs to one verified full session.
#[derive(Clone, Copy)]
pub(in crate::api::handlers::auth) enum ExchangePurpose {
    Login,
    Reauthenticate {
        user_id: Uuid,
        session_hash: [u8; 32],
    },
}

impl ExchangePurpose {
    /// Stable database discriminator; never selected from a browser field.
    fn name(self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::Reauthenticate { .. } => "reauth",
        }
    }

    /// Store only the verified session's hash for session-specific elevation.
    fn session_hash(self) -> Option<[u8; 32]> {
        match self {
            Self::Login => None,
            Self::Reauthenticate { session_hash, .. } => Some(session_hash),
        }
    }
}

/// Decrypted library state cannot be logged or serialized by an HTTP DTO.
pub(in crate::api::handlers::auth) struct OpaqueLoginState {
    pub(in crate::api::handlers::auth) state: ServerLogin<OpaqueSuite>,
    pub(in crate::api::handlers::auth) identity: Option<ExchangeIdentity>,
}

/// Shared cryptographic setup and limits; pending exchanges live exclusively in PostgreSQL.
pub struct OpaqueState {
    server_setup: ServerSetup<OpaqueSuite>,
    server_id: Vec<u8>,
    storage_seed: SecretBox<[u8; 32]>,
    login_ttl: Duration,
    max_pending_logins: usize,
}

struct ExchangeRow {
    id_hash: Vec<u8>,
    purpose: String,
    user_id: Option<Uuid>,
    credential_hash: Option<Vec<u8>>,
    session_hash: Option<Vec<u8>>,
    sealed_state: Vec<u8>,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    valid: bool,
}

impl ExchangeRow {
    /// Decode the consumed snapshot without panicking or exposing stored state in errors.
    fn from_row(row: &PgRow) -> Result<Self> {
        Ok(Self {
            id_hash: row.try_get("id_hash")?,
            purpose: row.try_get("purpose")?,
            user_id: row.try_get("user_id")?,
            credential_hash: row.try_get("credential_hash")?,
            session_hash: row.try_get("session_hash")?,
            sealed_state: row.try_get("sealed_state")?,
            created_at: row.try_get("created_at")?,
            expires_at: row.try_get("expires_at")?,
            valid: row.try_get("valid")?,
        })
    }
}

impl OpaqueState {
    /// Build deterministic setup for replicas sharing the Vault seed and server ID.
    /// The configured capacity is global across login and reauthentication exchanges.
    #[must_use]
    pub fn from_seed(
        seed: [u8; 32],
        server_id: String,
        login_ttl: Duration,
        max_pending_logins: usize,
    ) -> Self {
        let mut rng = ChaCha20Rng::from_seed(seed);
        Self {
            server_setup: ServerSetup::new(&mut rng),
            server_id: server_id.into_bytes(),
            storage_seed: SecretBox::new(Box::new(seed)),
            login_ttl,
            max_pending_logins,
        }
    }

    /// Setup contains server secret material and stays within the trusted protocol handlers.
    pub(in crate::api::handlers::auth) fn server_setup(&self) -> &ServerSetup<OpaqueSuite> {
        &self.server_setup
    }

    /// Identifier is bound into both the OPAQUE transcript and stored-state authentication.
    pub(in crate::api::handlers::auth) fn server_id(&self) -> &[u8] {
        &self.server_id
    }

    /// Expose configured expiration for tests without revealing secret setup material.
    #[cfg(test)]
    pub(in crate::api::handlers::auth) fn login_ttl(&self) -> Duration {
        self.login_ttl
    }

    /// Derive an independent AEAD key; fixed-size secret key material is zeroized on drop.
    fn cipher(&self) -> Result<ChaCha20Poly1305> {
        let mut mac =
            <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(self.storage_seed.expose_secret())
                .map_err(|_| anyhow!("OPAQUE state key derivation failed"))?;
        mac.update(KEY_LABEL);
        let key = Zeroizing::new(<[u8; 32]>::from(mac.finalize().into_bytes()));
        ChaCha20Poly1305::new_from_slice(key.as_ref())
            .map_err(|_| anyhow!("OPAQUE state key initialization failed"))
    }

    /// Bind the complete database snapshot and configured protocol identity into AEAD.
    fn aad(&self, row: &ExchangeRow) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&(
            KEY_LABEL,
            &row.id_hash,
            &row.purpose,
            row.user_id,
            &row.credential_hash,
            &row.session_hash,
            row.created_at.timestamp_micros(),
            row.expires_at.timestamp_micros(),
            &self.server_id,
        ))?)
    }

    /// Prune expired rows and serialize the global capacity check with insertion.
    /// Returns `None` only for capacity exhaustion; storage/crypto failures are errors.
    pub(in crate::api::handlers::auth) async fn store_login_state(
        &self,
        pool: &PgPool,
        state: ServerLogin<OpaqueSuite>,
        identity: Option<ExchangeIdentity>,
        purpose: ExchangePurpose,
        timeout_ms: i64,
    ) -> Result<Option<Uuid>> {
        let ttl = i64::try_from(self.login_ttl.as_secs()).context("invalid OPAQUE exchange TTL")?;
        let maximum =
            i64::try_from(self.max_pending_logins).context("invalid OPAQUE exchange capacity")?;
        if !(1..=3600).contains(&ttl) || maximum <= 0 {
            return Err(anyhow!("invalid OPAQUE exchange limits"));
        }
        let mut tx = begin(pool, timeout_ms).await?;
        sqlx::query(
            "SELECT pg_advisory_xact_lock(hashtextextended('permesi:opaque-exchanges:v1',0))",
        )
        .execute(&mut *tx)
        .await?;
        // Fresh database statement time keeps the expiry predicate indexable after acquiring the lock.
        sqlx::query("DELETE FROM opaque_exchanges WHERE expires_at <= statement_timestamp()")
            .execute(&mut *tx)
            .await?;
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM opaque_exchanges")
            .fetch_one(&mut *tx)
            .await?;
        if count >= maximum {
            tx.commit().await?;
            return Ok(None);
        }
        let id = Uuid::new_v4();
        let created_at: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *tx)
            .await?;
        let mut row = ExchangeRow {
            id_hash: hash_id(id).to_vec(),
            purpose: purpose.name().to_owned(),
            user_id: identity.as_ref().map(|value| value.user_id),
            credential_hash: identity.map(|value| value.credential_hash.to_vec()),
            session_hash: purpose.session_hash().map(|value| value.to_vec()),
            sealed_state: Vec::new(),
            created_at,
            expires_at: created_at + chrono::Duration::seconds(ttl),
            valid: true,
        };
        let plaintext = Zeroizing::new(state.serialize());
        let mut nonce_bytes = [0u8; 12];
        getrandom::fill(&mut nonce_bytes)?;
        let ciphertext = self
            .cipher()?
            .encrypt(
                &Nonce::from(nonce_bytes),
                Payload {
                    msg: plaintext.as_slice(),
                    aad: &self.aad(&row)?,
                },
            )
            .map_err(|_| anyhow!("OPAQUE state encryption failed"))?;
        row.sealed_state.extend_from_slice(&nonce_bytes);
        row.sealed_state.extend_from_slice(&ciphertext);
        sqlx::query("INSERT INTO opaque_exchanges (id_hash,purpose,user_id,credential_hash,session_hash,sealed_state,created_at,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)")
            .bind(row.id_hash).bind(row.purpose).bind(row.user_id).bind(row.credential_hash).bind(row.session_hash).bind(row.sealed_state).bind(row.created_at).bind(row.expires_at).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(Some(id))
    }

    /// Atomically consume before proof verification, including rejected purpose/session attempts.
    /// Concurrent callers have at most one row; expired or tampered state is unauthorized.
    pub(in crate::api::handlers::auth) async fn take_login_state(
        &self,
        pool: &PgPool,
        id: Uuid,
        purpose: ExchangePurpose,
        timeout_ms: i64,
    ) -> Result<Option<OpaqueLoginState>> {
        let mut tx = begin(pool, timeout_ms).await?;
        let row = sqlx::query("DELETE FROM opaque_exchanges WHERE id_hash=$1 RETURNING *,expires_at>clock_timestamp() AS valid").bind(hash_id(id).as_slice()).fetch_optional(&mut *tx).await?;
        tx.commit().await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let row = ExchangeRow::from_row(&row)?;
        if !row.valid || row.purpose != purpose.name() {
            return Ok(None);
        }
        if let ExchangePurpose::Reauthenticate {
            user_id,
            session_hash,
        } = purpose
            && (row.user_id != Some(user_id)
                || !bool::from(
                    row.session_hash
                        .as_deref()
                        .unwrap_or_default()
                        .ct_eq(&session_hash),
                ))
        {
            return Ok(None);
        }
        let Some((nonce, ciphertext)) = row.sealed_state.split_first_chunk::<12>() else {
            return Ok(None);
        };
        let plaintext = match self.cipher()?.decrypt(
            &Nonce::from(*nonce),
            Payload {
                msg: ciphertext,
                aad: &self.aad(&row)?,
            },
        ) {
            Ok(value) => SecretSlice::from(value),
            Err(_) => return Ok(None),
        };
        let Ok(state) = ServerLogin::<OpaqueSuite>::deserialize(plaintext.expose_secret()) else {
            return Ok(None);
        };
        let canonical = Zeroizing::new(state.serialize());
        if canonical.len() != plaintext.expose_secret().len() {
            return Ok(None);
        }
        let identity = match (row.user_id, row.credential_hash) {
            (Some(user_id), Some(hash)) => Some(ExchangeIdentity {
                user_id,
                credential_hash: hash
                    .try_into()
                    .map_err(|_| anyhow!("invalid OPAQUE identity binding"))?,
            }),
            (None, None) => None,
            _ => return Ok(None),
        };
        Ok(Some(OpaqueLoginState { state, identity }))
    }
}

/// Hash the unguessable external reference; plaintext login IDs never enter storage.
pub(in crate::api::handlers::auth) fn hash_id(id: Uuid) -> [u8; 32] {
    Sha256::digest(id.as_bytes()).into()
}

/// Prevent credential/status mutations racing successful session issuance or elevation.
/// Hold the returned transaction through the session write, then commit. Failed bindings
/// return no guard; callers must never issue authority without one.
pub(in crate::api::handlers::auth) async fn lock_identity<'a>(
    pool: &'a PgPool,
    identity: &ExchangeIdentity,
    timeout_ms: i64,
) -> Result<Option<Transaction<'a, Postgres>>> {
    let mut tx = begin(pool, timeout_ms).await?;
    let record: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT opaque_registration_record FROM users WHERE id=$1 AND status='active' FOR SHARE",
    )
    .bind(identity.user_id)
    .fetch_optional(&mut *tx)
    .await?;
    let valid = record.is_some_and(|record| {
        bool::from(<[u8; 32]>::from(Sha256::digest(&record)).ct_eq(&identity.credential_hash))
    });
    if !valid {
        tx.rollback().await?;
        return Ok(None);
    }
    Ok(Some(tx))
}

/// Apply transaction-local deadlines before any contended operation; invalid limits fail closed.
async fn begin(pool: &PgPool, timeout_ms: i64) -> Result<Transaction<'_, Postgres>> {
    if !(1..=10_000).contains(&timeout_ms) {
        return Err(anyhow!("invalid OPAQUE exchange deadline"));
    }
    let mut tx = pool.begin().await?;
    crate::oauth::locking::deadline(&mut tx, timeout_ms).await?;
    Ok(tx)
}
