//! Durable, sealed `WebAuthn` ceremony state shared by all Permesi replicas.
//!
//! Flow Overview: generate a random reference, seal the library state with its
//! server-derived purpose/origin/RP/user/session bindings, and insert under its hash.
//! Finish commits an atomic DELETE before interpreting the proof, so failed proofs,
//! restarts and concurrent requests cannot replay a challenge. PostgreSQL supplies
//! time and serializes bounded capacity. There is no process-local fallback.

use anyhow::{Context, Result, anyhow, ensure};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use secrecy::{ExposeSecret, SecretBox, zeroize::Zeroizing};
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use uuid::Uuid;

const LABEL: &[u8] = b"permesi/webauthn-exchange/v1";

/// Server-selected ceremony type; a browser cannot choose the verification path.
#[derive(Clone, Copy)]
pub(crate) enum Purpose {
    PasskeyRegistration,
    PasskeyLogin,
    SecurityKeyRegistration,
    SecurityKeyAuthentication,
}

impl Purpose {
    /// Stable schema discriminator included in authenticated metadata.
    const fn name(self) -> &'static str {
        match self {
            Self::PasskeyRegistration => "passkey_registration",
            Self::PasskeyLogin => "passkey_login",
            Self::SecurityKeyRegistration => "security_key_registration",
            Self::SecurityKeyAuthentication => "security_key_authentication",
        }
    }
}

/// Exact authority bindings resolved by the endpoint, never deserialized from a request.
pub(crate) struct Binding<'a> {
    pub(crate) purpose: Purpose,
    pub(crate) origin: &'a str,
    pub(crate) user: Option<Uuid>,
    pub(crate) session: Option<&'a [u8]>,
}

/// Replicas share the Vault seed and RP configuration; only sealed state resides in SQL.
pub(crate) struct ExchangeStore {
    pool: PgPool,
    key: SecretBox<[u8; 32]>,
    rp_id: String,
    ttl: i64,
    capacity: i64,
    timeout_ms: i64,
}

impl ExchangeStore {
    /// Derives a separate `XChaCha20` key and rejects unusable TTL/capacity/deadline policy.
    pub(crate) fn new(
        pool: PgPool,
        seed: &[u8; 32],
        rp_id: String,
        ttl: i64,
        capacity: usize,
        timeout_ms: i64,
    ) -> Result<Self> {
        ensure!(
            (1..=3600).contains(&ttl) && (1..=10000).contains(&timeout_ms) && capacity > 0,
            "invalid WebAuthn exchange policy"
        );
        let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(seed)
            .map_err(|_| anyhow!("WebAuthn state key unavailable"))?;
        mac.update(LABEL);
        Ok(Self {
            pool,
            key: SecretBox::new(Box::new(mac.finalize().into_bytes().into())),
            rp_id,
            ttl,
            capacity: i64::try_from(capacity)?,
            timeout_ms,
        })
    }

    /// Inserts sealed state under a hashed reference, with shared per-purpose capacity.
    pub(crate) async fn put<T: Serialize>(&self, binding: Binding<'_>, state: &T) -> Result<Uuid> {
        let mut tx = self.pool.begin().await?;
        crate::oauth::locking::deadline(&mut tx, self.timeout_ms).await?;
        sqlx::query(
            "SELECT pg_advisory_xact_lock(hashtextextended('permesi:webauthn-exchanges:v1',0))",
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM webauthn_exchanges WHERE expires_at<=statement_timestamp()")
            .execute(&mut *tx)
            .await?;
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM webauthn_exchanges WHERE purpose=$1")
                .bind(binding.purpose.name())
                .fetch_one(&mut *tx)
                .await?;
        ensure!(
            count < self.capacity,
            "WebAuthn exchange capacity exhausted"
        );
        let id = Uuid::new_v4();
        let hash = Sha256::digest(id.as_bytes()).to_vec();
        let created: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *tx)
            .await?;
        let expires = created + chrono::Duration::seconds(self.ttl);
        let aad = self.aad(&hash, &binding, created, expires)?;
        let plain = Zeroizing::new(serde_json::to_vec(state)?);
        ensure!(plain.len() <= 65536, "WebAuthn state exceeds storage bound");
        let mut nonce = [0; 24];
        getrandom::fill(&mut nonce)?;
        let cipher = XChaCha20Poly1305::new_from_slice(self.key.expose_secret())
            .map_err(|_| anyhow!("WebAuthn state key unavailable"))?;
        let mut sealed = nonce.to_vec();
        sealed.extend(
            cipher
                .encrypt(
                    &XNonce::from(nonce),
                    Payload {
                        msg: &plain,
                        aad: &aad,
                    },
                )
                .map_err(|_| anyhow!("WebAuthn state sealing failed"))?,
        );
        sqlx::query("INSERT INTO webauthn_exchanges (id_hash,purpose,origin,rp_id,user_id,session_hash,sealed_state,created_at,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)")
            .bind(hash).bind(binding.purpose.name()).bind(binding.origin).bind(&self.rp_id).bind(binding.user).bind(binding.session).bind(sealed).bind(created).bind(expires).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(id)
    }

    /// Commits consumption before proof checking; wrong bindings also burn the reference.
    /// Storage errors fail closed and never retrieve replica-local state.
    pub(crate) async fn take<T: DeserializeOwned>(
        &self,
        id: Uuid,
        binding: Binding<'_>,
    ) -> Result<T> {
        let mut tx = self.pool.begin().await?;
        crate::oauth::locking::deadline(&mut tx, self.timeout_ms).await?;
        let hash = Sha256::digest(id.as_bytes()).to_vec();
        let row = sqlx::query("DELETE FROM webauthn_exchanges WHERE id_hash=$1 RETURNING *,expires_at>clock_timestamp() AS valid").bind(&hash).fetch_optional(&mut *tx).await?;
        tx.commit().await?;
        let row = row.context("WebAuthn exchange unavailable")?;
        let user: Option<Uuid> = row.try_get("user_id")?;
        let session: Option<Vec<u8>> = row.try_get("session_hash")?;
        ensure!(
            row.try_get::<bool, _>("valid")?
                && row.try_get::<String, _>("purpose")? == binding.purpose.name()
                && row.try_get::<String, _>("origin")? == binding.origin
                && row.try_get::<String, _>("rp_id")? == self.rp_id
                && user == binding.user
                && session.as_deref() == binding.session,
            "WebAuthn exchange unavailable"
        );
        let aad = self.aad(
            &hash,
            &binding,
            row.try_get("created_at")?,
            row.try_get("expires_at")?,
        )?;
        let sealed: Vec<u8> = row.try_get("sealed_state")?;
        let nonce: [u8; 24] = sealed
            .get(..24)
            .context("WebAuthn exchange unavailable")?
            .try_into()?;
        let cipher = XChaCha20Poly1305::new_from_slice(self.key.expose_secret())
            .map_err(|_| anyhow!("WebAuthn state key unavailable"))?;
        let plain = Zeroizing::new(
            cipher
                .decrypt(
                    &XNonce::from(nonce),
                    Payload {
                        msg: sealed.get(24..).context("WebAuthn exchange unavailable")?,
                        aad: &aad,
                    },
                )
                .map_err(|_| anyhow!("WebAuthn exchange unavailable"))?,
        );
        serde_json::from_slice(&plain).context("WebAuthn exchange unavailable")
    }

    /// Deletes a failed pre-verification attempt without exposing its stored bindings.
    pub(crate) async fn discard(&self, id: Uuid) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        crate::oauth::locking::deadline(&mut tx, self.timeout_ms).await?;
        sqlx::query("DELETE FROM webauthn_exchanges WHERE id_hash=$1")
            .bind(Sha256::digest(id.as_bytes()).as_slice())
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Authenticates every authority field and database timestamp alongside the ciphertext.
    fn aad(
        &self,
        hash: &[u8],
        binding: &Binding<'_>,
        created: DateTime<Utc>,
        expires: DateTime<Utc>,
    ) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&(
            LABEL,
            hash,
            binding.purpose.name(),
            binding.origin,
            &self.rp_id,
            binding.user,
            binding.session,
            created.timestamp_micros(),
            expires.timestamp_micros(),
        ))?)
    }
}
