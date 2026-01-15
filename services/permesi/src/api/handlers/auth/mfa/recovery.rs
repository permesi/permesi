//! Recovery code generation and verification helpers.
//!
//! Recovery codes are intended for one-time account recovery when MFA factors
//! are unavailable. Codes are Argon2id-hashed with a server-side pepper.

use anyhow::{Context, Result};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use rand::{RngCore, rngs::OsRng};
use uuid::Uuid;

const RECOVERY_CODE_COUNT: usize = 10;
const RECOVERY_CODE_LEN: usize = 12;
const RECOVERY_CODE_GROUP_SIZE: usize = 4;
const RECOVERY_CODE_ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

/// A freshly generated recovery-code batch (plaintext + hashes).
#[derive(Debug)]
pub struct RecoveryCodeBatch {
    pub batch_id: Uuid,
    pub codes: Vec<String>,
    pub code_hashes: Vec<String>,
}

impl RecoveryCodeBatch {
    /// Generate a new recovery-code batch using the provided pepper.
    pub fn generate(pepper: &[u8]) -> Result<Self> {
        let mut rng = OsRng;
        Self::generate_with_rng(&mut rng, pepper)
    }

    fn generate_with_rng<R: RngCore + ?Sized>(rng: &mut R, pepper: &[u8]) -> Result<Self> {
        let mut codes = Vec::with_capacity(RECOVERY_CODE_COUNT);
        let mut code_hashes = Vec::with_capacity(RECOVERY_CODE_COUNT);
        for _ in 0..RECOVERY_CODE_COUNT {
            let code = generate_code(rng)?;
            let hash = hash_recovery_code(&code, pepper)?;
            codes.push(code);
            code_hashes.push(hash);
        }
        Ok(Self {
            batch_id: Uuid::new_v4(),
            codes,
            code_hashes,
        })
    }
}

/// Normalize a recovery code for verification.
pub fn normalize_recovery_code(input: &str) -> Result<String> {
    let normalized: String = input
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|ch| ch.to_ascii_uppercase())
        .collect();

    if normalized.len() != RECOVERY_CODE_LEN {
        return Err(anyhow::anyhow!("invalid recovery code length"));
    }

    if !normalized
        .as_bytes()
        .iter()
        .all(|ch| RECOVERY_CODE_ALPHABET.contains(ch))
    {
        return Err(anyhow::anyhow!("invalid recovery code characters"));
    }

    Ok(normalized)
}

/// Format a normalized recovery code for display.
pub fn format_recovery_code(normalized: &str) -> Result<String> {
    if normalized.len() != RECOVERY_CODE_LEN {
        return Err(anyhow::anyhow!("invalid recovery code length"));
    }
    let mut out = String::with_capacity(RECOVERY_CODE_LEN + 2);
    for (idx, chunk) in normalized
        .as_bytes()
        .chunks(RECOVERY_CODE_GROUP_SIZE)
        .enumerate()
    {
        if idx > 0 {
            out.push('-');
        }
        out.push_str(std::str::from_utf8(chunk).context("invalid recovery code chunk")?);
    }
    Ok(out)
}

/// Verify a recovery code against a stored hash.
pub fn verify_recovery_code(code: &str, stored_hash: &str, pepper: &[u8]) -> Result<bool> {
    let normalized = normalize_recovery_code(code)?;
    let parsed = PasswordHash::new(stored_hash)
        .map_err(|_| anyhow::anyhow!("invalid recovery code hash"))?;
    let argon2 = Argon2::new_with_secret(
        pepper,
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::default(),
    )
    .map_err(|_| anyhow::anyhow!("failed to initialize Argon2id"))?;
    Ok(argon2
        .verify_password(normalized.as_bytes(), &parsed)
        .is_ok())
}

/// Generate a single recovery code in grouped form.
fn generate_code<R: RngCore + ?Sized>(rng: &mut R) -> Result<String> {
    let mut raw = [0u8; RECOVERY_CODE_LEN];
    rng.fill_bytes(&mut raw);
    let mut normalized = String::with_capacity(RECOVERY_CODE_LEN);
    for byte in raw {
        let idx = usize::from(byte) % RECOVERY_CODE_ALPHABET.len();
        if let Some(&char_byte) = RECOVERY_CODE_ALPHABET.get(idx) {
            normalized.push(char_byte as char);
        }
    }
    format_recovery_code(&normalized)
}

/// Hash a recovery code using Argon2id with the server-side pepper.
fn hash_recovery_code(code: &str, pepper: &[u8]) -> Result<String> {
    let normalized = normalize_recovery_code(code)?;
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::new_with_secret(
        pepper,
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::default(),
    )
    .map_err(|_| anyhow::anyhow!("failed to initialize Argon2id"))?;
    let hash = argon2
        .hash_password(normalized.as_bytes(), &salt)
        .map_err(|_| anyhow::anyhow!("failed to hash recovery code"))?
        .to_string();
    Ok(hash)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{
        RecoveryCodeBatch, format_recovery_code, normalize_recovery_code, verify_recovery_code,
    };

    #[test]
    fn normalize_recovery_code_trims_and_uppercases() {
        let normalized = normalize_recovery_code("abcd-efgh-jklm").unwrap();
        assert_eq!(normalized, "ABCDEFGHJKLM");
    }

    #[test]
    fn format_recovery_code_groups() {
        let formatted = format_recovery_code("ABCDEFGHJKLM").unwrap();
        assert_eq!(formatted, "ABCD-EFGH-JKLM");
    }

    #[test]
    fn hash_and_verify_round_trip() {
        let pepper = b"pepper";
        let batch = RecoveryCodeBatch::generate(pepper).unwrap();
        let code = batch.codes.first().unwrap();
        let hash = batch.code_hashes.first().unwrap();
        assert!(verify_recovery_code(code, hash, pepper).unwrap());
        assert!(!verify_recovery_code("ABCD-EFGH-9999", hash, pepper).unwrap());
    }

    #[test]
    fn recovery_code_single_use_enforced() {
        let pepper = b"pepper";
        let batch = RecoveryCodeBatch::generate(pepper).unwrap();
        let code = batch.codes.first().unwrap();
        let hash = batch.code_hashes.first().unwrap();
        let mut used = false;

        let mut consume = |input: &str| {
            if used {
                return false;
            }
            if verify_recovery_code(input, hash, pepper).unwrap_or(false) {
                used = true;
                true
            } else {
                false
            }
        };

        assert!(consume(code));
        assert!(!consume(code));
    }
}
