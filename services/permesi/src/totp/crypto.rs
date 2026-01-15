use anyhow::Result;
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use rand::{RngCore, rngs::OsRng};
use uuid::Uuid;

/// Encrypts the seed using the provided DEK and context (AAD).
/// Returns `nonce (12 bytes) || ciphertext`.
///
/// # Errors
/// Returns an error if encryption fails.
#[allow(deprecated)]
pub fn encrypt_seed(
    dek: &[u8],
    seed: &[u8],
    tenant_id: Option<Uuid>, // Optional if not strict multi-tenant yet, but good for AAD
    user_id: Uuid,
    credential_id: Uuid,
) -> Result<Vec<u8>> {
    let key = Key::from_slice(dek); // 32-bytes
    let cipher = ChaCha20Poly1305::new(key);

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let aad = construct_aad(tenant_id, user_id, credential_id);
    let payload = Payload {
        msg: seed,
        aad: &aad,
    };

    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|e| anyhow::anyhow!("Encryption failure: {e}"))?;

    let mut result = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypts the seed using the provided DEK.
/// Expects `data` to be `nonce (12 bytes) || ciphertext`.
///
/// # Errors
/// Returns an error if decryption fails or if ciphertext is too short.
#[allow(deprecated)]
pub fn decrypt_seed(
    dek: &[u8],
    data: &[u8],
    tenant_id: Option<Uuid>,
    user_id: Uuid,
    credential_id: Uuid,
) -> Result<Vec<u8>> {
    if data.len() < 12 {
        return Err(anyhow::anyhow!("Invalid ciphertext length"));
    }

    let (nonce_bytes, ciphertext) = data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    let key = Key::from_slice(dek);
    let cipher = ChaCha20Poly1305::new(key);

    let aad = construct_aad(tenant_id, user_id, credential_id);
    let payload = Payload {
        msg: ciphertext,
        aad: &aad,
    };

    let plaintext = cipher
        .decrypt(nonce, payload)
        .map_err(|e| anyhow::anyhow!("Decryption failure: {e}"))?;

    Ok(plaintext)
}

fn construct_aad(tenant_id: Option<Uuid>, user_id: Uuid, credential_id: Uuid) -> Vec<u8> {
    // AAD = "totp-seed:v1|tenant_id|user_id|credential_id"
    let tid = tenant_id.unwrap_or_default();
    format!("totp-seed:v1|{tid}|{user_id}|{credential_id}").into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_encrypt_decrypt_roundtrip() {
        let dek = [42u8; 32];
        let seed = b"my-secret-seed-123";
        let user_id = Uuid::new_v4();
        let credential_id = Uuid::new_v4();

        let encrypted = encrypt_seed(&dek, seed, None, user_id, credential_id).unwrap();
        assert_ne!(encrypted, seed);
        assert!(encrypted.len() > seed.len());

        let decrypted = decrypt_seed(&dek, &encrypted, None, user_id, credential_id).unwrap();
        assert_eq!(decrypted, seed);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_decrypt_fails_wrong_aad() {
        let dek = [42u8; 32];
        let seed = b"secret";
        let user_id = Uuid::new_v4();
        let credential_id = Uuid::new_v4();

        let encrypted = encrypt_seed(&dek, seed, None, user_id, credential_id).unwrap();

        // Try decrypt with wrong credential_id
        let result = decrypt_seed(&dek, &encrypted, None, user_id, Uuid::new_v4());
        assert!(result.is_err());
    }

    #[test]
    #[allow(clippy::unwrap_used, clippy::indexing_slicing)]
    fn test_decrypt_fails_tampered_ciphertext() {
        let dek = [42u8; 32];
        let seed = b"secret";
        let user_id = Uuid::new_v4();
        let credential_id = Uuid::new_v4();

        let mut encrypted = encrypt_seed(&dek, seed, None, user_id, credential_id).unwrap();

        // Tamper with last byte
        let len = encrypted.len();
        if let Some(byte) = encrypted.get_mut(len - 1) {
            *byte ^= 0xFF;
        }

        let result = decrypt_seed(&dek, &encrypted, None, user_id, credential_id);
        assert!(result.is_err());
    }
}
