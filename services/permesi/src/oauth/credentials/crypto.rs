//! Canonical secret encoding and bounded PHC verification. Secret types never implement Debug.

use argon2::{Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use secrecy::{ExposeSecret, SecretString};
use uuid::Uuid;

use super::{CredentialConfig, CredentialError};

/// Credential locator plus 256 random bits, authenticated as one canonical string.
pub(super) struct ClientSecret {
    pub id: Uuid,
    value: SecretString,
}

impl ClientSecret {
    /// Bounds input before decoding and rejects padding, aliases, trailing fields and whitespace.
    pub(super) fn parse(value: &str) -> Result<Self, CredentialError> {
        if value.len() != 84 {
            return Err(CredentialError::InvalidCredentials);
        }
        let parts: Vec<_> = value.split('.').collect();
        let ["pcs", id, material] = parts.as_slice() else {
            return Err(CredentialError::InvalidCredentials);
        };
        let id = Uuid::parse_str(id).map_err(|_| CredentialError::InvalidCredentials)?;
        let decoded = URL_SAFE_NO_PAD
            .decode(material)
            .map_err(|_| CredentialError::InvalidCredentials)?;
        if decoded.len() != 32
            || URL_SAFE_NO_PAD.encode(decoded) != *material
            || format!("pcs.{id}.{material}") != value
        {
            return Err(CredentialError::InvalidCredentials);
        }
        Ok(Self {
            id,
            value: value.to_owned().into(),
        })
    }
}

/// Generates random material and a fresh salt; only the PHC string crosses into persistence.
pub(super) fn hash_secret(
    policy: &CredentialConfig,
) -> Result<(Uuid, SecretString, String), CredentialError> {
    let id = Uuid::new_v4();
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| CredentialError::Unavailable)?;
    let raw: SecretString = format!("pcs.{id}.{}", URL_SAFE_NO_PAD.encode(bytes)).into();
    let params = Params::new(
        policy.memory_kib,
        policy.iterations,
        policy.parallelism,
        Some(32),
    )
    .map_err(|_| CredentialError::Unavailable)?;
    let hash = Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password(raw.expose_secret().as_bytes())
        .map_err(|_| CredentialError::Unavailable)?
        .to_string();
    Ok((id, raw, hash))
}

/// Checks algorithm/version/cost and output/salt before allocation; Argon2's verifier uses
/// constant-time digest equality. Accepts supported historical costs across config changes.
pub(super) fn verify_secret(secret: &ClientSecret, hash: &str) -> Result<(), CredentialError> {
    if hash.len() > 256 {
        return Err(CredentialError::InvalidCredentials);
    }
    let parsed = PasswordHash::new(hash).map_err(|_| CredentialError::InvalidCredentials)?;
    let params = Params::try_from(&parsed).map_err(|_| CredentialError::InvalidCredentials)?;
    if parsed.algorithm.as_str() != "argon2id"
        || parsed.version != Some(19)
        || !(19456..=65536).contains(&params.m_cost())
        || !(2..=6).contains(&params.t_cost())
        || !(1..=4).contains(&params.p_cost())
        || parsed.hash.as_ref().is_none_or(|hash| hash.len() != 32)
        || parsed.salt.is_none_or(|salt| salt.len() < 16)
        || parsed.params.iter().count() != 3
        || parsed
            .params
            .iter()
            .any(|(name, _)| !["m", "t", "p"].contains(&name.as_str()))
    {
        return Err(CredentialError::InvalidCredentials);
    }
    Argon2::default()
        .verify_password(secret.value.expose_secret().as_bytes(), &parsed)
        .map_err(|_| CredentialError::InvalidCredentials)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_secret_rejects_aliases_padding_and_malformed_input() -> Result<(), CredentialError> {
        let (_, raw, _) = hash_secret(&CredentialConfig::for_tests())?;
        assert!(ClientSecret::parse(raw.expose_secret()).is_ok());
        for value in [
            String::new(),
            raw.expose_secret().to_uppercase(),
            format!("{}=", raw.expose_secret()),
            format!(" {}", raw.expose_secret()),
            "pcs.bad.bad".into(),
        ] {
            assert!(ClientSecret::parse(&value).is_err());
        }
        Ok(())
    }

    #[test]
    fn client_secret_verifies_supported_historical_costs() -> Result<(), CredentialError> {
        let mut policy = CredentialConfig::for_tests();
        policy.memory_kib = 65536;
        policy.iterations = 3;
        policy.parallelism = 2;
        let (_, raw, hash) = hash_secret(&policy)?;
        let secret = ClientSecret::parse(raw.expose_secret())?;
        assert!(verify_secret(&secret, &hash).is_ok());
        Ok(())
    }

    #[test]
    fn client_secret_verification_rejects_weak_or_excessive_phc_parameters()
    -> Result<(), CredentialError> {
        let (_, raw, hash) = hash_secret(&CredentialConfig::for_tests())?;
        let secret = ClientSecret::parse(raw.expose_secret())?;
        assert!(verify_secret(&secret, &hash).is_ok());
        for changed in [
            hash.replace("argon2id", "argon2i"),
            hash.replace("v=19", "v=16"),
            hash.replace("m=19456", "m=65537"),
            hash.replace("m=19456", "m=1024"),
            hash.replace("t=2", "t=1"),
            hash.replace("t=2", "t=7"),
            hash.replace("p=1", "p=5"),
            "$argon2id$invalid".into(),
        ] {
            assert!(verify_secret(&secret, &changed).is_err());
        }
        let (_, other, other_hash) = hash_secret(&CredentialConfig::for_tests())?;
        assert!(!raw.expose_secret().eq(other.expose_secret()));
        assert!(verify_secret(&secret, &other_hash).is_err());
        Ok(())
    }
}
