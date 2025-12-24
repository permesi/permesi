use crate::Error;
use base64ct::{Base64, Encoding};
use pasetors::errors::Error as PasetorsError;
use pasetors::keys::AsymmetricPublicKey;
use pasetors::paserk::{FormatAsPaserk, Id};
use pasetors::version4::V4;
use serde::{Deserialize, Serialize};
const KEYSET_VERSION: &str = "v4";
const KEYSET_PURPOSE: &str = "public";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PaserkKeySet {
    pub version: String,
    pub purpose: String,
    pub active_kid: String,
    pub keys: Vec<PaserkKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PaserkKey {
    pub kid: String,
    pub paserk: String,
}

impl PaserkKeySet {
    /// Parse a PASERK keyset from JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if `s` is not valid JSON or doesn't match the expected shape.
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }

    /// Serialize this PASERK keyset to pretty-printed JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Find a key by `kid` (PASERK ID).
    #[must_use]
    pub fn find_by_kid(&self, kid: &str) -> Option<&PaserkKey> {
        self.keys.iter().find(|k| k.kid == kid)
    }

    /// Validate keyset metadata and ensure every `kid` matches its PASERK ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the version/purpose are invalid or any key is malformed.
    pub fn validate(&self) -> Result<(), Error> {
        if self.version != KEYSET_VERSION {
            return Err(Error::InvalidPaserkVersion);
        }
        if self.purpose != KEYSET_PURPOSE {
            return Err(Error::InvalidPaserkPurpose);
        }
        if self.keys.iter().all(|key| key.kid != self.active_kid) {
            return Err(Error::UnknownKid(self.active_kid.clone()));
        }
        for key in &self.keys {
            key.validate()?;
        }
        Ok(())
    }
}

impl PaserkKey {
    /// Build a PASERK key entry from an Ed25519 public key (raw bytes).
    ///
    /// # Errors
    ///
    /// Returns an error if PASERK ID computation fails.
    pub fn from_ed25519_public_key_bytes(public_key: &[u8; 32]) -> Result<Self, Error> {
        let key = AsymmetricPublicKey::<V4>::from(public_key.as_slice())
            .map_err(|_| Error::InvalidKeyType)?;
        let paserk = format_paserk(&key)?;
        let kid = format_kid(&key)?;
        Ok(Self { kid, paserk })
    }

    /// Parse a standard base64 Ed25519 public key and convert it into a PASERK entry.
    ///
    /// # Errors
    ///
    /// Returns an error if the base64 content is invalid or not 32 bytes.
    pub fn from_ed25519_public_key_base64(public_key_b64: &str) -> Result<Self, Error> {
        let raw = Base64::decode_vec(public_key_b64).map_err(|_| Error::Base64)?;
        let bytes: [u8; 32] = raw
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidKeyLength)?;
        Self::from_ed25519_public_key_bytes(&bytes)
    }

    /// Convert this PASERK entry to a PASETO public key.
    ///
    /// # Errors
    ///
    /// Returns an error if the PASERK is invalid or the key bytes are malformed.
    pub fn to_public_key(&self) -> Result<AsymmetricPublicKey<V4>, Error> {
        public_key_from_paserk(&self.paserk)
    }

    /// Validate the PASERK entry and ensure the kid matches the PASERK ID.
    ///
    /// # Errors
    ///
    /// Returns an error if parsing fails or `kid` does not match the derived ID.
    pub fn validate(&self) -> Result<(), Error> {
        let key = public_key_from_paserk(&self.paserk)?;
        let expected = format_kid(&key)?;
        if self.kid != expected {
            return Err(Error::InvalidPaserkId);
        }
        Ok(())
    }
}

fn public_key_from_paserk(paserk: &str) -> Result<AsymmetricPublicKey<V4>, Error> {
    AsymmetricPublicKey::<V4>::try_from(paserk).map_err(|err| map_paserk_error(&err))
}

fn format_paserk(key: &AsymmetricPublicKey<V4>) -> Result<String, Error> {
    let mut paserk = String::new();
    key.fmt(&mut paserk).map_err(|_| Error::InvalidKeyType)?;
    Ok(paserk)
}

fn format_kid(key: &AsymmetricPublicKey<V4>) -> Result<String, Error> {
    let id = Id::from(key);
    let mut kid = String::new();
    id.fmt(&mut kid).map_err(|_| Error::InvalidPaserkId)?;
    Ok(kid)
}

fn map_paserk_error(err: &PasetorsError) -> Error {
    match err {
        PasetorsError::Base64 => Error::Base64,
        PasetorsError::Key => Error::InvalidKeyType,
        PasetorsError::LossyConversion => Error::InvalidLength,
        _ => Error::UnsupportedPaserk,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paserk_pid_matches_spec_vector() -> Result<(), Error> {
        let paserk = "k4.public.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8";
        let expected = "k4.pid.9ShR3xc8-qVJ_di0tc9nx0IDIqbatdeM2mqLFBJsKRHs";
        let key = public_key_from_paserk(paserk)?;
        let actual = format_kid(&key)?;
        assert_eq!(actual, expected);
        Ok(())
    }

    #[test]
    fn paserk_validate_rejects_mismatched_kid() -> Result<(), Error> {
        let key = PaserkKey::from_ed25519_public_key_bytes(&[7u8; 32])?;
        let mut invalid = key.clone();
        invalid.kid = "k4.pid.invalid".to_string();
        let result = invalid.validate();
        assert!(matches!(result, Err(Error::InvalidPaserkId)));
        Ok(())
    }
}
