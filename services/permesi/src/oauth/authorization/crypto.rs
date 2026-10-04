//! Typed PKCE and opaque code material; secrets have no Debug or Serialize implementation.
//!
//! S256 is mandatory for every interactive client. Challenges are canonical unpadded
//! base64url SHA-256 digests, and comparisons use constant time. Codes use 256 random
//! bits; only their digest may cross the persistence boundary.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::oauth::ValidationError;

/// A canonical S256 digest; never accepts plain or an omitted challenge method.
#[derive(Clone)]
pub(crate) struct PkceChallenge(String);

impl PkceChallenge {
    /// Validates method and digest encoding, rejecting padding and noncanonical trailing bits.
    pub(crate) fn parse(value: &str, method: &str) -> Result<Self, ValidationError> {
        let decoded = URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| ValidationError("Invalid PKCE challenge."))?;
        if method != "S256"
            || value.len() != 43
            || decoded.len() != 32
            || URL_SAFE_NO_PAD.encode(&decoded) != value
        {
            return Err(ValidationError("S256 PKCE is required."));
        }
        Ok(Self(value.to_owned()))
    }

    /// Returns validated public challenge bytes for PostgreSQL storage.
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    /// Verifies RFC 7636 S256 in constant time after verifier syntax validation.
    pub(crate) fn matches(&self, verifier: &CodeVerifier) -> bool {
        let computed = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.0.as_bytes()));
        bool::from(self.0.as_bytes().ct_eq(computed.as_bytes()))
    }
}

/// A 43–128 byte RFC 7636 verifier. It is never logged, serialized, or persisted.
pub(crate) struct CodeVerifier(String);

impl CodeVerifier {
    /// Accepts only ASCII unreserved characters and the mandatory verifier length bounds.
    pub(crate) fn parse(value: &str) -> Result<Self, ValidationError> {
        if !(43..=128).contains(&value.len())
            || !value
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-._~".contains(&c))
        {
            return Err(ValidationError("Invalid PKCE verifier."));
        }
        Ok(Self(value.to_owned()))
    }
}

/// Opaque 256-bit code, browser binding, or CSRF token. Only hashes belong in storage.
pub(crate) struct SecretValue(String);

impl SecretValue {
    /// Generates independent OS-random material without a process-local challenge registry.
    pub(crate) fn generate() -> Result<Self, getrandom::Error> {
        let mut bytes = [0; 32];
        getrandom::fill(&mut bytes)?;
        Ok(Self(URL_SAFE_NO_PAD.encode(bytes)))
    }

    /// Validates an externally returned code/token without exposing it in an error.
    pub(crate) fn parse(value: &str) -> Result<Self, ValidationError> {
        if value.len() != 43 {
            return Err(ValidationError("Invalid opaque value."));
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| ValidationError("Invalid opaque value."))?;
        if bytes.len() != 32 || URL_SAFE_NO_PAD.encode(&bytes) != value {
            return Err(ValidationError("Invalid opaque value."));
        }
        Ok(Self(value.to_owned()))
    }

    /// Exposes plaintext only to the protocol redirect or browser-binding response.
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }

    /// Produces the sole representation permitted in PostgreSQL and never logs plaintext.
    pub(crate) fn hash(&self) -> Vec<u8> {
        Sha256::digest(self.0.as_bytes()).to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_s256_matches_rfc7636_and_rejects_downgrades() -> Result<(), ValidationError> {
        let verifier = CodeVerifier::parse("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")?;
        let digest = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert!(PkceChallenge::parse(digest, "S256")?.matches(&verifier));
        assert!(
            !PkceChallenge::parse(digest, "S256")?.matches(&CodeVerifier::parse(&"a".repeat(43))?)
        );
        for method in ["plain", "", "s256"] {
            assert!(PkceChallenge::parse(digest, method).is_err());
        }
        for challenge in [
            "x",
            "*",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB",
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM=",
        ] {
            assert!(PkceChallenge::parse(challenge, "S256").is_err());
        }
        for verifier in [
            "a".repeat(42),
            "a".repeat(129),
            "!".repeat(43),
            "é".repeat(43),
        ] {
            assert!(CodeVerifier::parse(&verifier).is_err());
        }
        assert!(CodeVerifier::parse(&"a".repeat(128)).is_ok());
        Ok(())
    }

    #[test]
    fn authorization_code_is_random_and_only_digest_is_storable() -> anyhow::Result<()> {
        let first = SecretValue::generate()?;
        let second = SecretValue::generate()?;
        assert_eq!(first.expose().len(), 43);
        assert_ne!(first.expose(), second.expose());
        assert_eq!(first.hash().len(), 32);
        assert_eq!(SecretValue::parse(first.expose())?.hash(), first.hash());
        Ok(())
    }
}
