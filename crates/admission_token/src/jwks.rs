use base64ct::{Base64UrlUnpadded, Encoding};
use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey};
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
use rsa::traits::PublicKeyParts;
use rsa::{BigUint, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

impl Jwks {
    /// Parse a JWKS from JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if `s` is not valid JSON or doesn't match the expected JWKS shape.
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }

    /// Serialize this JWKS to pretty-printed JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Find a key by `kid` (Key ID).
    #[must_use]
    pub fn find_by_kid(&self, kid: &str) -> Option<&Jwk> {
        self.keys.iter().find(|k| k.kid == kid)
    }

    /// Build a JWKS from an RSA public key (PEM or DER).
    ///
    /// # Errors
    ///
    /// Returns an error if the key cannot be parsed or the JWK cannot be created.
    pub fn from_rsa_public_key_pem_or_der(
        pem_or_der: &[u8],
        kid: impl Into<String>,
    ) -> Result<Self, super::jwt::Error> {
        let jwk = Jwk::from_rsa_public_key_pem_or_der(pem_or_der, kid)?;
        Ok(Self { keys: vec![jwk] })
    }

    /// Build a JWKS from an RSA private key (PEM or DER).
    ///
    /// The public key is derived from the private key.
    ///
    /// # Errors
    ///
    /// Returns an error if the key cannot be parsed or the JWK cannot be created.
    pub fn from_rsa_private_key_pem_or_der(
        private_key_pem_or_der: &[u8],
        kid: impl Into<String>,
    ) -> Result<Self, super::jwt::Error> {
        let private_key = decode_private_key(private_key_pem_or_der)?;
        let public_key = RsaPublicKey::from(&private_key);
        let jwk = Jwk::from_rsa_public_key(&public_key, kid)?;
        Ok(Self { keys: vec![jwk] })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Jwk {
    pub kty: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
    pub key_use: Option<String>,
    pub kid: String,
    pub n: String,
    pub e: String,
}

impl Jwk {
    /// Build a JWK from an RSA public key (PEM or DER).
    ///
    /// # Errors
    ///
    /// Returns an error if the key cannot be parsed or the JWK cannot be created.
    pub fn from_rsa_public_key_pem_or_der(
        pem_or_der: &[u8],
        kid: impl Into<String>,
    ) -> Result<Self, super::jwt::Error> {
        let public_key = decode_public_key(pem_or_der)?;
        Self::from_rsa_public_key(&public_key, kid)
    }

    /// Build a JWK from an `RsaPublicKey`.
    ///
    /// # Errors
    ///
    /// Returns an error if the key cannot be converted to a JWK.
    pub fn from_rsa_public_key(
        public_key: &RsaPublicKey,
        kid: impl Into<String>,
    ) -> Result<Self, super::jwt::Error> {
        let n = Base64UrlUnpadded::encode_string(&public_key.n().to_bytes_be());
        let e = Base64UrlUnpadded::encode_string(&public_key.e().to_bytes_be());
        Ok(Self {
            kty: "RSA".to_string(),
            alg: Some("RS256".to_string()),
            key_use: Some("sig".to_string()),
            kid: kid.into(),
            n,
            e,
        })
    }

    /// Convert this JWK to an `RsaPublicKey`.
    ///
    /// # Errors
    ///
    /// Returns an error if the base64url values cannot be decoded or the RSA key is invalid.
    pub fn to_rsa_public_key(&self) -> Result<RsaPublicKey, super::jwt::Error> {
        let n_bytes =
            Base64UrlUnpadded::decode_vec(&self.n).map_err(|_| super::jwt::Error::Base64)?;
        let e_bytes =
            Base64UrlUnpadded::decode_vec(&self.e).map_err(|_| super::jwt::Error::Base64)?;
        let n = BigUint::from_bytes_be(&n_bytes);
        let e = BigUint::from_bytes_be(&e_bytes);
        RsaPublicKey::new(n, e).map_err(super::jwt::Error::Rsa)
    }
}

fn decode_private_key(pem_or_der: &[u8]) -> Result<RsaPrivateKey, super::jwt::Error> {
    if pem_or_der.starts_with(b"-----BEGIN") {
        let s = std::str::from_utf8(pem_or_der).map_err(|_| super::jwt::Error::KeyParse)?;
        if let Ok(k) = RsaPrivateKey::from_pkcs8_pem(s) {
            return Ok(k);
        }
        if let Ok(k) = RsaPrivateKey::from_pkcs1_pem(s) {
            return Ok(k);
        }
        return Err(super::jwt::Error::KeyParse);
    }

    if let Ok(k) = RsaPrivateKey::from_pkcs8_der(pem_or_der) {
        return Ok(k);
    }
    if let Ok(k) = RsaPrivateKey::from_pkcs1_der(pem_or_der) {
        return Ok(k);
    }
    Err(super::jwt::Error::KeyParse)
}

fn decode_public_key(pem_or_der: &[u8]) -> Result<RsaPublicKey, super::jwt::Error> {
    if pem_or_der.starts_with(b"-----BEGIN") {
        let s = std::str::from_utf8(pem_or_der).map_err(|_| super::jwt::Error::KeyParse)?;
        if let Ok(k) = RsaPublicKey::from_public_key_pem(s) {
            return Ok(k);
        }
        if let Ok(k) = RsaPublicKey::from_pkcs1_pem(s) {
            return Ok(k);
        }
        return Err(super::jwt::Error::KeyParse);
    }

    if let Ok(k) = RsaPublicKey::from_public_key_der(pem_or_der) {
        return Ok(k);
    }
    if let Ok(k) = RsaPublicKey::from_pkcs1_der(pem_or_der) {
        return Ok(k);
    }
    Err(super::jwt::Error::KeyParse)
}
