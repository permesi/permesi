use crate::jwks::Jwks;
use base64ct::{Base64UrlUnpadded, Encoding};
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs1v15::{Signature, SigningKey, VerifyingKey};
use rsa::pkcs8::DecodePrivateKey;
use rsa::signature::{SignatureEncoding, Signer, Verifier};
use rsa::{RsaPrivateKey, errors::Error as RsaError};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;

pub const TOKEN_VERSION: u8 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdmissionTokenHeader {
    pub alg: String,
    pub typ: String,
    pub kid: String,
}

impl AdmissionTokenHeader {
    fn rs256(kid: impl Into<String>) -> Self {
        Self {
            alg: "RS256".to_string(),
            typ: "JWT".to_string(),
            kid: kid.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdmissionTokenClaims {
    pub v: u8,
    pub iss: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub jti: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid token format")]
    TokenFormat,
    #[error("invalid base64url encoding")]
    Base64,
    #[error("invalid json")]
    Json(#[from] serde_json::Error),
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlg(String),
    #[error("unknown key id: {0}")]
    UnknownKid(String),
    #[error("failed to parse RSA key")]
    KeyParse,
    #[error("rsa error")]
    Rsa(#[from] RsaError),
    #[error("invalid signature")]
    InvalidSignature,
    #[error("token expired")]
    Expired,
    #[error("invalid issuer")]
    InvalidIssuer,
    #[error("invalid audience")]
    InvalidAudience,
    #[error("invalid token version")]
    InvalidVersion,
}

fn b64e_json<T: Serialize>(value: &T) -> Result<String, Error> {
    let json = serde_json::to_vec(value)?;
    Ok(Base64UrlUnpadded::encode_string(&json))
}

fn b64d_json<T: for<'de> Deserialize<'de>>(s: &str) -> Result<T, Error> {
    let bytes = Base64UrlUnpadded::decode_vec(s).map_err(|_| Error::Base64)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn decode_private_key(pem_or_der: &[u8]) -> Result<RsaPrivateKey, Error> {
    if pem_or_der.starts_with(b"-----BEGIN") {
        let s = std::str::from_utf8(pem_or_der).map_err(|_| Error::KeyParse)?;
        if let Ok(k) = RsaPrivateKey::from_pkcs8_pem(s) {
            return Ok(k);
        }
        if let Ok(k) = RsaPrivateKey::from_pkcs1_pem(s) {
            return Ok(k);
        }
        return Err(Error::KeyParse);
    }

    if let Ok(k) = RsaPrivateKey::from_pkcs8_der(pem_or_der) {
        return Ok(k);
    }
    if let Ok(k) = RsaPrivateKey::from_pkcs1_der(pem_or_der) {
        return Ok(k);
    }
    Err(Error::KeyParse)
}

/// Create an RS256 signed Admission Token (JWT).
///
/// # Errors
///
/// Returns an error if the private key cannot be parsed, claims/header JSON cannot be encoded,
/// or signing fails.
pub fn sign_rs256(
    private_key_pem_or_der: &[u8],
    kid: impl Into<String>,
    claims: &AdmissionTokenClaims,
) -> Result<String, Error> {
    let header = AdmissionTokenHeader::rs256(kid);
    let header_b64 = b64e_json(&header)?;
    let claims_b64 = b64e_json(claims)?;
    let signing_input = format!("{header_b64}.{claims_b64}");

    let private_key = decode_private_key(private_key_pem_or_der)?;
    let signing_key = SigningKey::<Sha256>::new(private_key);
    let signature: Signature = signing_key.sign(signing_input.as_bytes());
    let signature_b64 = Base64UrlUnpadded::encode_string(&signature.to_vec());

    Ok(format!("{signing_input}.{signature_b64}"))
}

/// Verify an RS256 Admission Token (JWT) and return its decoded claims.
///
/// # Errors
///
/// Returns an error if:
/// - the token is malformed or contains invalid base64/json,
/// - the `kid` is unknown for the provided JWKS,
/// - the signature is invalid,
/// - the claims fail validation (`v`, `iss`, `aud`, `exp`).
pub fn verify_rs256(
    token: &str,
    jwks: &Jwks,
    expected_issuer: &str,
    expected_audience: &str,
    now_unix_seconds: i64,
) -> Result<AdmissionTokenClaims, Error> {
    let mut parts = token.split('.');
    let header_b64 = parts.next().ok_or(Error::TokenFormat)?;
    let claims_b64 = parts.next().ok_or(Error::TokenFormat)?;
    let sig_b64 = parts.next().ok_or(Error::TokenFormat)?;
    if parts.next().is_some() {
        return Err(Error::TokenFormat);
    }

    let header: AdmissionTokenHeader = b64d_json(header_b64)?;
    if header.alg != "RS256" {
        return Err(Error::UnsupportedAlg(header.alg));
    }

    let jwk = jwks
        .find_by_kid(&header.kid)
        .ok_or_else(|| Error::UnknownKid(header.kid.clone()))?;

    let public_key = jwk.to_rsa_public_key()?;
    let verifying_key = VerifyingKey::<Sha256>::new(public_key);
    let signing_input = format!("{header_b64}.{claims_b64}");
    let signature_bytes = Base64UrlUnpadded::decode_vec(sig_b64).map_err(|_| Error::Base64)?;
    let signature =
        Signature::try_from(signature_bytes.as_slice()).map_err(|_| Error::InvalidSignature)?;
    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| Error::InvalidSignature)?;

    let claims: AdmissionTokenClaims = b64d_json(claims_b64)?;
    if claims.v != TOKEN_VERSION {
        return Err(Error::InvalidVersion);
    }
    if claims.iss != expected_issuer {
        return Err(Error::InvalidIssuer);
    }
    if claims.aud != expected_audience {
        return Err(Error::InvalidAudience);
    }
    if claims.exp <= now_unix_seconds {
        return Err(Error::Expired);
    }

    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwks::Jwks;

    const TEST_PRIVATE_KEY_PEM: &str = r"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCunW7btqwtqcJ7
H6yViX8LE6kwPQvO62skFfGQzJOgUQKKUVVznimMMxoDvaja6DWqFKvTDSBoblnF
jW0c2CUTb6cbVRbyAulTcJLwt1nPcw+IbK5LTWYy8GeiWuXT508TPOGOBYXCispE
QsC8KOzfpbqRbLb3t9cyU68NGt3xlTg3xTk7UYA2xoR8XRUsHu2XpZqeA6icxBi9
ltd/uCLAx8fWY78z43tZhVbdIVSnXq/+ZjDQ8riQ2DQSrYqhI5Nbf7RUVFmX4Crw
kHoQV+jBQSUo8IuW2NCvq8TfNp8HCpIwCCcSBucCNsu1gSF69l7W1Bwtu4AyBW+j
lm14Ni9tAgMBAAECggEAVM3nKlREuQSqjIuskQ+vIN0SnXf4hS024ta5dJ62z/So
LC8mNjnJaerjpo91M6P1dD4H2T+VzsJRXS27oXekQhVG7nJb63vYgAq7gqc5uhPi
plpKKA5WJUU2v9YvqsO7VteJoCU0enBXneFho8CoklH2E2zeS98AZ9PWv6Gdyxbl
S6roYnLFpZCNPTVzR654v2u7N1+ZBuAFVP888UGIF7NN+5TcIHgiJOVGFs+42AOk
tBjwm5Gki2gtAr6frjzR2JvelmXM4tOcwOQA1g+t4Ng9ADlvEy3RqEuoK+eKWJ7j
mKGtbsTOkZ1/k07Di3MSqxANRDYl1pAZlaNjJkaETQKBgQDWll0zA+1kW0sNfQVF
6pGQLQE4b2iHmu+oLJCcpSvyZbFa45ffh8SQNk3nYt/XN4br0darGRnaujOukm/8
mP2MJGe9SaMRZr+QYRdqtMM30gYRhLxt34R5FHfSQ4wB3Ai3W4v/4S+nn4T59Eyf
4u3zDUvhLd7jpq13T3IERf7HbwKBgQDQUD41WnkoEmoLmfjHIbAbbL7bG39SNdXa
hkpYrFAQl5uakbHbZhzSiKrWFMdwx4Pz4xlTOGFGSs9GTMKhaqF8vFwq+y6539dL
nVMp5ig/hjZv6jCpyakHLv+JLykzTAWTs6a9enK/c1Oy6VQsMRoXLIshnyptS0xC
HfkVyP4o4wKBgB+Esme92e51ok524IFmdL7yfU1mv7m7Phw7f3oioJPX7/bjmvkQ
HgT4lPS5hxs7YqvchGVZKH0CAHlRtPUrG4KsDji1SihSKSzxtdjMeCgIxy9nia2x
uOl34imWFkhnozgbUDLjRnaebY+xHFgXos+iUlTewfA6GRx/JMYP6d4tAoGAFhWr
wrRIy/rHy1sTiOkFZqLsyQXtRaX3eidqkmQSSPAJyyVPGdeFjrx2gCPL0SUV1DFr
aes8RNuBhg51Q++uFy9RBi2DEqmshZO0UWjZM4LjGpJVfmqmxOAyrzSUxZ91p+cP
8l6c87ciVIFwLw81mOdcCMB7GwM0nn3W/nxElckCgYEApg6MxHhAdPIjHPhWDwke
R9ntZlZN9BZneUqGXEQM6IkRXhYH4cTqhDzFKOpfx3eDP/vQ/ntM1R5SqP9ddcdg
laq3PWndNFHaEkY9ifgYADCC/I6jhxGtaeCJtTOOuM2bLUJXUClNBaKoWNmYG3O7
vsfQ/voIp/Vp1JqaeJtEfhg=
-----END PRIVATE KEY-----";

    // Fixed claims for stable golden vectors.
    const NOW: i64 = 1_700_000_000;
    const GOLDEN_VECTOR_1: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImsxIn0.eyJ2IjoxLCJpc3MiOiJodHRwczovL2dlbmVzaXMuZXhhbXBsZS50ZXN0IiwiYXVkIjoicGVybWVzaSIsImV4cCI6MTcwMDAwMDEyMCwiaWF0IjoxNzAwMDAwMDAwLCJqdGkiOiJqdGktMSIsInN1YiI6ImNsaWVudC0xMjMifQ.ZuSntt7xVlQx8Yj-dgEH5gxAmcX7err0u_t5iFaUuuJSgqsXMCLHFpc9rCwJaHtKcXrB2yw76oKCqciwRRnq8xZW49XRIs2hm6xhC1La0BXwIajbH0aKiTkRVYvxuaRZWVc2bVFju9PFj4MYxZshsDKRJq-z9qelz6fbjRD152YkwPZi7qpyky5_oUOEpaoezQqNHEeTaw8sltt-s8siVIphvXMkNPzrXOA7R46g5RCoJpYR7y7jO8mcSaipqBkPm98loTLI504jjWzKnzJqfWWlRcT7csMfhn8GGxxu4eFdm1q5YVk0-tvvcGd-2U73WkoW2BPcIxrZqTy1tY_syQ";
    const GOLDEN_VECTOR_2: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImsyIn0.eyJ2IjoxLCJpc3MiOiJodHRwczovL2dlbmVzaXMuZXhhbXBsZS50ZXN0IiwiYXVkIjoicGVybWVzaSIsImV4cCI6MTcwMDAwMDEyMCwiaWF0IjoxNzAwMDAwMDAwLCJqdGkiOiJqdGktMiIsInN1YiI6ImNsaWVudC0xMjMifQ.bmuYeBAxmpNtwfAcKkPGxl4BD37_-ysyb9c6B-3sl0yMpHjBIZt87GGFP-WW4iMWIZobQHS-f52gWE6xgP2hwF6HupLyF9-qEoSbA9vm6b_iIqcSRQWSaV2eODNWb8ltzStjjQhLDYQTR23biLayVHc-iGafibrR4d179WgyKQ0iFhWV-x67s2fnIe3LxHpoigFlTC7qF0-j5JXccz9R3yPVXjvbdnBXWkx72ChgR9-iYr2QqqHNtuB_QeZTu8TBjCIjIwUxEy40-EbkJeyXT4hdDhJcRhttnwuk-8GzqGSzJxaHBqsgAAMkCShZikQhwBRkotZW7Pj2deHO_SIYmw";

    fn test_claims(jti: &str) -> AdmissionTokenClaims {
        AdmissionTokenClaims {
            v: TOKEN_VERSION,
            iss: "https://genesis.example.test".to_string(),
            aud: "permesi".to_string(),
            iat: NOW,
            exp: NOW + 120,
            jti: jti.to_string(),
            sub: Some("client-123".to_string()),
        }
    }

    #[test]
    fn golden_vector_1_sign_and_verify() -> Result<(), Error> {
        let jwks = Jwks::from_rsa_private_key_pem_or_der(TEST_PRIVATE_KEY_PEM.as_bytes(), "k1")?;
        let token = sign_rs256(TEST_PRIVATE_KEY_PEM.as_bytes(), "k1", &test_claims("jti-1"))?;

        // Golden token string (stable because RS256 is deterministic and claims are fixed).
        assert_eq!(token, GOLDEN_VECTOR_1);

        let verified = verify_rs256(
            &token,
            &jwks,
            "https://genesis.example.test",
            "permesi",
            NOW,
        )?;
        assert_eq!(verified.jti, "jti-1");
        Ok(())
    }

    #[test]
    fn golden_vector_2_sign_and_verify() -> Result<(), Error> {
        let jwks = Jwks::from_rsa_private_key_pem_or_der(TEST_PRIVATE_KEY_PEM.as_bytes(), "k2")?;
        let token = sign_rs256(TEST_PRIVATE_KEY_PEM.as_bytes(), "k2", &test_claims("jti-2"))?;

        assert_eq!(token, GOLDEN_VECTOR_2);

        let verified = verify_rs256(
            &token,
            &jwks,
            "https://genesis.example.test",
            "permesi",
            NOW,
        )?;
        assert_eq!(verified.jti, "jti-2");
        Ok(())
    }

    #[test]
    fn rejects_expired_or_wrong_aud() -> Result<(), Error> {
        let jwks = Jwks::from_rsa_private_key_pem_or_der(TEST_PRIVATE_KEY_PEM.as_bytes(), "k")?;
        let token = sign_rs256(TEST_PRIVATE_KEY_PEM.as_bytes(), "k", &test_claims("jti-x"))?;

        let result = verify_rs256(
            &token,
            &jwks,
            "https://genesis.example.test",
            "wrong-aud",
            NOW,
        );
        assert!(matches!(result, Err(Error::InvalidAudience)));

        let result = verify_rs256(
            &token,
            &jwks,
            "https://genesis.example.test",
            "permesi",
            NOW + 9999,
        );
        assert!(matches!(result, Err(Error::Expired)));

        Ok(())
    }
}
