use crate::{Error, PaserkKeySet};
use base64ct::{Base64UrlUnpadded, Encoding};
use pasetors::Public;
use pasetors::errors::Error as PasetorsError;
use pasetors::footer::Footer;
use pasetors::token::UntrustedToken;
use pasetors::version4::{PublicToken, V4};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

const HEADER: &str = "v4.public.";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdmissionTokenClaims {
    pub iss: String,
    pub aud: String,
    pub exp: String,
    pub iat: String,
    pub jti: String,
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdmissionTokenFooter {
    pub kid: String,
}

/// Options for verifying v4.public Admission Tokens.
pub struct VerificationOptions<'a> {
    pub expected_issuer: &'a str,
    pub expected_audience: &'a str,
    pub expected_action: &'a str,
    pub now_unix_seconds: i64,
    pub min_ttl_seconds: i64,
    pub max_ttl_seconds: i64,
}

pub struct SigningInput {
    pub pre_auth: Vec<u8>,
    pub payload: Vec<u8>,
    pub footer: Vec<u8>,
}

/// Encode the payload/footer and return the PASETO v4.public signing input.
///
/// # Errors
///
/// Returns an error if JSON encoding or PAE fails.
pub fn encode_signing_input(
    claims: &AdmissionTokenClaims,
    footer: &AdmissionTokenFooter,
) -> Result<SigningInput, Error> {
    let payload = serde_json::to_vec(claims)?;
    let footer_bytes = serde_json::to_vec(footer)?;
    let pre_auth = pae(&[
        HEADER.as_bytes(),
        payload.as_slice(),
        footer_bytes.as_slice(),
        b"",
    ])?;
    Ok(SigningInput {
        pre_auth,
        payload,
        footer: footer_bytes,
    })
}

/// Build a v4.public token from payload, footer, and Ed25519 signature.
#[must_use]
pub fn build_token(payload: &[u8], footer: &[u8], signature: &[u8; 64]) -> String {
    let mut message = Vec::with_capacity(payload.len() + signature.len());
    message.extend_from_slice(payload);
    message.extend_from_slice(signature);
    let body_b64 = Base64UrlUnpadded::encode_string(&message);
    if footer.is_empty() {
        format!("{HEADER}{body_b64}")
    } else {
        let footer_b64 = Base64UrlUnpadded::encode_string(footer);
        format!("{HEADER}{body_b64}.{footer_b64}")
    }
}

/// Verify a v4.public Admission Token and return its decoded claims.
///
/// # Errors
///
/// Returns an error if:
/// - the token is malformed or contains invalid base64/json,
/// - the `kid` is unknown for the provided PASERK keyset,
/// - the signature is invalid,
/// - the claims fail validation (`iss`, `aud`, `exp`, `iat`, `action`, ttl).
pub fn verify_v4_public(
    token: &str,
    keyset: &PaserkKeySet,
    options: &VerificationOptions<'_>,
) -> Result<AdmissionTokenClaims, Error> {
    let untrusted =
        UntrustedToken::<Public, V4>::try_from(token).map_err(|err| map_paseto_error(&err))?;
    let footer_bytes = untrusted.untrusted_footer();
    if footer_bytes.is_empty() {
        return Err(Error::MissingFooter);
    }

    let kid = footer_kid(footer_bytes)?;
    let key = keyset
        .find_by_kid(&kid)
        .ok_or_else(|| Error::UnknownKid(kid.clone()))?;
    let public_key = key.to_public_key()?;

    let trusted = PublicToken::verify(&public_key, &untrusted, None, None)
        .map_err(|err| map_paseto_error(&err))?;
    let claims: AdmissionTokenClaims = serde_json::from_str(trusted.payload())?;
    validate_claims(&claims, options)?;
    Ok(claims)
}

/// Convert a unix timestamp to RFC3339.
///
/// # Errors
///
/// Returns an error if formatting fails.
pub fn rfc3339_from_unix(unix_seconds: i64) -> Result<String, Error> {
    let dt = OffsetDateTime::from_unix_timestamp(unix_seconds).map_err(|_| Error::TimeFormat)?;
    dt.format(&Rfc3339).map_err(|_| Error::TimeFormat)
}

/// Parse an RFC3339 timestamp into unix seconds.
///
/// # Errors
///
/// Returns an error if parsing fails.
pub fn unix_from_rfc3339(value: &str) -> Result<i64, Error> {
    let dt = OffsetDateTime::parse(value, &Rfc3339).map_err(|_| Error::TimeParse)?;
    Ok(dt.unix_timestamp())
}

fn validate_claims(
    claims: &AdmissionTokenClaims,
    options: &VerificationOptions<'_>,
) -> Result<(), Error> {
    if claims.iss != options.expected_issuer {
        return Err(Error::InvalidIssuer);
    }
    if claims.aud != options.expected_audience {
        return Err(Error::InvalidAudience);
    }
    if claims.action != options.expected_action {
        return Err(Error::InvalidAction);
    }

    let iat = unix_from_rfc3339(&claims.iat).map_err(|_| Error::InvalidIat)?;
    let exp = unix_from_rfc3339(&claims.exp).map_err(|_| Error::InvalidExp)?;

    if iat > options.now_unix_seconds {
        return Err(Error::InvalidIat);
    }
    if exp <= options.now_unix_seconds {
        return Err(Error::Expired);
    }
    if exp <= iat {
        return Err(Error::InvalidTtl);
    }

    let ttl = exp - iat;
    if ttl < options.min_ttl_seconds || ttl > options.max_ttl_seconds {
        return Err(Error::InvalidTtl);
    }

    Ok(())
}

fn footer_kid(footer_bytes: &[u8]) -> Result<String, Error> {
    let mut footer = Footer::new();
    footer
        .parse_bytes(footer_bytes)
        .map_err(|_| Error::InvalidFooter)?;
    let kid = footer
        .get_claim("kid")
        .and_then(|value| value.as_str())
        .ok_or(Error::InvalidFooter)?;
    Ok(kid.to_string())
}

fn pae(pieces: &[&[u8]]) -> Result<Vec<u8>, Error> {
    let count = u64::try_from(pieces.len()).map_err(|_| Error::InvalidLength)?;
    let mut out = Vec::new();
    out.extend_from_slice(&le64(count));
    for piece in pieces {
        let len = u64::try_from(piece.len()).map_err(|_| Error::InvalidLength)?;
        out.extend_from_slice(&le64(len));
        out.extend_from_slice(piece);
    }
    Ok(out)
}

fn le64(mut value: u64) -> [u8; 8] {
    let mut out = [0u8; 8];
    for (i, byte) in out.iter_mut().enumerate() {
        if i == 7 {
            value &= 0x7f;
        }
        *byte = (value & 0xff) as u8;
        value >>= 8;
    }
    out
}

fn map_paseto_error(err: &PasetorsError) -> Error {
    match err {
        PasetorsError::Base64 => Error::Base64,
        PasetorsError::TokenValidation => Error::InvalidSignature,
        PasetorsError::FooterParsing => Error::InvalidFooter,
        PasetorsError::LossyConversion => Error::InvalidLength,
        PasetorsError::Key => Error::InvalidKeyType,
        _ => Error::TokenFormat,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PaserkKey;
    use ed25519_dalek::{Signer, SigningKey};

    const NOW: i64 = 1_700_000_000;
    const ISSUER: &str = "https://genesis.example.test";
    const AUDIENCE: &str = "permesi";
    const ACTION: &str = "admission";

    fn test_claims(jti: &str) -> Result<AdmissionTokenClaims, Error> {
        Ok(AdmissionTokenClaims {
            iss: ISSUER.to_string(),
            aud: AUDIENCE.to_string(),
            iat: rfc3339_from_unix(NOW)?,
            exp: rfc3339_from_unix(NOW + 120)?,
            jti: jti.to_string(),
            action: ACTION.to_string(),
            sub: Some("client-123".to_string()),
        })
    }

    fn keyset_for_signing_key(signing_key: &SigningKey) -> Result<PaserkKeySet, Error> {
        let verifying_key = signing_key.verifying_key();
        let key = PaserkKey::from_ed25519_public_key_bytes(&verifying_key.to_bytes())?;
        Ok(PaserkKeySet {
            version: "v4".to_string(),
            purpose: "public".to_string(),
            active_kid: key.kid.clone(),
            keys: vec![key],
        })
    }

    fn sign_token(
        claims: &AdmissionTokenClaims,
        kid: &str,
        signing_key: &SigningKey,
    ) -> Result<String, Error> {
        let footer = AdmissionTokenFooter {
            kid: kid.to_string(),
        };
        let signing_input = encode_signing_input(claims, &footer)?;
        let signature = signing_key.sign(signing_input.pre_auth.as_slice());
        Ok(build_token(
            signing_input.payload.as_slice(),
            signing_input.footer.as_slice(),
            &signature.to_bytes(),
        ))
    }

    fn sign_token_without_footer(
        claims: &AdmissionTokenClaims,
        signing_key: &SigningKey,
    ) -> Result<String, Error> {
        let payload = serde_json::to_vec(claims)?;
        let pre_auth = pae(&[HEADER.as_bytes(), payload.as_slice(), b"", b""])?;
        let signature = signing_key.sign(pre_auth.as_slice());
        Ok(build_token(payload.as_slice(), b"", &signature.to_bytes()))
    }

    #[test]
    fn v4_public_sign_and_verify() -> Result<(), Error> {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let keyset = keyset_for_signing_key(&signing_key)?;
        keyset.validate()?;

        let claims = test_claims("paseto-jti")?;
        let token = sign_token(&claims, &keyset.active_kid, &signing_key)?;

        let options = VerificationOptions {
            expected_issuer: ISSUER,
            expected_audience: AUDIENCE,
            expected_action: ACTION,
            now_unix_seconds: NOW,
            min_ttl_seconds: 60,
            max_ttl_seconds: 180,
        };
        let verified = verify_v4_public(&token, &keyset, &options)?;
        assert_eq!(verified.jti, "paseto-jti");
        Ok(())
    }

    #[test]
    fn verify_v4_public_rejects_unknown_kid() -> Result<(), Error> {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let keyset = keyset_for_signing_key(&signing_key)?;

        let other_signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let other_keyset = keyset_for_signing_key(&other_signing_key)?;

        let claims = test_claims("paseto-unknown")?;
        let token = sign_token(&claims, &other_keyset.active_kid, &other_signing_key)?;

        let options = VerificationOptions {
            expected_issuer: ISSUER,
            expected_audience: AUDIENCE,
            expected_action: ACTION,
            now_unix_seconds: NOW,
            min_ttl_seconds: 60,
            max_ttl_seconds: 180,
        };

        let result = verify_v4_public(&token, &keyset, &options);
        assert!(matches!(
            result,
            Err(Error::UnknownKid(kid)) if kid == other_keyset.active_kid
        ));
        Ok(())
    }

    #[test]
    fn verify_v4_public_rejects_missing_footer() -> Result<(), Error> {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let keyset = keyset_for_signing_key(&signing_key)?;
        let claims = test_claims("paseto-no-footer")?;
        let token = sign_token_without_footer(&claims, &signing_key)?;

        let options = VerificationOptions {
            expected_issuer: ISSUER,
            expected_audience: AUDIENCE,
            expected_action: ACTION,
            now_unix_seconds: NOW,
            min_ttl_seconds: 60,
            max_ttl_seconds: 180,
        };

        let result = verify_v4_public(&token, &keyset, &options);
        assert!(matches!(result, Err(Error::MissingFooter)));
        Ok(())
    }

    #[test]
    fn verify_v4_public_rejects_invalid_issuer() -> Result<(), Error> {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let keyset = keyset_for_signing_key(&signing_key)?;
        let claims = test_claims("paseto-bad-issuer")?;
        let token = sign_token(&claims, &keyset.active_kid, &signing_key)?;

        let options = VerificationOptions {
            expected_issuer: "https://other.example.test",
            expected_audience: AUDIENCE,
            expected_action: ACTION,
            now_unix_seconds: NOW,
            min_ttl_seconds: 60,
            max_ttl_seconds: 180,
        };

        let result = verify_v4_public(&token, &keyset, &options);
        assert!(matches!(result, Err(Error::InvalidIssuer)));
        Ok(())
    }

    #[test]
    fn verify_v4_public_rejects_ttl_out_of_range() -> Result<(), Error> {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let keyset = keyset_for_signing_key(&signing_key)?;

        let claims = AdmissionTokenClaims {
            iss: ISSUER.to_string(),
            aud: AUDIENCE.to_string(),
            iat: rfc3339_from_unix(NOW)?,
            exp: rfc3339_from_unix(NOW + 30)?,
            jti: "paseto-ttl".to_string(),
            action: ACTION.to_string(),
            sub: None,
        };
        let token = sign_token(&claims, &keyset.active_kid, &signing_key)?;

        let options = VerificationOptions {
            expected_issuer: ISSUER,
            expected_audience: AUDIENCE,
            expected_action: ACTION,
            now_unix_seconds: NOW,
            min_ttl_seconds: 60,
            max_ttl_seconds: 180,
        };

        let result = verify_v4_public(&token, &keyset, &options);
        assert!(matches!(result, Err(Error::InvalidTtl)));
        Ok(())
    }
}
