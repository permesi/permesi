//! Strict token form and Basic authentication parsing before database authority checks.
//!
//! Flow Overview: reject duplicates, ambiguous encoding and unsupported authority inputs,
//! ignore unknown extensions, select one authentication method, and retain bearer material in redacted
//! secret types. Tenant, scope and session claims are never accepted from this form.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use http::{
    HeaderMap,
    header::{AUTHORIZATION, CONTENT_TYPE},
};
use secrecy::SecretString;
use std::collections::BTreeMap;
use uuid::Uuid;

use super::TokenError;

/// Validated exchange inputs; deliberately cannot be formatted or serialized.
pub(crate) struct TokenRequest {
    pub code: SecretString,
    pub redirect_uri: String,
    pub verifier: SecretString,
}

/// Exclusive authentication choice, independent of internal authenticated sessions.
pub(crate) enum ClientAuthentication {
    Basic { client: Uuid, secret: SecretString },
    Public(Uuid),
}

impl ClientAuthentication {
    /// Returns only the public registration identifier for keyed rate limiting.
    pub(crate) const fn client_id(&self) -> Uuid {
        match self {
            Self::Basic { client, .. } | Self::Public(client) => *client,
        }
    }
}

/// Parses one bounded form and authentication mechanism, ignoring unrecognized extensions.
/// Duplicate fields, invalid encoding and recognized unsupported authority inputs fail closed.
pub(crate) fn parse(
    headers: &HeaderMap,
    body: &[u8],
) -> Result<(TokenRequest, ClientAuthentication), TokenError> {
    let content = headers.get_all(CONTENT_TYPE).iter().collect::<Vec<_>>();
    if content.len() != 1
        || content
            .first()
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.split(';').next())
            .is_none_or(|s| {
                !s.trim()
                    .eq_ignore_ascii_case("application/x-www-form-urlencoded")
            })
    {
        return Err(TokenError::InvalidRequest);
    }
    let raw = std::str::from_utf8(body).map_err(|_| TokenError::InvalidRequest)?;
    valid_encoding(raw)?;
    let mut fields = BTreeMap::new();
    for (key, value) in url::form_urlencoded::parse(body) {
        if key.contains('\u{fffd}')
            || value.contains('\u{fffd}')
            || fields
                .insert(key.into_owned(), value.into_owned())
                .is_some()
        {
            return Err(TokenError::InvalidRequest);
        }
    }
    if ["client_secret", "scope", "organization_id"]
        .iter()
        .any(|key| fields.get(*key).is_some_and(|value| !value.is_empty()))
    {
        return Err(TokenError::InvalidRequest);
    }
    if take(&mut fields, "grant_type")? != "authorization_code" {
        return Err(TokenError::UnsupportedGrant);
    }
    let client = fields
        .remove("client_id")
        .filter(|s| !s.is_empty())
        .map(|s| client_id(&s))
        .transpose()?;
    let auth = authentication(headers, client)?;
    let request = TokenRequest {
        code: take(&mut fields, "code")?.into(),
        redirect_uri: take(&mut fields, "redirect_uri")?,
        verifier: take(&mut fields, "code_verifier")?.into(),
    };
    Ok((request, auth))
}

/// Requires a nonempty, single form value; no implicit defaults widen authority.
fn take(fields: &mut BTreeMap<String, String>, key: &str) -> Result<String, TokenError> {
    fields
        .remove(key)
        .filter(|s| !s.is_empty())
        .ok_or(TokenError::InvalidRequest)
}

/// Treats public client IDs as canonical opaque strings, never UUID aliases.
fn client_id(input: &str) -> Result<Uuid, TokenError> {
    let id = Uuid::parse_str(input).map_err(|_| TokenError::InvalidClient)?;
    if id.to_string() != input {
        return Err(TokenError::InvalidClient);
    }
    Ok(id)
}

/// Supports RFC 6749 Basic form-encoded components and public `none` only.
/// A conflicting body identifier or a second Authorization header is rejected.
fn authentication(
    headers: &HeaderMap,
    body_client: Option<Uuid>,
) -> Result<ClientAuthentication, TokenError> {
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let Some(header) = values.next() else {
        return body_client
            .map(ClientAuthentication::Public)
            .ok_or(TokenError::InvalidClient);
    };
    if values.next().is_some() {
        return Err(TokenError::InvalidRequest);
    }
    let (scheme, value) = header
        .to_str()
        .map_err(|_| TokenError::InvalidClient)?
        .split_once(' ')
        .ok_or(TokenError::InvalidClient)?;
    if !scheme.eq_ignore_ascii_case("Basic") {
        return Err(TokenError::InvalidClient);
    }
    let bytes = STANDARD
        .decode(value)
        .map_err(|_| TokenError::InvalidClient)?;
    if STANDARD.encode(&bytes) != value {
        return Err(TokenError::InvalidClient);
    }
    let decoded = std::str::from_utf8(&bytes).map_err(|_| TokenError::InvalidClient)?;
    let (name, secret) = decoded.split_once(':').ok_or(TokenError::InvalidClient)?;
    let client = client_id(&component(name)?)?;
    if body_client.is_some_and(|id| id != client) {
        return Err(TokenError::InvalidRequest);
    }
    let secret = component(secret)?;
    if secret.is_empty() {
        return Err(TokenError::InvalidClient);
    }
    Ok(ClientAuthentication::Basic {
        client,
        secret: secret.into(),
    })
}

/// Decodes one Basic component without permitting form separators or lossy UTF-8.
fn component(input: &str) -> Result<String, TokenError> {
    valid_encoding(input).map_err(|_| TokenError::InvalidClient)?;
    if input.contains('&') {
        return Err(TokenError::InvalidClient);
    }
    let form = format!("v={input}");
    let mut pairs = url::form_urlencoded::parse(form.as_bytes());
    let (_, value) = pairs.next().ok_or(TokenError::InvalidClient)?;
    if pairs.next().is_some() || value.contains('\u{fffd}') {
        return Err(TokenError::InvalidClient);
    }
    Ok(value.into_owned())
}

/// Prevents the form decoder from silently accepting malformed percent escapes.
fn valid_encoding(input: &str) -> Result<(), TokenError> {
    let bytes = input.as_bytes();
    for (i, &byte) in bytes.iter().enumerate() {
        if byte == b'%'
            && bytes
                .get(i + 1..i + 3)
                .is_none_or(|v| !v.iter().all(u8::is_ascii_hexdigit))
        {
            return Err(TokenError::InvalidRequest);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;
    use secrecy::ExposeSecret as _;

    /// Supplies the exact form content type used by token clients.
    fn headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            http::HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        headers
    }

    /// Keeps required inputs valid while testing controlled parser additions.
    fn body(extra: &str) -> String {
        format!(
            "grant_type=authorization_code&code=opaque&redirect_uri=https%3A%2F%2Fc.example%2Fcb&code_verifier=verifier&{extra}"
        )
    }

    #[test]
    fn token_parser_accepts_public_and_form_encoded_basic() {
        let id = "00000000-0000-4000-8000-000000000001";
        let (request, auth) =
            parse(&headers(), body(&format!("client_id={id}")).as_bytes()).unwrap();
        assert_eq!(auth.client_id().to_string(), id);
        assert_eq!(request.code.expose_secret(), "opaque");
        let mut headers = headers();
        headers.insert(
            AUTHORIZATION,
            format!("Basic {}", STANDARD.encode(format!("{id}:a%3Ab%2B%26c")))
                .parse()
                .unwrap(),
        );
        let (_, auth) = parse(&headers, body("").as_bytes()).unwrap();
        let ClientAuthentication::Basic { secret, .. } = auth else {
            panic!("wrong method")
        };
        assert_eq!(secret.expose_secret(), "a:b+&c");
        // An empty optional body identifier is absent, including with Basic authentication.
        let (_, auth) = parse(&headers, body("client_id=").as_bytes()).unwrap();
        assert_eq!(auth.client_id().to_string(), id);
    }

    /// Unknown extensions have no authority; RFC 6749 requires ignoring them.
    #[test]
    fn token_parser_ignores_unknown_extensions_without_accepting_duplicates() {
        let id = "00000000-0000-4000-8000-000000000001";
        let (_, auth) = parse(
            &headers(),
            body(&format!(
                "client_id={id}&vendor_extension=ignored&nonce=ignored&resource=ignored&audience=ignored"
            ))
            .as_bytes(),
        )
        .unwrap();
        assert_eq!(auth.client_id().to_string(), id);
        assert!(matches!(
            parse(
                &headers(),
                body(&format!(
                    "client_id={id}&vendor_extension=one&vendor_extension=two"
                ))
                .as_bytes()
            ),
            Err(TokenError::InvalidRequest)
        ));
    }

    #[test]
    fn token_parser_rejects_ambiguous_and_authority_fields() {
        for extra in [
            "code=second",
            "scope=platform%3Aadmin",
            "organization_id=tenant",
            "client_secret=secret",
            "code_verifier=%xy",
            "client_id=%ff",
            "client_id=not-a-client",
        ] {
            assert!(parse(&headers(), body(extra).as_bytes()).is_err());
        }
        let mut headers = headers();
        headers.append(AUTHORIZATION, http::HeaderValue::from_static("Basic bad"));
        headers.append(AUTHORIZATION, http::HeaderValue::from_static("Basic bad"));
        assert!(matches!(
            parse(&headers, body("").as_bytes()),
            Err(TokenError::InvalidRequest)
        ));
    }

    #[test]
    fn token_parser_rejects_conflicting_authentication_and_encoding_aliases() {
        let id = "00000000-0000-4000-8000-000000000001";
        let other = "00000000-0000-4000-8000-000000000002";
        let mut headers = headers();
        headers.insert(
            AUTHORIZATION,
            format!("Basic {}", STANDARD.encode(format!("{id}:secret")))
                .parse()
                .unwrap(),
        );
        assert!(matches!(
            parse(&headers, body(&format!("client_id={other}")).as_bytes()),
            Err(TokenError::InvalidRequest)
        ));
        assert!(matches!(parse(&headers,body("client%5fid=00000000-0000-4000-8000-000000000001&client_id=00000000-0000-4000-8000-000000000001").as_bytes()),Err(TokenError::InvalidRequest)));
        headers.insert(
            AUTHORIZATION,
            format!("Basic {}", STANDARD.encode(format!("{id}:secret%ff")))
                .parse()
                .unwrap(),
        );
        assert!(matches!(
            parse(&headers, body("").as_bytes()),
            Err(TokenError::InvalidClient)
        ));
        headers.remove(AUTHORIZATION);
        assert!(matches!(
            parse(&headers, body("").as_bytes()),
            Err(TokenError::InvalidClient)
        ));
        assert!(matches!(
            parse(
                &headers,
                format!("grant_type=password&client_id={id}").as_bytes()
            ),
            Err(TokenError::UnsupportedGrant)
        ));
        headers.append(
            CONTENT_TYPE,
            http::HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        assert!(matches!(
            parse(&headers, body(&format!("client_id={id}")).as_bytes()),
            Err(TokenError::InvalidRequest)
        ));
    }
}
