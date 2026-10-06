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

/// Disjoint supported grants; bearer values deliberately cannot be formatted or serialized.
pub(crate) enum TokenRequest {
    Code(CodeRequest),
    Refresh(RefreshRequest),
}

/// Exact code/redirect/S256 inputs, independent of refresh-family authority.
pub(crate) struct CodeRequest {
    pub code: SecretString,
    pub redirect_uri: String,
    pub verifier: SecretString,
}

/// Refresh scope may only narrow the server-stored family; no tenant inputs are accepted.
pub(crate) struct RefreshRequest {
    pub token: SecretString,
    pub scopes: Option<Vec<crate::oauth::scope::OAuthScope>>,
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
    if ["client_secret", "organization_id"]
        .iter()
        .any(|key| fields.get(*key).is_some_and(|value| !value.is_empty()))
    {
        return Err(TokenError::InvalidRequest);
    }
    let grant = take(&mut fields, "grant_type")?;
    let client = fields
        .remove("client_id")
        .filter(|s| !s.is_empty())
        .map(|s| client_id(&s))
        .transpose()?;
    let auth = authentication(headers, client)?;
    let request = grant_request(&mut fields, &grant)?;
    Ok((request, auth))
}

/// Parses only inputs belonging to the selected grant and rejects mixed authority fields.
fn grant_request(
    fields: &mut BTreeMap<String, String>,
    grant: &str,
) -> Result<TokenRequest, TokenError> {
    match grant {
        "authorization_code" => {
            if ["scope", "refresh_token"]
                .iter()
                .any(|k| fields.get(*k).is_some_and(|v| !v.is_empty()))
            {
                return Err(TokenError::InvalidRequest);
            }
            Ok(TokenRequest::Code(CodeRequest {
                code: take(fields, "code")?.into(),
                redirect_uri: take(fields, "redirect_uri")?,
                verifier: take(fields, "code_verifier")?.into(),
            }))
        }
        "refresh_token" => {
            if ["code", "redirect_uri", "code_verifier"]
                .iter()
                .any(|k| fields.get(*k).is_some_and(|v| !v.is_empty()))
            {
                return Err(TokenError::InvalidRequest);
            }
            let scopes = fields
                .remove("scope")
                .map(|s| {
                    if s.is_empty() || s.len() > 8192 {
                        return Err(TokenError::InvalidScope);
                    }
                    let scopes = crate::oauth::scope::OAuthScope::validate_list(
                        s.split(' ').map(str::to_owned).collect(),
                    )
                    .map_err(|_| TokenError::InvalidScope)?;
                    if scopes.len() > 64 {
                        return Err(TokenError::InvalidScope);
                    }
                    Ok(scopes)
                })
                .transpose()?;
            Ok(TokenRequest::Refresh(RefreshRequest {
                token: take(fields, "refresh_token")?.into(),
                scopes,
            }))
        }
        _ => Err(TokenError::UnsupportedGrant),
    }
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
        let TokenRequest::Code(request) = request else {
            panic!("wrong grant")
        };
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
    /// Refresh parses a distinct grant, retaining only redacted token and exact optional scopes.
    #[test]
    fn token_parser_refresh_rejects_mixed_grants_and_scope_ambiguity() {
        let base = "grant_type=refresh_token&client_id=00000000-0000-4000-8000-000000000001&refresh_token=opaque";
        assert!(matches!(
            parse(&headers(), base.as_bytes()),
            Ok((TokenRequest::Refresh(_), _))
        ));
        for extra in [
            "scope=",
            "scope=jobs%3Aread+jobs%3Aread",
            "scope=jobs%3Aread++runs%3Aread",
            "code=other",
            "redirect_uri=https%3A%2F%2Fclient.example",
            "code_verifier=verifier",
            "refresh_token=second",
            "organization_id=tenant",
        ] {
            assert!(parse(&headers(), format!("{base}&{extra}").as_bytes()).is_err());
        }
        assert!(
            parse(
                &headers(),
                format!("{base}&scope=openid+offline_access+jobs%3Aread").as_bytes()
            )
            .is_ok()
        );
    }
}
