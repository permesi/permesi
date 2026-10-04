//! Security-sensitive redirect registration with byte-for-byte comparison.
//!
//! The URL parser checks syntax but its normalized output is never stored or compared.
//! HTTPS redirects are supported for both client types. HTTP is restricted to public
//! clients using canonical loopback IP literals; localhost names, private-use schemes,
//! and native ephemeral-port matching are deferred until native application metadata exists.

use std::collections::HashSet;
use url::Url;

use super::{ValidationError, client::ClientType};

/// A validated redirect whose original bytes are retained, including path/query encoding.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RedirectUri(String);

impl RedirectUri {
    /// Accepts absolute HTTPS URLs or public-client HTTP loopback IP URLs.
    /// Rejects fragments, wildcards, userinfo, parser-repaired authority syntax,
    /// whitespace, backslashes, non-ASCII input, and malformed percent escapes.
    ///
    /// # Errors
    /// Returns a value-free validation error for unsupported or ambiguous URIs.
    pub fn parse(value: String, client_type: ClientType) -> Result<Self, ValidationError> {
        let valid_byte =
            |byte: u8| byte.is_ascii_alphanumeric() || b"-._~:/?[]@!$&'()+,;=%".contains(&byte);
        if value.is_empty() || value.len() > 2048 || !value.bytes().all(valid_byte) {
            return Err(ValidationError(
                "Redirect URI contains invalid characters or is too long.",
            ));
        }
        for (index, byte) in value.bytes().enumerate() {
            if byte == b'%' {
                let Some(escape) = value.as_bytes().get(index + 1..index + 3) else {
                    return Err(ValidationError("Invalid redirect URI percent escape."));
                };
                if !escape.iter().all(u8::is_ascii_hexdigit) {
                    return Err(ValidationError("Invalid redirect URI percent escape."));
                }
            }
        }
        let url =
            Url::parse(&value).map_err(|_| ValidationError("Invalid absolute redirect URI."))?;
        let Some((scheme, rest)) = value.split_once("://") else {
            return Err(ValidationError(
                "Redirect URI requires an explicit authority.",
            ));
        };
        let authority = rest.split(['/', '?']).next().unwrap_or_default();
        if authority.is_empty()
            || authority.contains('@')
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return Err(ValidationError(
                "Redirect URI must have a host and no userinfo or fragment.",
            ));
        }
        let loopback = authority == "127.0.0.1"
            || authority.starts_with("127.0.0.1:")
            || authority == "[::1]"
            || authority.starts_with("[::1]:");
        if scheme != "https" && !(scheme == "http" && client_type == ClientType::Public && loopback)
        {
            return Err(ValidationError(
                "Redirect URI requires HTTPS; public clients may use loopback IP HTTP.",
            ));
        }
        Ok(Self(value))
    }

    /// Returns the unnormalized registration string for storage or display.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Authorizes redirect selection only for an exact registration string. No role or
    /// scope grants this check; prefix, URL normalization, and port substitution are forbidden.
    #[must_use]
    pub fn matches_exactly(&self, requested: &str) -> bool {
        self.0 == requested
    }

    /// Validates a replacement allow-list and rejects duplicate original strings.
    pub(crate) fn validate_list(
        values: Vec<String>,
        client_type: ClientType,
    ) -> Result<Vec<Self>, ValidationError> {
        let mut unique = HashSet::new();
        let mut result = Vec::new();
        for value in values {
            let redirect = Self::parse(value, client_type)?;
            if !unique.insert(redirect.clone()) {
                return Err(ValidationError("Duplicate redirect URI."));
            }
            result.push(redirect);
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_uri_rejects_unsafe_configuration() {
        for uri in [
            "https://*.example/cb",
            "https://example/cb*",
            "https://example/cb#",
            "https://example/cb#fragment",
            "https://user@example/cb",
            "https:///example/cb",
            "https://example/\\evil",
            " https://example/cb",
            "https://example/cb\n",
            "https://example/%",
            "https://example/%zz",
            "https://example/<callback>",
            "https://example/\"callback\"",
            "http://example/cb",
            "http://localhost:8080/cb",
            "http://127.1:8080/cb",
            "http://2130706433/cb",
            "http://127.0.0.1.evil/cb",
            "com.example:/cb",
            "/cb",
        ] {
            assert!(
                RedirectUri::parse(uri.to_owned(), ClientType::Public).is_err(),
                "{uri}"
            );
        }
    }

    #[test]
    fn redirect_uri_preserves_exact_match_semantics() -> Result<(), ValidationError> {
        let uri = RedirectUri::parse(
            "https://EXAMPLE:443/a/../cb?x=%2f".into(),
            ClientType::Public,
        )?;
        assert!(uri.matches_exactly("https://EXAMPLE:443/a/../cb?x=%2f"));
        for candidate in [
            "https://example/cb?x=%2F",
            "https://EXAMPLE:443/a/../cb?x=%2f&extra=1",
            "https://EXAMPLE:443/a/../cb?x=%2f/evil",
        ] {
            assert!(!uri.matches_exactly(candidate));
        }
        Ok(())
    }

    #[test]
    fn redirect_uri_loopback_is_public_only_and_port_exact() -> Result<(), ValidationError> {
        for uri in ["http://127.0.0.1:8080/cb", "http://[::1]:8080/cb"] {
            let redirect = RedirectUri::parse(uri.into(), ClientType::Public)?;
            assert!(!redirect.matches_exactly(&uri.replace("8080", "8081")));
            assert!(RedirectUri::parse(uri.into(), ClientType::Confidential).is_err());
        }
        Ok(())
    }

    #[test]
    fn redirect_uri_rejects_duplicates() {
        assert!(
            RedirectUri::validate_list(
                vec!["https://example/cb".into(), "https://example/cb".into()],
                ClientType::Public,
            )
            .is_err()
        );
    }
}
