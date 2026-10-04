//! OAuth scope tokens and protocol semantics, isolated from internal Principal capabilities.
//!
//! Scope names follow RFC 6749 scope-token syntax and remain case sensitive; no
//! whitespace trimming or lowercasing can silently change delegated authority.
//! Each application registry includes immutable protocol entries and API entries.
//! Registration alone never grants authority: request validation requires both the
//! configured client allow-list and independently verified tenant/user authorization.

use chrono::{DateTime, Utc};
use sqlx::{Row, postgres::PgRow};
use std::collections::HashSet;
use uuid::Uuid;

use super::ValidationError;

pub(crate) const PROTOCOL_SCOPES: [&str; 6] = [
    "openid",
    "profile",
    "email",
    "address",
    "phone",
    "offline_access",
];

/// A delegated OAuth scope token. There is no conversion from Principal permissions.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OAuthScope(String);

impl OAuthScope {
    /// Parses one case-sensitive RFC 6749 token, without normalization.
    ///
    /// # Errors
    /// Rejects empty/oversized values, non-ASCII, spaces, controls, quotes, and backslashes.
    pub fn parse(value: String) -> Result<Self, ValidationError> {
        if value.is_empty()
            || value.len() > 128
            || !value
                .bytes()
                .all(|byte| matches!(byte, 0x21 | 0x23..=0x5b | 0x5d..=0x7e))
        {
            return Err(ValidationError("Invalid OAuth scope name."));
        }
        Ok(Self(value))
    }

    /// Parses an application-defined token, reserving OIDC protocol names and the
    /// Permesi internal capability namespace to prevent misleading configurations.
    ///
    /// # Errors
    /// Rejects reserved names (including case variants) and invalid scope-token syntax.
    pub fn application(value: String) -> Result<Self, ValidationError> {
        let scope = Self::parse(value)?;
        let lower = scope.0.to_ascii_lowercase();
        if PROTOCOL_SCOPES.contains(&lower.as_str())
            || lower.starts_with("platform:")
            || lower.starts_with("users:")
        {
            return Err(ValidationError("Scope name is reserved."));
        }
        Ok(scope)
    }

    /// Returns the exact token for registry lookups and protocol serialization.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Validates a scope allow-list, rejecting duplicates instead of silently deduplicating.
    pub(crate) fn validate_list(values: Vec<String>) -> Result<Vec<Self>, ValidationError> {
        let mut unique = HashSet::new();
        let mut result = Vec::new();
        for value in values {
            let scope = Self::parse(value)?;
            if !unique.insert(scope.clone()) {
                return Err(ValidationError("Duplicate OAuth scope."));
            }
            result.push(scope);
        }
        Ok(result)
    }
}

/// Credential-free scope registry record, distinct from HTTP payloads.
#[derive(Debug)]
pub(crate) struct ScopeRecord {
    pub id: Uuid,
    pub application_id: Uuid,
    pub name: String,
    pub description: String,
    pub kind: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl sqlx::FromRow<'_, PgRow> for ScopeRecord {
    /// Decodes registry fields explicitly without adding SQL macro dependencies.
    fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            application_id: row.try_get("application_id")?,
            name: row.try_get("name")?,
            description: row.try_get("description")?,
            kind: row.try_get("kind")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}
/// Authorizes requested delegation only when every token appears in BOTH trusted
/// server-side lists: client configuration and user authorization in the selected
/// tenant. OIDC claim/consent policy must further restrict protocol scopes.
/// Caller-supplied claims and Principal.scopes must never populate these lists.
///
/// # Errors
/// Rejects duplicate, unconfigured, or unauthorized requested tokens; never widens a request.
pub fn validate_requested_scopes(
    requested: &[OAuthScope],
    client_allowed: &[OAuthScope],
    tenant_authorized: &[OAuthScope],
) -> Result<(), ValidationError> {
    let mut seen = HashSet::new();
    for scope in requested {
        if !seen.insert(scope)
            || !client_allowed.contains(scope)
            || !tenant_authorized.contains(scope)
        {
            return Err(ValidationError("Requested OAuth scope is not authorized."));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oauth_scope_validates_token_syntax_and_reserved_names() {
        for name in [
            "",
            "jobs read",
            " jobs:read",
            "jobs:read ",
            "foo\\bar",
            "foo\"bar",
            "é",
            "x\n",
        ] {
            assert!(OAuthScope::parse(name.into()).is_err(), "{name}");
        }
        for name in [
            "openid",
            "OpenID",
            "profile",
            "email",
            "address",
            "phone",
            "offline_access",
            "platform:admin",
            "users:write",
            "users:delete",
            "users:assign-role",
        ] {
            assert!(OAuthScope::application(name.into()).is_err(), "{name}");
        }
        assert!(OAuthScope::application("jobs:read".into()).is_ok());
        assert!(OAuthScope::application("custom.scope+value".into()).is_ok());
    }

    #[test]
    fn oauth_scope_preserves_case_and_rejects_duplicates() -> Result<(), ValidationError> {
        assert_ne!(
            OAuthScope::parse("jobs:read".into())?,
            OAuthScope::parse("Jobs:read".into())?
        );
        assert!(OAuthScope::validate_list(vec!["jobs:read".into(), "jobs:read".into()]).is_err());
        Ok(())
    }

    #[test]
    fn oauth_scope_requests_require_client_and_tenant_authorization() -> Result<(), ValidationError>
    {
        let read = OAuthScope::parse("jobs:read".into())?;
        let write = OAuthScope::parse("jobs:write".into())?;
        assert!(
            validate_requested_scopes(
                std::slice::from_ref(&write),
                std::slice::from_ref(&read),
                std::slice::from_ref(&write)
            )
            .is_err()
        );
        assert!(
            validate_requested_scopes(
                std::slice::from_ref(&write),
                std::slice::from_ref(&write),
                std::slice::from_ref(&read)
            )
            .is_err()
        );
        assert!(
            validate_requested_scopes(
                &[read.clone(), read.clone()],
                std::slice::from_ref(&read),
                std::slice::from_ref(&read)
            )
            .is_err()
        );
        validate_requested_scopes(
            std::slice::from_ref(&read),
            std::slice::from_ref(&read),
            std::slice::from_ref(&read),
        )?;
        Ok(())
    }
}
