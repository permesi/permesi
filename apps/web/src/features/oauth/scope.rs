//! Derived application-scope presentation and form composition, without new wire fields.
//!
//! Application rows have resource/action semantics; OIDC system entries keep their
//! original tokens in a separate group. Nonconforming or unknown rows are not assignable.
//! These helpers improve editing UX; the backend enforces syntax and authorization.

use std::collections::BTreeMap;

use super::types::{ScopeKind, ScopeResponse};

/// Derived labels for a single-colon application token, never a protocol scope.
#[derive(Debug, PartialEq, Eq)]
pub struct ApplicationScopeParts<'a> {
    pub resource: &'a str,
    pub action: &'a str,
}

impl<'a> ApplicationScopeParts<'a> {
    /// Derives labels only from server-classified application rows in the convention.
    /// Malformed and unknown/system rows receive no invented semantics.
    #[must_use]
    pub fn from_scope(scope: &'a ScopeResponse) -> Option<Self> {
        if scope.kind != ScopeKind::Application {
            return None;
        }
        let (resource, action) = scope.name.split_once(':')?;
        (!resource.is_empty() && !action.is_empty() && !action.contains(':'))
            .then_some(Self { resource, action })
    }
}

/// Composes the sole API name field from exactly one resource and arbitrary action.
/// Does not trim or normalize names; validation here is UX, never authorization.
///
/// # Errors
/// Rejects empty/colon-containing parts, unsafe/oversized tokens and reserved namespaces.
pub fn compose_application_scope(resource: &str, action: &str) -> Result<String, &'static str> {
    if resource.is_empty() || action.is_empty() || resource.contains(':') || action.contains(':') {
        return Err("Enter one resource and one action, without colons.");
    }
    let name = format!("{resource}:{action}");
    if name.len() > 128
        || !name
            .bytes()
            .all(|byte| matches!(byte, 0x21 | 0x23..=0x5b | 0x5d..=0x7e))
    {
        return Err(
            "Use an OAuth scope token of at most 128 ASCII characters, without spaces, quotes or backslashes.",
        );
    }
    if matches!(resource.to_ascii_lowercase().as_str(), "users" | "platform") {
        return Err("Scope name is reserved for Permesi internal permissions.");
    }
    Ok(name)
}

/// Assignment categories keep system scopes separate from application resources.
#[derive(Debug, PartialEq, Eq)]
pub enum ScopeGroupKind {
    Resource(String),
    Protocol,
}

/// Presentation grouping only; choosing a row still submits its exact OAuth name.
pub struct ScopeGroup {
    pub kind: ScopeGroupKind,
    pub scopes: Vec<ScopeResponse>,
}

impl ScopeGroup {
    /// Labels resources exactly as registered, without interpreting user authority.
    #[must_use]
    pub fn label(&self) -> &str {
        match &self.kind {
            ScopeGroupKind::Resource(resource) => resource,
            ScopeGroupKind::Protocol => "System OIDC scopes",
        }
    }
}

/// Groups assignable application rows by exact resource; unknown kinds stay excluded.
/// Protocol rows stay separate; nonconforming application rows fail closed as unassignable.
#[must_use]
pub fn scope_assignment_groups(registry: Vec<ScopeResponse>) -> Vec<ScopeGroup> {
    let mut resources: BTreeMap<String, Vec<ScopeResponse>> = BTreeMap::new();
    let mut protocol = Vec::new();
    for scope in registry {
        match scope.kind {
            ScopeKind::Application => {
                if let Some(parts) = ApplicationScopeParts::from_scope(&scope) {
                    resources
                        .entry(parts.resource.to_owned())
                        .or_default()
                        .push(scope);
                }
            }
            ScopeKind::Protocol => protocol.push(scope),
            ScopeKind::Unknown => {}
        }
    }
    let mut groups: Vec<_> = resources
        .into_iter()
        .map(|(resource, scopes)| ScopeGroup {
            kind: ScopeGroupKind::Resource(resource),
            scopes,
        })
        .collect();
    if !protocol.is_empty() {
        groups.push(ScopeGroup {
            kind: ScopeGroupKind::Protocol,
            scopes: protocol,
        });
    }
    groups
}

/// Identifies configured names absent from the supported registry presentation.
/// These values may only be removed explicitly, never silently dropped or re-added.
#[must_use]
pub fn unavailable_scopes(selected: &[String], registry: &[ScopeResponse]) -> Vec<String> {
    selected
        .iter()
        .filter(|name| {
            !registry.iter().any(|scope| {
                scope.name == **name
                    && (scope.kind == ScopeKind::Protocol
                        || ApplicationScopeParts::from_scope(scope).is_some())
            })
        })
        .cloned()
        .collect()
}
