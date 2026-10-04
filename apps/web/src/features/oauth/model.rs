//! Pure configuration edit transitions used by browser forms and regression tests.
//!
//! Failed API requests leave drafts intact. Redirect edits preserve registered
//! bytes, while checkbox changes are restricted to the fetched scope registry.

use super::types::{ScopeKind, ScopeResponse};

pub const NO_CLIENTS: &str = "No OAuth clients";
pub const NO_APPLICATION_SCOPES: &str = "No application scopes";

/// Marks a console section active on exact paths or slash-delimited descendants.
/// This is presentation only; it does not authorize access to any resource.
#[must_use]
pub fn navigation_active(current: &str, target: &str, descendants: bool) -> bool {
    let current = current.trim_end_matches('/');
    let target = target.trim_end_matches('/');
    current == target
        || (descendants
            && current
                .strip_prefix(target)
                .is_some_and(|suffix| suffix.starts_with('/')))
}

/// Adds a draft URI, trimming surrounding whitespace only. Complex URI validation
/// stays on the server. Existing values are never normalized or deduplicated.
///
/// # Errors
/// Rejects an empty candidate or an exact duplicate without changing the draft.
pub fn add_redirect(existing: &[String], candidate: &str) -> Result<Vec<String>, &'static str> {
    let candidate = candidate.trim();
    if candidate.is_empty() {
        return Err("Enter a redirect URI.");
    }
    if existing.iter().any(|uri| uri == candidate) {
        return Err("Duplicate redirect URI.");
    }
    let mut result = existing.to_vec();
    result.push(candidate.to_owned());
    Ok(result)
}

/// Changes a checkbox only for a scope in the current server registry. This UX
/// helper does not grant authority or interpret internal Principal permissions.
pub fn toggle_scope(
    selected: &mut Vec<String>,
    registry: &[ScopeResponse],
    name: &str,
    checked: bool,
) {
    if !registry
        .iter()
        .any(|scope| scope.name == name && scope.kind != ScopeKind::Unknown)
    {
        return;
    }
    selected.retain(|scope| scope != name);
    if checked {
        selected.push(name.to_owned());
    }
}

/// Preserves useful validation messages while hiding server/SQL response details.
#[must_use]
pub fn http_message(status: u16, body: &str) -> String {
    match status {
        400 | 409 if !body.trim_start().starts_with('<') => body.to_owned(),
        401 => "Your session has expired. Sign in again.".to_owned(),
        403 | 404 => "This resource is unavailable, or your organization role does not permit this operation.".to_owned(),
        422 => "Check the form fields and try again.".to_owned(),
        429 => "Too many attempts. Please wait and try again.".to_owned(),
        _ => "The request could not be completed. Please try again.".to_owned(),
    }
}

/// Compares case-sensitive scope selections as sets so toggling a choice off/on
/// does not trigger an unnecessary replacement and saved-grant revocation.
#[must_use]
pub fn scope_selection_matches(left: &[String], right: &[String]) -> bool {
    left.len() == right.len() && left.iter().all(|name| right.contains(name))
}

/// Identifies the application-scope empty state independently of seeded OIDC rows.
/// Unknown kinds and protocol scopes are not application-defined API authority.
#[must_use]
pub fn application_scopes_empty(registry: &[ScopeResponse]) -> bool {
    !registry.iter().any(ScopeResponse::editable)
}

/// Compares exact URI registrations independently of display order. Both lists
/// contain unique original strings; no normalization or prefix matching occurs.
#[must_use]
pub fn redirect_selection_matches(left: &[String], right: &[String]) -> bool {
    left.len() == right.len() && left.iter().all(|uri| right.contains(uri))
}
