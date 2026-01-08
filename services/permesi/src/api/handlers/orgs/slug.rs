//! Slug normalization helpers used by the orgs API.
//!
//! Slugs are normalized to lowercase `a-z0-9-` with collapsing separators and
//! length bounds enforced by callers.

/// Normalizes user input into a URL-safe slug (`a-z0-9-`) within the provided length bounds.
/// Returns `None` when the normalized result is empty or outside `min..=max`.
/// Caller must still enforce uniqueness and any additional policy (reserved words, etc.).
pub(super) fn normalize_slug(input: &str, min: usize, max: usize) -> Option<String> {
    let mut slug = String::new();
    let mut prev_dash = false;
    for ch in input.trim().to_lowercase().chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch);
            prev_dash = false;
        } else if !prev_dash {
            slug.push('-');
            prev_dash = true;
        }
    }
    let trimmed = slug.trim_matches('-').to_string();
    if trimmed.is_empty() {
        return None;
    }
    let truncated: String = trimmed.chars().take(max).collect();
    let normalized = truncated.trim_matches('-').to_string();
    if normalized.len() < min || normalized.len() > max {
        return None;
    }
    Some(normalized)
}

/// Builds a slug by appending a numeric `-{suffix}` to an existing base.
/// Returns `None` if the suffix would exceed `max_len` or leaves no non-empty base segment.
/// Used to deterministically resolve slug collisions without changing normalization rules.
pub(super) fn with_suffix(base: &str, suffix: usize, max_len: usize) -> Option<String> {
    let suffix = format!("-{suffix}");
    if suffix.len() >= max_len {
        return None;
    }
    let allowed = max_len.saturating_sub(suffix.len());
    let mut base_part: String = base.chars().take(allowed).collect();
    base_part = base_part.trim_end_matches('-').to_string();
    if base_part.is_empty() {
        return None;
    }
    Some(format!("{base_part}{suffix}"))
}
