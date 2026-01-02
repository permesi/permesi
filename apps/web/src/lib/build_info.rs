//! Build-time metadata for UI diagnostics. The health page uses this data to
//! show the current git commit without calling the backend, at the cost of
//! stale data until the next build.

/// Returns the git commit hash embedded at build time.
pub fn git_commit_hash() -> &'static str {
    match option_env!("PERMESI_WEB_GIT_SHA") {
        Some(value) if !value.is_empty() => value,
        _ => "unknown",
    }
}
