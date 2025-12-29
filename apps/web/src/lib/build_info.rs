pub fn git_commit_hash() -> &'static str {
    match option_env!("PERMESI_WEB_GIT_SHA") {
        Some(value) if !value.is_empty() => value,
        _ => "unknown",
    }
}
