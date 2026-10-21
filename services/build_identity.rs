//! Shared service build identity and Cargo invalidation, including Git-less builds.
//!
//! Flow Overview: track the explicit CI identity and available Git references,
//! generate library metadata, then append the existing explicit-hash fallback.
//! This is build provenance, never runtime authentication or artifact attestation.

use std::{env, error::Error, fs::OpenOptions, io::Write, path::PathBuf};

/// Generates metadata with explicit environment and repository cache invalidation.
///
/// # Errors
/// Fails if Git metadata or generated output cannot be read/written.
pub fn write() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-env-changed=BUILD_GIT_COMMIT_HASH");
    // Adding explicit directives replaces Cargo's implicit package-wide scan.
    println!("cargo:rerun-if-changed=.");
    track_git()?;
    built::write_built_file()?;
    let fallback = match env::var("BUILD_GIT_COMMIT_HASH") {
        Ok(hash) if !hash.is_empty() && hash != "unknown" => format!("Some({hash:?})"),
        _ => "None".to_string(),
    };
    let built_path = PathBuf::from(env::var("OUT_DIR")?).join("built.rs");
    let mut built_file = OpenOptions::new().append(true).open(built_path)?;
    writeln!(
        built_file,
        "pub const FALLBACK_GIT_COMMIT_HASH: Option<&str> = {fallback};"
    )?;
    Ok(())
}

/// Watches loose/packed refs and worktree HEAD without requiring the Git executable.
fn track_git() -> Result<(), git2::Error> {
    let directory = env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
    let repository = match git2::Repository::discover(directory) {
        Ok(repository) => repository,
        Err(error) if error.code() == git2::ErrorCode::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    for path in [
        repository.path().join("HEAD"),
        repository.commondir().join("refs"),
        repository.commondir().join("packed-refs"),
    ] {
        if path.exists() {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
    if let Some(workdir) = repository.workdir() {
        let marker = workdir.join(".git");
        if marker.is_file() {
            println!("cargo:rerun-if-changed={}", marker.display());
        }
    }
    Ok(())
}
