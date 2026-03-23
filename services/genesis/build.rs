fn main() {
    if let Err(e) = built::write_built_file() {
        eprintln!("Failed to acquire build-time information: {e}");
        std::process::exit(1);
    }

    if let Err(e) = write_commit_fallback() {
        eprintln!("Failed to write build-time commit fallback: {e}");
        std::process::exit(1);
    }
}

fn write_commit_fallback() -> std::io::Result<()> {
    use std::{env, fs::OpenOptions, io::Write, path::PathBuf};

    let fallback = match env::var("BUILD_GIT_COMMIT_HASH") {
        Ok(hash) if !hash.is_empty() && hash != "unknown" => format!("Some({hash:?})"),
        _ => "None".to_string(),
    };

    let built_path = PathBuf::from(env::var("OUT_DIR").unwrap_or_default()).join("built.rs");
    let mut built_file = OpenOptions::new().append(true).open(built_path)?;
    writeln!(
        built_file,
        "pub const FALLBACK_GIT_COMMIT_HASH: Option<&str> = {fallback};"
    )
}
