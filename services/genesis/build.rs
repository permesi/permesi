#[path = "../build_identity.rs"]
mod build_identity;

/// Generates service provenance; failure must stop the build instead of preserving stale identity.
fn main() {
    if let Err(error) = build_identity::write() {
        eprintln!("Failed to acquire build-time information: {error}");
        std::process::exit(1);
    }
}
