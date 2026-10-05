//! Private per-run files with bounded traversal and deterministic artifact fingerprints.

use crate::error::{Result, Safe, check};
use sha2::{Digest, Sha256};
use std::{
    fmt::Write as _,
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
};
use uuid::Uuid;

/// Private temporary directory; dropping removes TLS keys and private browser-control files.
pub struct PrivateDir(pub PathBuf);

impl PrivateDir {
    /// Creates a fresh mode-0700 directory without reusing any prior run path.
    pub fn new() -> Result<Self> {
        let path = std::env::temp_dir().join(format!("permesi-scenario-{}", Uuid::new_v4()));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .safe("Cannot create private run directory.")?;
        Ok(Self(path))
    }

    /// Creates a mode-0600 file once; filenames are runner-authored rather than manifest input.
    pub fn write(&self, name: &str, data: &[u8]) -> Result<PathBuf> {
        let path = self.0.join(name);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .safe("Cannot create private fixture file.")?;
        file.write_all(data)
            .safe("Cannot write private fixture file.")?;
        Ok(path)
    }
    /// Explicitly removes private state so cleanup failure is reportable; Drop remains a fallback.
    pub fn remove(&self) -> Result<()> {
        match fs::remove_dir_all(&self.0) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(crate::error::Failure::harness(
                "Cannot remove private run files.",
            )),
        }
    }
}

impl Drop for PrivateDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Hashes fixture/build identity only; never used to generate passwords or PKCE material.
pub fn fingerprint(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

/// Formats public artifact digests as stable lowercase hexadecimal.
fn hex(bytes: &[u8]) -> String {
    let mut result = String::new();
    for byte in bytes {
        let _ = write!(result, "{byte:02x}");
    }
    result
}

/// Fingerprints the exact served files in a bounded tree; symlinks and special files fail closed.
pub fn web_fingerprint(root: &Path) -> Result<String> {
    let mut hash = Sha256::new();
    let mut entries = Vec::new();
    collect(root, root, &mut entries)?;
    check(
        root.join("index.html").is_file()
            && entries
                .iter()
                .any(|p| p.extension().is_some_and(|ext| ext == "wasm")),
        "Frontend dist requires index.html and compiled WASM.",
    )?;
    entries.sort();
    let mut total = 0_usize;
    for file in entries {
        hash.update(
            file.strip_prefix(root)
                .safe("Invalid asset path.")?
                .as_os_str()
                .as_encoded_bytes(),
        );
        hash.update([0]);
        let mut bytes = Vec::new();
        fs::File::open(file)
            .safe("Cannot open frontend asset.")?
            .take(64 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .safe("Cannot read frontend asset.")?;
        total = total.saturating_add(bytes.len());
        check(
            bytes.len() <= 64 * 1024 * 1024 && total <= 256 * 1024 * 1024,
            "Frontend assets exceed byte bounds.",
        )?;
        hash.update(bytes.len().to_le_bytes());
        hash.update(bytes);
    }
    Ok(hex(&hash.finalize()))
}

/// Rejects asset traversal through symlinks and bounds recursion/count to finite build output.
fn collect(root: &Path, path: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    check(
        path.components()
            .count()
            .saturating_sub(root.components().count())
            <= 8
            && files.len() <= 1024,
        "Frontend asset tree exceeds bounds.",
    )?;
    for entry in fs::read_dir(path).safe("Cannot inspect frontend dist.")? {
        let entry = entry.safe("Cannot inspect frontend asset.")?;
        let kind = entry
            .file_type()
            .safe("Cannot inspect frontend asset type.")?;
        if kind.is_dir() {
            collect(root, &entry.path(), files)?;
        } else {
            check(
                kind.is_file()
                    && entry.metadata().safe("Cannot inspect asset size.")?.len()
                        <= 64 * 1024 * 1024,
                "Only bounded regular frontend files are permitted.",
            )?;
            check(
                files.len() < 1024,
                "Frontend asset tree exceeds file count.",
            )?;
            files.push(entry.path());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_files_are_unique_and_removed_on_drop() -> Result<()> {
        let a = PrivateDir::new()?;
        let b = PrivateDir::new()?;
        assert_ne!(a.0, b.0);
        let file = a.write("private", b"secret")?;
        let path = a.0.clone();
        drop(a);
        assert!(!file.exists());
        assert!(!path.exists());
        Ok(())
    }
}
