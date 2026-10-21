//! Fail-closed artifact identity checks before any owned infrastructure is started.
//!
//! Flow Overview: read bounded service version strings, compare both services and
//! the runner's linked build identity with the caller's explicit commit, then
//! allow startup. Commit labels aid same-run provenance; they are not signatures.

use crate::{
    error::{Result, Safe, check},
    process,
};
use std::path::Path;

/// Requires a full lowercase GitHub commit ID rather than a prefix or sentinel.
pub fn parse_commit(value: &str) -> std::result::Result<String, &'static str> {
    if value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(value.to_owned())
    } else {
        Err("Expected a full 40-character lowercase commit ID")
    }
}

/// Records only expected version/commit text; arbitrary subprocess output is not forwarded.
pub async fn binary_version(path: &Path) -> Result<String> {
    let bytes = process::output(
        tokio::process::Command::new(path)
            .env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .arg("--version"),
        10,
    )
    .await?;
    let version = std::str::from_utf8(&bytes)
        .safe("Invalid binary version output.")?
        .trim();
    check(
        version.len() <= 160
            && version
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b" .-_".contains(&byte)),
        "Unexpected binary identity output.",
    )?;
    Ok(version.into())
}

/// Authorizes startup only when every native component matches the caller's exact commit/version.
pub fn verify(expected: &str, runner: &str, permesi: &str, genesis: &str) -> Result<()> {
    check(
        parse_commit(expected).is_ok(),
        "Invalid expected build identity.",
    )?;
    let version = env!("CARGO_PKG_VERSION");
    check(
        runner == expected
            && permesi == format!("permesi {version} - {expected}")
            && genesis == format!("genesis {version} - {expected}"),
        "Scenario artifacts do not match the expected commit and workspace version.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

    #[test]
    fn commit_parser_rejects_prefixes_sentinels_and_injection() {
        assert_eq!(parse_commit(COMMIT).as_deref(), Ok(COMMIT));
        for value in [
            "",
            "unknown",
            "0123456",
            &"a".repeat(41),
            &"A".repeat(40),
            &"g".repeat(40),
            &format!("{COMMIT}\n"),
        ] {
            assert!(parse_commit(value).is_err());
        }
    }

    #[test]
    fn identity_requires_both_services_runner_names_versions_and_full_commit() -> Result<()> {
        let permesi = format!("permesi {} - {COMMIT}", env!("CARGO_PKG_VERSION"));
        let genesis = format!("genesis {} - {COMMIT}", env!("CARGO_PKG_VERSION"));
        verify(COMMIT, COMMIT, &permesi, &genesis)?;
        for (runner, permesi, genesis) in [
            ("unknown", permesi.as_str(), genesis.as_str()),
            (COMMIT, "permesi 0.0.0 - unknown", genesis.as_str()),
            (COMMIT, permesi.as_str(), "genesis 0.0.0 - unknown"),
            (COMMIT, genesis.as_str(), permesi.as_str()),
            (
                COMMIT,
                "permesi 0.0.0 - 0123456789abcdef0123456789abcdef01234567",
                genesis.as_str(),
            ),
        ] {
            assert!(verify(COMMIT, runner, permesi, genesis).is_err());
        }
        assert!(verify("0123456", COMMIT, &permesi, &genesis).is_err());
        Ok(())
    }
}
