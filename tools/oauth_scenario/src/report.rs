//! Allowlisted reports: case identity, timing, curated errors and reproducible build metadata.
//!
//! HTTP payloads, browser evaluations and secrets are not report inputs. JSON and
//! `JUnit` serialize the same cases so assertion failures cannot appear green in CI.

use crate::{
    error::{Failure, Result, Safe},
    registry::Case,
};
use serde::Serialize;
use std::{fmt::Write as _, path::Path, time::Instant};

#[derive(Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Passed,
    Failed,
    Blocked,
}

#[derive(Serialize)]
pub struct CaseReport {
    pub id: &'static str,
    pub description: &'static str,
    pub group: &'static str,
    pub repetition: u32,
    pub status: Status,
    pub duration_ms: u128,
    pub failure: Option<Failure>,
}

/// Public, reproducible component identity; none of these fields accept raw request data.
#[derive(Default, Serialize)]
pub struct Components {
    pub permesi_commit: String,
    pub genesis_commit: String,
    pub web_sha256: String,
    pub postgres_image: String,
    pub vault_image: String,
    pub browser_image: String,
}

#[derive(Serialize)]
pub struct Report {
    pub schema_version: u32,
    pub run_id: String,
    pub version: &'static str,
    pub commit: &'static str,
    pub fixture_seed: u64,
    pub manifest_sha256: String,
    pub components: Components,
    pub cases: Vec<CaseReport>,
    pub infrastructure_failure: Option<Failure>,
    pub cleanup_failures: Vec<Failure>,
    pub planned: [&'static str; 3],
    pub limitations: [&'static str; 3],
}

impl Report {
    /// Creates the report before setup, keeping planned capabilities outside pass counts.
    pub fn new(run_id: String, seed: u64, manifest_sha256: String) -> Self {
        Self {
            schema_version: 1,
            run_id,
            version: env!("CARGO_PKG_VERSION"),
            commit: permesi::GIT_COMMIT_HASH,
            fixture_seed: seed,
            manifest_sha256,
            components: Components::default(),
            cases: Vec::new(),
            infrastructure_failure: None,
            cleanup_failures: Vec::new(),
            planned: [
                "Refresh-token rotation/reuse detection",
                "UserInfo/introspection/revocation",
                "Client credentials/M2M grant",
            ],
            limitations: [
                "WebAuthn/passkey challenge state remains process-local; OPAQUE exchanges use shared PostgreSQL.",
                "Lifecycle diagnostics include internal rollback controls; token cases exercise real runtime-role HTTP issuance.",
                "JWT authority expires at its bounded TTL; immediate resource-server revocation/UserInfo/refresh tokens are not implemented.",
            ],
        }
    }

    /// Appends a named check with a result; failures retain only curated diagnostics.
    pub fn record(&mut self, case: Case, repetition: u32, start: Instant, result: Result<()>) {
        let status = if result.is_ok() {
            Status::Passed
        } else {
            Status::Failed
        };
        println!(
            "{} {} ({:.2}s)",
            if result.is_ok() { "PASS" } else { "FAIL" },
            case.id,
            start.elapsed().as_secs_f64()
        );
        if let Err(error) = &result {
            println!("  {}", error.message);
        }
        self.cases.push(CaseReport {
            id: case.id,
            description: case.description,
            group: case.group,
            repetition,
            status,
            duration_ms: start.elapsed().as_millis(),
            failure: result.err(),
        });
    }

    /// Marks selected but unexecuted checks as blocked rather than counting them as passes.
    pub fn block(&mut self, cases: &[Case], repetition: u32, failure: &Failure) {
        for case in cases {
            self.cases.push(CaseReport {
                id: case.id,
                description: case.description,
                group: case.group,
                repetition,
                status: Status::Blocked,
                duration_ms: 0,
                failure: Some(failure.clone()),
            });
        }
    }

    /// Requires executed checks and successful cleanup; infrastructure failures override passes.
    pub fn success(&self) -> bool {
        !self.cases.is_empty()
            && self.cases.iter().all(|c| c.status == Status::Passed)
            && self.infrastructure_failure.is_none()
            && self.cleanup_failures.is_empty()
    }

    /// Writes both artifact formats and a human summary without retaining private runtime state.
    pub fn write(&self, directory: &Path) -> Result<()> {
        std::fs::create_dir_all(directory).safe("Cannot create report directory.")?;
        atomic_write(
            directory,
            "report.json",
            &serde_json::to_vec_pretty(self).safe("Cannot encode report.")?,
        )?;
        atomic_write(directory, "junit.xml", self.junit()?.as_bytes())?;
        let passed = self
            .cases
            .iter()
            .filter(|c| c.status == Status::Passed)
            .count();
        if let Some(failure) = &self.infrastructure_failure {
            println!("Infrastructure/harness: {}", failure.message);
        }
        for failure in &self.cleanup_failures {
            println!("Cleanup: {}", failure.message);
        }
        println!(
            "{}: {passed}/{} checks passed; {} cleanup errors. Reports: {}",
            if self.success() { "SUCCESS" } else { "FAILED" },
            self.cases.len(),
            self.cleanup_failures.len(),
            directory.display()
        );
        Ok(())
    }

    /// Produces XML-safe case identity and failures, including setup and cleanup errors.
    fn junit(&self) -> Result<String> {
        let failures = self
            .cases
            .iter()
            .filter(|c| c.status != Status::Passed)
            .count()
            + usize::from(self.infrastructure_failure.is_some())
            + self.cleanup_failures.len();
        let tests = self.cases.len()
            + usize::from(self.infrastructure_failure.is_some())
            + self.cleanup_failures.len();
        let mut xml = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><testsuite name=\"oauth-scenario\" tests=\"{tests}\" failures=\"{failures}\">"
        );
        for case in &self.cases {
            write!(
                xml,
                "<testcase name=\"{}#{}\" classname=\"{}\" time=\"{}\">",
                escape(case.id),
                case.repetition,
                escape(case.group),
                format_args!("{}.{:03}", case.duration_ms / 1000, case.duration_ms % 1000)
            )
            .safe("Cannot format JUnit case.")?;
            if let Some(failure) = &case.failure {
                write!(xml, "<failure message=\"{}\"/>", escape(failure.message))
                    .safe("Cannot format JUnit failure.")?;
            }
            xml.push_str("</testcase>");
        }
        for failure in self
            .infrastructure_failure
            .iter()
            .chain(&self.cleanup_failures)
        {
            write!(
                xml,
                "<testcase name=\"harness\"><failure message=\"{}\"/></testcase>",
                escape(failure.message)
            )
            .safe("Cannot format harness failure.")?;
        }
        xml.push_str("</testsuite>");
        Ok(xml)
    }
}

/// Writes complete report bytes to a private fresh file before atomically replacing the final artifact.
fn atomic_write(directory: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    use std::{io::Write as _, os::unix::fs::OpenOptionsExt as _};
    let temporary = directory.join(format!(".{}-{}", name, uuid::Uuid::new_v4()));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .safe("Cannot create report artifact.")?;
        file.write_all(bytes)
            .safe("Cannot write report artifact.")?;
        file.sync_all().safe("Cannot sync report artifact.")?;
        std::fs::rename(&temporary, directory.join(name)).safe("Cannot publish report artifact.")
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temporary);
    }
    result
}

/// Escapes report strings for XML attributes rather than trusting fixture or error formatting.
fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        error::{Kind, Safe},
        registry::CASES,
    };

    #[test]
    fn reports_fail_assertions_blocks_and_cleanup_without_leaking_external_errors() -> Result<()> {
        let mut report = Report::new("run".into(), 7, "manifest".into());
        let case = *CASES
            .first()
            .ok_or_else(|| Failure::harness("Missing case."))?;
        let external: std::result::Result<(), &str> = Err("SECRET_COOKIE_CODE_PASSWORD_SENTINEL");
        report.record(
            case,
            1,
            Instant::now(),
            external.safe("Service unavailable."),
        );
        assert!(!report.success());
        let json = serde_json::to_string(&report).safe("Encode report.")?;
        assert!(!json.contains("SENTINEL"));
        assert!(report.junit()?.contains("<failure"));
        report.cases.clear();
        report.block(&[case], 1, &Failure::infrastructure("Setup failed."));
        assert!(!report.success());
        report.cases.clear();
        report.record(case, 1, Instant::now(), Ok(()));
        assert!(report.success());
        report.cleanup_failures.push(Failure {
            kind: Kind::Cleanup,
            message: "Cleanup failed.",
        });
        assert!(!report.success());
        assert!(report.junit()?.contains("tests=\"2\" failures=\"1\""));
        Ok(())
    }
}
