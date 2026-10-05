//! Standalone, real-service OAuth scenario foundation.
//!
//! Flow Overview: validate CLI/manifest, start uniquely owned local dependencies,
//! launch real services and browser, provision a fresh API tenant for each case,
//! run independent assertions, then clean up before writing JSON/JUnit results.
//! Production authentication and token policy are not modified by this harness.

mod browser;
mod cases;
mod cli;
mod client;
mod error;
mod files;
mod gateway;
mod infrastructure;
mod manifest;
mod podman;
mod process;
mod registry;
mod report;
mod runtime;
mod services;
mod tls;

use crate::{
    cli::Options,
    error::{Failure, Result, Safe},
    files::{fingerprint, web_fingerprint},
    report::{Components, Report},
};
use clap::Parser as _;
use std::{
    path::{Path, PathBuf},
    process::ExitCode,
    time::Duration,
};
use uuid::Uuid;

/// Entrypoint always reports curated failures, and returns nonzero for incomplete checks or cleanup.
#[tokio::main]
async fn main() -> ExitCode {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let options = Options::parse();
    if options.list {
        for case in registry::CASES {
            println!("{} [{}] {}", case.id, case.group, case.description);
        }
        return ExitCode::SUCCESS;
    }
    match run(&options).await {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("{}", error.message);
            ExitCode::FAILURE
        }
    }
}

/// Resolves caller-provided local artifacts, without building or changing the development stack implicitly.
fn artifact(explicit: Option<&Path>, fallback: &str) -> Result<PathBuf> {
    explicit
        .unwrap_or_else(|| Path::new(fallback))
        .canonicalize()
        .safe("Missing local build artifact; run just oauth-scenario-build first.")
}

/// Creates versioned reports even for failed startup, and never treats unexecuted cases as successes.
async fn run(options: &Options) -> Result<bool> {
    let selected = registry::select(options.suite, &options.cases)?;
    let manifest = manifest::Manifest::load(options.scenario.as_deref())?;
    let manifest_hash =
        fingerprint(&serde_json::to_vec(&manifest).safe("Cannot encode fixture identity.")?);
    let run_id = Uuid::new_v4().simple().to_string();
    let directory = options.report_dir.join(&run_id);
    std::fs::create_dir_all(&directory).safe("Cannot create run report directory.")?;
    let mut report = Report::new(run_id, options.seed, manifest_hash);
    let artifacts = (|| {
        Ok((
            artifact(options.permesi_bin.as_deref(), "target/debug/permesi")?,
            artifact(options.genesis_bin.as_deref(), "target/debug/genesis")?,
            artifact(options.web_dist.as_deref(), "apps/web/dist")?,
        ))
    })();
    let (permesi, genesis, web) = match artifacts {
        Ok(artifacts) => artifacts,
        Err(error) => {
            for repetition in 1..=options.repeat {
                report.block(&selected, repetition, &error);
            }
            report.infrastructure_failure = Some(error);
            report.write(&directory)?;
            return Ok(false);
        }
    };
    let metadata = async {
        Ok(Components {
            permesi_commit: binary_version(&permesi).await?,
            genesis_commit: binary_version(&genesis).await?,
            web_sha256: web_fingerprint(&web)?,
            postgres_image: infrastructure::POSTGRES_IMAGE.into(),
            vault_image: infrastructure::VAULT_IMAGE.into(),
            browser_image: options.browser_image.clone(),
        })
    }
    .await;
    match metadata {
        Ok(components) => report.components = components,
        Err(error) => {
            for repetition in 1..=options.repeat {
                report.block(&selected, repetition, &error);
            }
            report.infrastructure_failure = Some(error);
            report.write(&directory)?;
            return Ok(false);
        }
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(options.timeout_seconds);
    let inputs = runtime::Inputs {
        options,
        selected: &selected,
        manifest: &manifest,
        binaries: [&permesi, &genesis],
        web: &web,
    };
    for repetition in 1..=options.repeat {
        if let Err(error) =
            runtime::repetition(&inputs, repetition, &directory, deadline, &mut report).await
        {
            report.infrastructure_failure = Some(error);
        }
        if report.infrastructure_failure.is_some() || !report.cleanup_failures.is_empty() {
            break;
        }
    }
    // Interrupted/failed repetitions must not vanish from the reported selection.
    for repetition in 1..=options.repeat {
        let missing = selected
            .iter()
            .copied()
            .filter(|case| {
                !report
                    .cases
                    .iter()
                    .any(|record| record.id == case.id && record.repetition == repetition)
            })
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            report.block(
                &missing,
                repetition,
                &Failure::harness("Earlier infrastructure failure prevented this repetition."),
            );
        }
    }
    let success = report.success();
    report.write(&directory)?;
    Ok(success)
}

/// Records only expected version/commit text; arbitrary subprocess output is not forwarded.
async fn binary_version(path: &Path) -> Result<String> {
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
    error::check(
        version.len() <= 160
            && version
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b" .-_".contains(&byte)),
        "Unexpected binary identity output.",
    )?;
    Ok(version.into())
}
