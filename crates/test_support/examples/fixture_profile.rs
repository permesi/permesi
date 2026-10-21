//! Measures fresh fixture phases with CI's four-worker concurrency.
//!
//! Flow Overview: initialize the local engine, start four independent PostgreSQL/
//! Vault pairs per round, bootstrap canonical SQL and transit, then explicitly
//! remove every container. Output contains only durations and fixed phase names;
//! credentials, endpoints and dependency diagnostics never enter the report.

use anyhow::{Result, ensure};
use serde::Serialize;
use std::{process::ExitCode, time::Instant};
use test_support::{postgres::PostgresContainer, vault::VaultContainer};

#[derive(Serialize)]
struct Sample {
    postgres_start: u128,
    postgres_ready: u128,
    postgres_bootstrap: u128,
    vault_start: u128,
    vault_setup: u128,
    cleanup: u128,
    total: u128,
}

#[derive(Serialize)]
struct Profile {
    schema_version: u32,
    unit: &'static str,
    workers: usize,
    rounds: usize,
    wall_ms: u128,
    samples: Vec<Sample>,
}

/// Bounds the workload before creating local containers; failures never emit raw diagnostics.
#[tokio::main]
async fn main() -> ExitCode {
    if let Ok(report) = Box::pin(profile()).await
        && let Ok(json) = serde_json::to_string(&report)
    {
        println!("{json}");
        return ExitCode::SUCCESS;
    }
    eprintln!("Fixture profiling failed; no successful benchmark was recorded.");
    ExitCode::FAILURE
}

/// Runs fresh pairs without sharing schemas, keys or authority between samples.
async fn profile() -> Result<Profile> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    ensure!(arguments.len() <= 1, "Expected at most one round count");
    let rounds = arguments
        .first()
        .map_or(Ok(3), |rounds| rounds.parse::<usize>())?;
    ensure!((1..=10).contains(&rounds), "Round count must be 1..=10");
    test_support::runtime::ensure_container_runtime()?;
    let start = Instant::now();
    let mut samples = Vec::new();
    let mut failed = false;
    for _ in 0..rounds {
        // Poll all workers to completion, including cleanup, even after a failure.
        let (first, second, third, fourth) = tokio::join!(sample(), sample(), sample(), sample());
        for result in [first, second, third, fourth] {
            if let Ok(sample) = result {
                samples.push(sample);
            } else {
                failed = true;
            }
        }
        if failed {
            break;
        }
    }
    ensure!(!failed, "Fixture sample failed");
    Ok(Profile {
        schema_version: 1,
        unit: "milliseconds",
        workers: 4,
        rounds,
        wall_ms: start.elapsed().as_millis(),
        samples,
    })
}

/// Measures readiness and canonical setup separately; explicit removal is part of success.
async fn sample() -> Result<Sample> {
    let start = Instant::now();
    let postgres = PostgresContainer::start("bridge").await?;
    let postgres_start = start.elapsed().as_millis();
    let phase = Instant::now();
    postgres.wait_until_ready().await?;
    let postgres_ready = phase.elapsed().as_millis();
    let phase = Instant::now();
    postgres.bootstrap().await?;
    let postgres_bootstrap = phase.elapsed().as_millis();
    let phase = Instant::now();
    let vault = VaultContainer::start("bridge").await?;
    let vault_start = phase.elapsed().as_millis();
    let phase = Instant::now();
    vault.enable_auth("approle", "approle").await?;
    vault.enable_secrets_engine("transit", "transit").await?;
    vault
        .create_transit_key("transit", "fixture-profile", "ed25519")
        .await?;
    let vault_setup = phase.elapsed().as_millis();
    let phase = Instant::now();
    // Attempt both removals even if the first one fails.
    let vault_removed = vault.remove().await;
    let postgres_removed = postgres.remove().await;
    vault_removed?;
    postgres_removed?;
    Ok(Sample {
        postgres_start,
        postgres_ready,
        postgres_bootstrap,
        vault_start,
        vault_setup,
        cleanup: phase.elapsed().as_millis(),
        total: start.elapsed().as_millis(),
    })
}
