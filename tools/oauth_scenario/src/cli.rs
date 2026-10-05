//! Runner-only CLI policy, separate from product configuration and deployment credentials.

use crate::registry::Suite;
use clap::Parser;
use std::path::PathBuf;

/// Bounded runner options; no live database, service URL or user credential input is accepted.
#[derive(Parser, Clone)]
#[command(
    version,
    about = "Run real OAuth scenarios on a disposable local Podman stack"
)]
pub struct Options {
    #[arg(long)]
    pub list: bool,
    #[arg(long, value_enum, default_value = "full")]
    pub suite: Suite,
    #[arg(long = "case")]
    pub cases: Vec<String>,
    #[arg(long)]
    pub scenario: Option<PathBuf>,
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..=100))]
    pub repeat: u32,
    #[arg(long, default_value_t = 1)]
    pub seed: u64,
    #[arg(long)]
    pub permesi_bin: Option<PathBuf>,
    #[arg(long)]
    pub genesis_bin: Option<PathBuf>,
    #[arg(long)]
    pub web_dist: Option<PathBuf>,
    #[arg(long, default_value = ".tmp/oauth-scenarios")]
    pub report_dir: PathBuf,
    #[arg(long, default_value_t = 900, value_parser = clap::value_parser!(u64).range(30..=3600))]
    pub timeout_seconds: u64,
    #[arg(long, default_value_t = 90, value_parser = clap::value_parser!(u64).range(1..=300))]
    pub readiness_seconds: u64,
    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u64).range(1..=60))]
    pub request_seconds: u64,
    #[arg(long, default_value_t = 15, value_parser = clap::value_parser!(u64).range(1..=120))]
    pub browser_seconds: u64,
    #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..=120))]
    pub cleanup_seconds: u64,
    #[arg(long, default_value = "localhost/permesi-scenario-browser:1")]
    pub browser_image: String,
}
