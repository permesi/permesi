//! # Genesis (Edge Admission Mint)
//!
//! `genesis` is a specialized HTTP service that sits at the network edge. Its primary
//! responsibility is to issue short-lived **Admission Tokens** (signed via Vault Transit)
//! to clients after they pass basic noise filters (rate limits, `PoW`, etc.).
//!
//! These tokens allow `permesi` (the core IAM) to verify requests offline without
//! calling the edge service on every request, maintaining the "Split-Trust" architecture.
//!
//! ## Database & Retention
//!
//! The service persists minted token IDs (`jti`) and request metadata (IP, Country, User-Agent)
//! in `PostgreSQL`. This store is used for:
//!
//! 1. **Auditing:** Tracking who requested tokens and from where.
//! 2. **Revocation:** Providing a data source for short-term token invalidation.
//!
//! ### Time-Ordered Storage (`UUIDv7`)
//!
//! Tokens use **`UUIDv7`** for their primary identifiers. `UUIDv7` is time-ordered (like ULID)
//! but native in `PostgreSQL` 18. This allows for:
//! - Efficient B-Tree indexing (sequential inserts).
//! - Direct extraction of the creation timestamp from the ID.
//! - High-performance range scans for cleanup.
//!
//! ### Partitioning & Pruning
//!
//! To prevent table bloat from millions of short-lived tokens, `genesis` uses time-based
//! range partitioning.
//!
//! - **Strategy:** Daily partitions.
//! - **Pruning:** Whole partitions are dropped instead of row-by-row `DELETE` operations.
//! - **Maintenance:** Handled via `pg_cron` or the `genesis_tokens_rollover(retention_days, future_days)` function.
//!
//! For production setup details, see the `sql/partitioning.sql` file.

pub mod api;
pub mod cli;
pub mod vault;

#[cfg(test)]
mod tests {
    use anyhow::{Context, Result, ensure};
    use std::fs;
    use std::path::{Path, PathBuf};

    const TEST_CLIENT_NAME: &str = "__test_only__";
    const TEST_CLIENT_UUID: &str = "00000000-0000-0000-0000-000000000000";

    // Normalize SQL to avoid brittle formatting checks in schema tests.
    fn canonicalize_sql(sql: &str) -> String {
        sql.chars()
            .filter(|ch| !ch.is_whitespace())
            .map(|ch| ch.to_ascii_lowercase())
            .collect()
    }

    fn canonical_sql(path: &Path) -> Result<String> {
        let sql = fs::read_to_string(path)
            .with_context(|| format!("Failed to read SQL file at {}", path.display()))?;
        Ok(canonicalize_sql(&sql))
    }

    // Smoke-test the SQL bootstrap files so test/dev schemas stay aligned.
    fn assert_seed_client(path: &Path, canonical: &str) -> Result<()> {
        let expected = format!("values(0,'{TEST_CLIENT_NAME}','{TEST_CLIENT_UUID}',false)")
            .to_ascii_lowercase();
        ensure!(
            canonical.contains(&expected),
            "Seed client is missing or mismatched in {}",
            path.display()
        );
        Ok(())
    }

    fn assert_no_seed_client(path: &Path, canonical: &str) -> Result<()> {
        let expected = format!("values(0,'{TEST_CLIENT_NAME}','{TEST_CLIENT_UUID}',false)")
            .to_ascii_lowercase();
        ensure!(
            !canonical.contains(&expected),
            "Seed client should not appear in {}",
            path.display()
        );
        Ok(())
    }

    // Look for `is_reserved boolean not null default true` in the canonicalized SQL.
    fn assert_reserved_default(path: &Path, canonical: &str) -> Result<()> {
        // canonicalize_sql strips whitespace/lowercases, so the expected snippet is compact.
        let expected = "is_reservedbooleannotnulldefaulttrue";
        ensure!(
            canonical.contains(expected),
            "Reserved default is missing or mismatched in {}",
            path.display()
        );
        Ok(())
    }

    fn assert_contains_include(path: &Path, canonical: &str, include: &str) -> Result<()> {
        ensure!(
            canonical.contains(include),
            "Expected include {include} is missing in {}",
            path.display()
        );
        Ok(())
    }

    fn assert_not_contains(path: &Path, canonical: &str, needle: &str) -> Result<()> {
        ensure!(
            !canonical.contains(needle),
            "Unexpected content {needle} found in {}",
            path.display()
        );
        Ok(())
    }

    #[test]
    fn schema_sql_integrity() -> Result<()> {
        // Ensure the base genesis schema is pure and has correct defaults.
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../db/sql/01_genesis.sql");
        let canonical = canonical_sql(&path)?;
        assert_no_seed_client(&path, &canonical)?;
        assert_reserved_default(&path, &canonical)
    }

    #[test]
    fn seed_sql_integrity() -> Result<()> {
        // Ensure the test-only seed client is present in the seed file.
        let path =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../db/sql/seed_test_client.sql");
        let canonical = canonical_sql(&path)?;
        assert_seed_client(&path, &canonical)
    }

    #[test]
    fn init_sql_includes_schemas_and_seed() -> Result<()> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../db/sql/00_init.sql");
        let canonical = canonical_sql(&path)?;
        assert_contains_include(&path, &canonical, r"\ir01_genesis.sql")?;
        assert_contains_include(&path, &canonical, r"\ir02_permesi.sql")?;
        assert_contains_include(&path, &canonical, r"\irseed_test_client.sql")
    }

    #[test]
    fn container_entrypoint_targets_init_sql() -> Result<()> {
        let path =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../db/sql/container-entrypoint.sql");
        let canonical = canonical_sql(&path)?;
        assert_contains_include(&path, &canonical, r"\i/db/sql/00_init.sql")
    }

    #[test]
    fn cron_jobs_sql_centralizes_scheduling() -> Result<()> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../db/sql/cron_jobs.sql");
        let canonical = canonical_sql(&path)?;
        assert_contains_include(&path, &canonical, "schedule_in_database")?;
        assert_contains_include(&path, &canonical, "genesis_tokens_rollover")?;
        assert_contains_include(&path, &canonical, "cleanup_expired_tokens")
    }

    #[test]
    fn maintenance_sql_does_not_register_cron_jobs() -> Result<()> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../db/sql/maintenance.sql");
        let canonical = canonical_sql(&path)?;
        assert_not_contains(&path, &canonical, "pg_cron")?;
        assert_not_contains(&path, &canonical, "cron.schedule")
    }

    #[test]
    fn partitioning_sql_does_not_register_cron_jobs() -> Result<()> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../db/sql/partitioning.sql");
        let canonical = canonical_sql(&path)?;
        assert_not_contains(&path, &canonical, "pg_cron")?;
        assert_not_contains(&path, &canonical, "cron.schedule")
    }
}
