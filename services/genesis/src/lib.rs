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

    #[test]
    fn schema_sql_seeds_test_only_client() -> Result<()> {
        // Guard prod schema seed values against accidental drift.
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("sql/schema.sql");
        let canonical = canonical_sql(&path)?;
        assert_seed_client(&path, &canonical)?;
        assert_reserved_default(&path, &canonical)
    }

    #[test]
    fn dev_sql_seeds_test_only_client() -> Result<()> {
        // Guard dev/bootstrap schema seed values against accidental drift.
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../db/sql/01_genesis.sql");
        let canonical = canonical_sql(&path)?;
        assert_seed_client(&path, &canonical)?;
        assert_reserved_default(&path, &canonical)
    }
}
