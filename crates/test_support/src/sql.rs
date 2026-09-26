//! Apply the repository's psql-style SQL scripts to test databases.
//!
//! The schema files under `db/sql/` are written for `psql`: they use meta-commands
//! such as `\ir` and `\connect`, and PL/pgSQL bodies wrapped in dollar quotes
//! (`DO $$ ... $$`). Splitting such a script on `;` in Rust breaks those bodies,
//! and the per-test splitters that did this made schema setup fail, which the
//! tests then treated as "no container runtime" and silently skipped.
//!
//! Instead, meta-command lines are dropped and the rest is sent as one
//! simple-query script, so PostgreSQL itself finds statement boundaries and
//! handles dollar quoting. The script runs in a single implicit transaction per
//! statement, exactly as `psql -f` would without `--single-transaction`.

use anyhow::{Context, Result};
use sqlx::{Executor, PgConnection};

/// Remove psql meta-command lines (`\ir`, `\connect`, ...), which the server cannot run.
///
/// Included files are not inlined; callers load each file they need explicitly.
#[must_use]
pub fn strip_psql_meta_commands(sql: &str) -> String {
    sql.lines()
        .filter(|line| !line.trim_start().starts_with('\\'))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Execute a psql-style script against `connection`.
///
/// # Errors
/// Returns an error naming `label` if any statement in the script fails.
pub async fn execute_script(connection: &mut PgConnection, label: &str, sql: &str) -> Result<()> {
    let script = strip_psql_meta_commands(sql);
    connection
        .execute(sqlx::raw_sql(sqlx::AssertSqlSafe(script)))
        .await
        .with_context(|| format!("Failed to apply SQL script: {label}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::strip_psql_meta_commands;

    #[test]
    fn strip_psql_meta_commands_keeps_dollar_quoted_bodies() {
        let sql = "CREATE TABLE users(id int);\n\\ir partitioning.sql\nDO $$\nBEGIN\n    PERFORM 1;\nEND $$;\n";
        let script = strip_psql_meta_commands(sql);
        assert!(!script.contains("\\ir"));
        assert!(script.contains("DO $$\nBEGIN\n    PERFORM 1;\nEND $$;"));
        assert!(script.contains("CREATE TABLE users(id int);"));
    }
}
