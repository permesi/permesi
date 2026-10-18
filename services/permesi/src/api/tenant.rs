//! Operator-bounded tenant mutations without changing tenant authority or lock order.
//!
//! Flow Overview: after HTTP input extraction, bound authentication, resolution and
//! persistence with one handler deadline. Each mutation transaction also installs
//! local PostgreSQL lock/statement deadlines before taking ancestry locks. Timeout
//! drops the owned future; shared transaction startup finishes tracking BEGIN before
//! rolling back abandoned work. Pool reuse cannot inherit transaction-local settings.
//! Existing row locks and authorization checks remain authoritative across replicas.
//! A lost response or deadline during commit can have an ambiguous outcome: callers
//! must reconcile state rather than automatically replay a mutation. These bounds
//! do not establish writer fairness, a body-read timeout or a production load SLO.

use std::{future::Future, time::Duration};

use anyhow::{Result, ensure};
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use sqlx::{PgPool, Postgres, Transaction};

/// Validated policy for hierarchy creation, organization edits and bottom-up deletion.
#[derive(Clone, Copy, Debug)]
pub struct MutationPolicy {
    lock_timeout_ms: i64,
    timeout_ms: u32,
    slug_attempts: u16,
}

impl MutationPolicy {
    /// Validates operator budgets; the lock deadline cannot exceed the handler budget.
    ///
    /// # Errors
    /// Rejects zero/out-of-range budgets, attempt limits and inconsistent deadlines.
    pub fn new(lock_timeout_ms: i64, timeout_ms: u64, slug_attempts: u16) -> Result<Self> {
        ensure!(
            (1..=10_000).contains(&lock_timeout_ms),
            "--tenant-lock-timeout-ms must be between 1 and 10000"
        );
        ensure!(
            (1..=30_000).contains(&timeout_ms),
            "--tenant-mutation-timeout-ms must be between 1 and 30000"
        );
        ensure!(
            u64::try_from(lock_timeout_ms)? <= timeout_ms,
            "--tenant-lock-timeout-ms must not exceed --tenant-mutation-timeout-ms"
        );
        ensure!(
            (1..=128).contains(&slug_attempts),
            "--tenant-slug-attempts must be between 1 and 128"
        );
        Ok(Self {
            lock_timeout_ms,
            timeout_ms: u32::try_from(timeout_ms)?,
            slug_attempts,
        })
    }

    /// Bounds organization slug candidates, including the initially requested slug.
    pub(crate) const fn slug_attempts(self) -> u16 {
        self.slug_attempts
    }

    /// Bounds all handler work after extraction, including session lookup and pool waits.
    /// Shared transaction startup survives cancelled BEGIN; tracked transactions roll back on drop.
    /// An ambiguous commit is never retried.
    pub(crate) async fn respond<F, R>(self, operation: F) -> Response
    where
        F: Future<Output = R>,
        R: IntoResponse,
    {
        match tokio::time::timeout(Duration::from_millis(u64::from(self.timeout_ms)), operation)
            .await
        {
            Ok(response) => response.into_response(),
            Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
        }
    }

    /// Installs transaction-local deadlines before any mutation or ancestry lock.
    /// Existing nonzero database deadlines remain in force when they are stricter.
    /// The handler bounds pool acquisition; server deadlines also bound cancelled SQL work.
    pub(crate) async fn begin(
        self,
        pool: &PgPool,
    ) -> Result<Transaction<'_, Postgres>, sqlx::Error> {
        let mut tx = service_utils::database::begin(pool).await?;
        sqlx::query(r"WITH budgets(name,milliseconds) AS (
                VALUES ('lock_timeout',$1::bigint),('statement_timeout',$2::bigint)
            ) SELECT pg_catalog.set_config(s.name,
                LEAST(COALESCE(NULLIF(s.setting::bigint,0),b.milliseconds),b.milliseconds)::text || 'ms',true)
            FROM pg_catalog.pg_settings s JOIN budgets b ON b.name=s.name")
        .bind(self.lock_timeout_ms)
        .bind(i64::from(self.timeout_ms))
        .execute(&mut *tx)
        .await?;
        Ok(tx)
    }

    /// Mirrors CLI defaults only in test fixtures; production policy always comes from dispatch.
    #[cfg(test)]
    pub(crate) const fn for_tests() -> Self {
        Self {
            lock_timeout_ms: 1000,
            timeout_ms: 5000,
            slug_attempts: 16,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutation_policy_rejects_invalid_and_inconsistent_budgets() {
        for (lock, total) in [
            (0, 1000),
            (-1, 1000),
            (10_001, 30_000),
            (1, 0),
            (1, 30_001),
            (1000, 999),
        ] {
            assert!(MutationPolicy::new(lock, total, 16).is_err());
        }
        for (lock, total) in [(1, 1), (1000, 5000), (10_000, 30_000)] {
            assert!(MutationPolicy::new(lock, total, 16).is_ok());
        }
        for attempts in [0, 129] {
            assert!(MutationPolicy::new(1000, 5000, attempts).is_err());
        }
        for attempts in [1, 16, 128] {
            assert!(MutationPolicy::new(1000, 5000, attempts).is_ok());
        }
    }
}
