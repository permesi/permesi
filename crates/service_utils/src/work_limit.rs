//! Per-replica entry limits bound downstream work before body processing and database access.
//!
//! ## Flow Overview
//! Reserve one in-flight slot and charge a shared token bucket. If either budget
//! is exhausted, shed immediately. Dropping the permit releases capacity even on cancellation.

use anyhow::{Result, ensure};
use std::{sync::Mutex, time::Instant};
use tokio::sync::{Semaphore, SemaphorePermit};

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    rate: u32,
    burst: u32,
    concurrent: u32,
}

impl Limits {
    /// Recheck deployment settings before allocating a bucket or semaphore.
    /// # Errors
    /// Each bound must be positive and concurrency must fit the semaphore.
    pub fn new(rate: u32, burst: u32, concurrent: u32) -> Result<Self> {
        ensure!(
            rate > 0
                && burst > 0
                && concurrent > 0
                && concurrent as usize <= Semaphore::MAX_PERMITS,
            "invalid public work limits"
        );
        Ok(Self {
            rate,
            burst,
            concurrent,
        })
    }
}

#[derive(Debug)]
pub struct Budget {
    limits: Limits,
    slots: Semaphore,
    // One token costs 1e9 units, so fractional refills survive frequent arrivals.
    balance: Mutex<(u128, Instant)>,
}

impl Budget {
    #[must_use]
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            slots: Semaphore::new(limits.concurrent as usize),
            balance: Mutex::new((u128::from(limits.burst) * 1_000_000_000, Instant::now())),
        }
    }

    /// Acquire without queuing. A full semaphore consumes no rate budget.
    pub fn enter(&self) -> Option<SemaphorePermit<'_>> {
        let permit = self.slots.try_acquire().ok()?;
        let mut bucket = self.balance.lock().ok()?;
        let now = Instant::now();
        let refill = now.duration_since(bucket.1).as_nanos() * u128::from(self.limits.rate);
        bucket.0 = (bucket.0 + refill).min(u128::from(self.limits.burst) * 1_000_000_000);
        bucket.1 = now;
        bucket.0 = bucket.0.checked_sub(1_000_000_000)?;
        Some(permit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_rejects_at_concurrency_and_burst_ceilings() -> Result<()> {
        let budget = Budget::new(Limits::new(1, 2, 1)?);
        let permit = budget.enter();
        assert!(permit.is_some());
        assert!(budget.enter().is_none());
        drop(permit);
        assert!(budget.enter().is_some());
        assert!(budget.enter().is_none());
        Ok(())
    }
}
