//! Stable scenario IDs and explicit coverage; planned protocol stages never count as passes.

use crate::error::{Result, check};
use clap::ValueEnum;
use serde::Serialize;

#[derive(Clone, Copy, Debug, Default, ValueEnum, PartialEq, Eq)]
pub enum Suite {
    Smoke,
    Security,
    Lifecycle,
    #[default]
    Full,
}

/// One curated case; execution uses fresh clients/tenants or a documented local sequence.
#[derive(Clone, Copy, Serialize)]
pub struct Case {
    pub id: &'static str,
    pub description: &'static str,
    pub group: &'static str,
}

pub const CASES: &[Case] = &[
    Case {
        id: "foundation.provisioning",
        description: "Real account login, hierarchy and scope configuration",
        group: "smoke",
    },
    Case {
        id: "authorization.consent",
        description: "Browser consent, exact scopes/state/nonce and hashed code",
        group: "smoke",
    },
    Case {
        id: "authorization.login_resume",
        description: "Anonymous authorization resumes after real browser login",
        group: "smoke",
    },
    Case {
        id: "authorization.cancel_saved",
        description: "Cancellation, saved consent and explicit consent policy",
        group: "security",
    },
    Case {
        id: "authorization.validation",
        description: "Redirect, response type, scope, PKCE and client negatives",
        group: "security",
    },
    Case {
        id: "authorization.tenant_isolation",
        description: "Non-member and cross-tenant management/authorization rejection",
        group: "security",
    },
    Case {
        id: "redemption.bindings",
        description: "Independent connection, wrong bindings, rollback and replay",
        group: "security",
    },
    Case {
        id: "redemption.expiration_race",
        description: "Expiration and one committed concurrent redemption winner",
        group: "security",
    },
    Case {
        id: "credentials.lifecycle",
        description: "One-time issue, overlap rotation and explicit revocation",
        group: "lifecycle",
    },
    Case {
        id: "authorization.replica_failover",
        description: "Persist on A, stop A, complete consent on B",
        group: "security",
    },
    Case {
        id: "tenant.bottom_up_deletion",
        description: "Populated parent conflicts and explicit soft deletion",
        group: "lifecycle",
    },
    Case {
        id: "authorization.client_disabled_during_consent",
        description: "Client disable on B invalidates pending consent on A",
        group: "lifecycle",
    },
    Case {
        id: "authorization.scope_removed_during_consent",
        description: "Scope removal on B rejects pending consent without issuing a code",
        group: "lifecycle",
    },
    Case {
        id: "authorization.redirect_removed_during_consent",
        description: "Removed callback receives no error redirect from pending consent",
        group: "lifecycle",
    },
    Case {
        id: "redemption.client_disable_restore",
        description: "Client re-enable and fresh consent cannot resurrect an old code",
        group: "lifecycle",
    },
    Case {
        id: "redemption.scope_remove_restore",
        description: "Restored scope authority requires a fresh grant and single-use code",
        group: "lifecycle",
    },
    Case {
        id: "redemption.redirect_remove_restore",
        description: "Restored callback requires fresh consent; original code stays invalid",
        group: "lifecycle",
    },
];

/// Validates explicit IDs before startup; unsupported IDs cannot silently reduce coverage.
pub fn select(suite: Suite, ids: &[String]) -> Result<Vec<Case>> {
    check(
        ids.iter().all(|id| CASES.iter().any(|c| c.id == id)),
        "Unknown scenario case ID.",
    )?;
    let mut chosen = CASES
        .iter()
        .copied()
        .filter(|c| {
            if !ids.is_empty() {
                return ids.iter().any(|id| id == c.id);
            }
            match suite {
                Suite::Full => true,
                Suite::Smoke => c.group == "smoke",
                Suite::Security => c.group == "security",
                Suite::Lifecycle => c.group == "lifecycle",
            }
        })
        .collect::<Vec<_>>();
    // Destroying A is deliberate: always run that topology-changing case last, including future cases.
    chosen.sort_by_key(|case| case.id == "authorization.replica_failover");
    check(!chosen.is_empty(), "No scenario cases selected.")?;
    Ok(chosen)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn registry_selection_is_explicit_and_stable() -> Result<()> {
        assert_eq!(select(Suite::Full, &[])?.len(), CASES.len());
        assert_eq!(select(Suite::Smoke, &[])?.len(), 3);
        assert_eq!(select(Suite::Lifecycle, &[])?.len(), 8);
        assert_eq!(
            select(Suite::Full, &[])?.last().map(|case| case.id),
            Some("authorization.replica_failover")
        );
        assert!(select(Suite::Full, &["token.fake".into()]).is_err());
        let ids = CASES
            .iter()
            .map(|c| c.id)
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(ids.len(), CASES.len());
        Ok(())
    }
}
