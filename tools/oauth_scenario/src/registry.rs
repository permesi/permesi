//! Stable scenario IDs and explicit coverage; planned protocol stages never count as passes.

use crate::error::{Result, check};
use clap::ValueEnum;
use serde::Serialize;

#[derive(Clone, Copy, Debug, Default, ValueEnum, PartialEq, Eq)]
pub enum Suite {
    Smoke,
    Security,
    Lifecycle,
    Token,
    Interop,
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
        id: "authentication.shared_exchanges",
        description: "Real OPAQUE login/reauth start on A, finish on B, replay and same-user session isolation",
        group: "security",
    },
    Case {
        id: "token.signing_rollback_rotation",
        description: "Real Vault signing denial rolls back consumption; shared rotation verifies old/new tokens",
        group: "token",
    },
    Case {
        id: "token.public_claims",
        description: "Runtime-role exchange, independently verified access/ID claims and hash-only receipt",
        group: "token",
    },
    Case {
        id: "token.confidential_credentials",
        description: "HTTP Basic current/retiring/revoked secrets; no public-client downgrade",
        group: "token",
    },
    Case {
        id: "token.validation",
        description: "Strict form, PKCE/client/redirect/tenant/scope negatives and no ID without openid",
        group: "token",
    },
    Case {
        id: "token.replica_replay_race",
        description: "Authorization on A, exchange on B, exactly one concurrent committed winner and replay rejection",
        group: "token",
    },
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
    Case {
        id: "interop.public_client",
        description: "Standard public OIDC discovery/S256/callback/exchange on B and protected HTTPS jobs",
        group: "interop",
    },
    Case {
        id: "interop.confidential_client",
        description: "Standard confidential OIDC HTTP Basic/S256, ID validation and protected jobs",
        group: "interop",
    },
    Case {
        id: "interop.callback_identity_rejection",
        description: "Callback state/issuer/duplicate/substitution errors and ID nonce/hash/signature rejection",
        group: "interop",
    },
    Case {
        id: "interop.resource_scope_tenant",
        description: "Exact delegated scope and application/tenant resource boundaries; cookies confer no authority",
        group: "interop",
    },
    Case {
        id: "interop.invalid_access_tokens",
        description: "Malformed/tampered/unknown-kid/ID token rejection, real finite expiry and bounded refresh",
        group: "interop",
    },
    Case {
        id: "interop.signing_key_rotation",
        description: "Real Vault rotation, cached old keys, unknown-kid refresh and old/new protected-resource access",
        group: "interop",
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
                Suite::Token => c.group == "token",
                Suite::Interop => c.group == "interop",
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
        assert_eq!(select(Suite::Interop, &[])?.len(), 6);
        assert!(
            select(Suite::Interop, &[])?
                .iter()
                .all(|case| case.group == "interop")
        );
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
