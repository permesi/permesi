# Authentication and OAuth release batch

This batch closes the remaining replica-local authentication exchanges and adds
rotating OAuth refresh tokens. It uses the existing session, tenant, consent, Vault,
PostgreSQL and isolated scenario architecture. Each milestone receives a separate
imperative-subject commit, applicable regression checks and independent Claude review
through Herdr. Final GitHub CI must pass before the batch is called release-ready.

## Milestones

1. Finish hosted browser CI and reconcile existing OPAQUE documentation/TODO evidence.
   Chrome readiness works; PostgreSQL/Vault fixture ports require explicit loopback
   bindings for Podman 4.x compatibility. The corrected hosted gate is pending.
2. Replace pending passkey registration/login and hardware-key registration/MFA
   challenges with hashed, sealed, bounded PostgreSQL state. Verify actual proofs
   across replicas/restarts and rejected replay, expired state and changed bindings.
3. Revoke full and limited MFA sessions atomically with password rotation. Ensure
   a revoked factor/bootstrap session cannot finish enrollment or regain authority,
   including a concurrent elevation; clean up its pending ceremonies.
4. Add fair pending quotas, separate flow budgets, clear overload/dependency responses
   and sanitized outcome/timing telemetry. Exercise contention and document the
   trusted-edge IP policy and storage encryption-key/nonce lifetime limits.
5. Add hashed refresh-token families with atomic rotation/reuse detection to `/token`.
   Bind the exact client/user/application/organization/grant/scopes/resource and
   revalidate current authority on refresh. Require explicit offline consent, test
   public/confidential clients, replay, races, rollback, expiry and lifecycle changes.

The batch does not implement UserInfo, introspection, a token-revocation endpoint,
device authorization, M2M grants, formal OIDC certification or automatic release
publication. Signed access-token revocation at resource servers remains a separately
documented policy; revoking a refresh family prevents further issuance.

The authoritative completion markers remain in [TODO](../TODO.md). See
[shared OPAQUE state](opaque-exchanges.md), [OAuth architecture](oauth-foundation.md)
and [isolated scenarios](oauth-scenarios.md) for existing implementation and checks.
