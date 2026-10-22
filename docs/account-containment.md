# Account suspension and containment

An enabled platform operator can suspend an account through
`POST /v1/users/{id}/suspend` and restore account eligibility through
`POST /v1/users/{id}/reactivate`. Both require the exact current full session to
have authenticated within the last ten minutes, using the existing OPAQUE
reauthentication flow. Global user roles and organization owner/admin roles alone
do not authorize these operations. Self-suspension and self-reactivation return
409, leaving another enabled operator available to administer the target.

The JSON body contains only a required `reason`: `suspected_compromise`, `abuse`,
`administrative` or `incident_resolved`. Unknown fields and arbitrary text are
rejected. Fixed classifications prevent an audit reason from becoming a place to
submit passwords, tokens or personal incident details. Successful requests return
204, including already-applied requests. Missing sessions or stale authentication
return 401, invalid typed JSON bodies return 422, nonoperators receive 403 before target lookup, authorized unknown UUIDs
receive 404, and database failures return a generic 503.

## Flow and transaction boundary

After ordinary session authentication, a bounded PostgreSQL transaction locks the
actor and target identity rows in UUID order. It rechecks the exact original full
session, locks the enabled platform-operator record, and rechecks recent
authentication after that lock wait. The target status change, authority retirement
and append-only audit event commit together. A failed audit or SQL statement rolls
them all back. This reuses the existing authentication database timeout policy;
it does not introduce a global lock, process cache or network operation inside the
transaction. Different accounts can progress independently except when they share
an actor or another existing resource lock.

Suspension sets `users.status` to `disabled`, advances its authorization revision,
removes full/bootstrap/challenge sessions and user-bound OPAQUE/WebAuthn exchanges,
retires unconfirmed TOTP enrollment, consumes pending mailbox-verification tokens,
revokes all saved OAuth grants and refresh families, and retires queued verification
mail. Pending mail payloads are cleared and any worker lease is invalidated. SMTP
already in flight cannot be recalled; its verification capability no longer works.
Confirmed authentication factors and the registered password remain registered;
this operation does not perform password or factor recovery.

Bound authorization requests retain their immutable old session binding and cannot
resume with a replacement session. Existing authorization codes retain hash-only
history but fail current revision/grant validation; they are not falsely marked as
redeemed. Requests not yet bound to an account carry no account authority and must
still complete fresh authentication. Receipt and refresh lineage history is retained.

The identity lock orders suspension against login, consent, code redemption and
refresh issuance on every replica. If issuance gets the identity first, it may
commit; suspension then retires the newly committed authority. If suspension gets
it first, the waiting issuance fails validation. Code redemption explicitly locks
the user before the grant, consistently with refresh and containment ordering.

## Recovery and old proof protection

Reactivation restores verified accounts to `active` and unverified accounts to
`pending_verification`. It never substitutes operator approval for mailbox proof.
The operator must separately verify the incident resolution before requesting
recovery; the API does not establish external identity, KYC or resource ownership.

Every status transition also advances a database-clock `authentication_not_before`
cutoff. OPAQUE and discoverable passkey login carry their authenticated exchange
creation time through proof verification and compare it while holding current
identity authority. A proof consumed before suspension cannot finish after
reactivation, even though its exchange row is already gone. Anonymous passkey
challenges cannot be attributed to one user at start, so this cutoff rejects stale
assertions without discarding other users' challenges.

Old cookies, pending proofs, authorization codes, saved consent and refresh families
remain unusable after reactivation. Fresh login and consent are required. Current
UserInfo also rejects stale authorization revisions. An already-issued signed access
JWT may still be accepted by a resource that validates only its signature and claims
until normal expiration. Authenticated introspection and immediate access-token
revocation remain a separate milestone; suspension does not add them.

Persistent role assignments, organization memberships and an enabled platform-operator
designation are retained. If a suspended operator is reactivated, a fresh login can
exercise that designation again. Incident responders can use the separately
audited [operator-designation lifecycle](operator-designation.md) to disable the
operator record before restoring account eligibility; restoration of a disabled
designation requires a new request and a distinct operator's approval. Infrastructure
access rechecks active account status, so a suspended operator cannot use an
otherwise unexpired admin elevation token. Suspension and reactivation also
rotate the retained designation revision, so a token issued before suspension
does not revive after account recovery.

## Audit, permissions and rollout

`user_lifecycle_audit_log` records actor/target UUIDs, operation, fixed reason,
previous/new status, `changed`/`unchanged` outcome and database time for successful
transitions and repeated requests. Its RESTRICT foreign keys retain attribution.
Runtime logins may select/insert events, but cannot update/delete them. Rejected
requests create no transition event. There is no audit-history API or management UI
in this milestone. A repeated suspension reapplies containment; reactivation of an
already eligible account is a recorded no-op.

The canonical bootstrap adds the cutoff, audit table/index and `suspension` refresh
revocation reason. PostgreSQL requires an UPDATE privilege for `SELECT FOR SHARE`;
the runtime role receives only column-scoped `UPDATE` on `platform_operators`,
without permission to rewrite its identity/history columns. The separate
designation-management API rotates a token revision under the same narrow grant.

Apply the schema before the binaries, then replace every old replica before relying
on containment/recovery. Earlier login implementations do not enforce the new
proof cutoff. Coordinate deployment of all replicas; do not assume mixed versions
provide the completed lifecycle boundary. Suspension is global to the IAM account;
it does not remove organization membership, transfer tenant ownership, erase data
or suspend an organization.

## Validation

The PostgreSQL/HTTP regressions live in `users/lifecycle/tests.rs`, the token
containment tests, and the existing OPAQUE/WebAuthn exchange suites. They exercise
runtime-role privileges, rejected permissions and stale sessions, post-lock
revalidation, rollback on audit failure, status recovery, consumed-proof protection,
and both orderings of containment versus token issuance. Existing code/UserInfo
recovery tests also require fresh authority rather than resurrecting old snapshots.

The isolated `authentication.account_containment` scenario creates real verified
operator/target accounts, bootstraps only the owned fixture's operator record, and
uses actual recent-session APIs for all target transitions. Browser consent and
runtime-role token endpoints prove initial authority, rejection on every configured
replica before and after recovery, and successful fresh login/consent. Run it with:

```sh
just oauth-scenario --case authentication.account_containment --replicas 3
just oauth-scenario --case authentication.account_containment --replicas 5
```

The `full`, `security` and `ha` suites include it. Its topology has real independent
Permesi processes sharing PostgreSQL, not a production multi-host or load benchmark.
The default and all-feature workspace suites, browser tests, schema/runtime-role
verification, strict native/WASM Clippy, Web build and OpenAPI drift check pass.
Both full isolated topologies pass 38/38 cases, and the five-replica harness passes
its eight recovery/isolation checks. Independent Herdr/OMP Grok review identified
one stale HA-guide count, corrected in [HA validation](oauth-ha-validation.md);
the corrected-diff review found no confirmed defects.
