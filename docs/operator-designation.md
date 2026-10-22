# Platform-operator designation

Platform-operator designation is separate from global user roles, organization
membership and delegated OAuth scopes. An active, mailbox-verified account can be
designated through the user-detail console. The API requires an enabled operator's
exact full session with authentication in the last ten minutes. The console uses
the existing OPAQUE password reauthentication flow and asks the operator to type
the target email before submitting. Session cookies, not admin elevation PASETOs,
authorize these mutations across Permesi replicas.
The console shows the requester, reason and request time for pending approvals,
and lets the actor choose a fixed audit reason; it does not accept free-form
incident text.
Admin elevation PASETO signing still uses a process-local key, so an elevation
token may fail verification on another replica; shared key distribution and
rotation are tracked separately in TODO.md.

`POST /v1/users/{id}/operator/request-enable` records a pending request with a
fixed audit reason; it grants no authority. A different enabled operator approves
it through `POST /v1/users/{id}/operator/enable`. Requests expire after the same
ten-minute recent-authentication window and cannot be taken over while current.
The only exception lets the sole bootstrap operator explicitly approve the first
new second operator, while there has only ever been one designation. Once a
second designation exists, every later approval needs a different enabled
operator, including restoration of a disabled designation. If only one enabled
operator remains, recovery needs a separately audited administrative procedure;
the API does not silently reopen the bootstrap exception. Rejected attempts do
not create success audit events. Keep at least three enabled operators before
incident response so disabling one still leaves two people for later approvals.

`POST /v1/users/{id}/operator/disable` removes another operator's designation
immediately. Self-action and disabling the last enabled operator are rejected.
Disable and enable rotate the designation's token revision and remove the target's
full/limited sessions and unfinished OPAQUE/WebAuthn exchanges. A fresh login is
required after approval. Every admin elevation PASETO binds the operator's current
revision; infrastructure access rechecks it against PostgreSQL, so an elevation
token from before disable cannot revive after re-enablement. Infrastructure access
also checks that the operator account is currently active, so suspension blocks an
otherwise valid elevation token. Account status transitions rotate the revision,
preventing old elevation tokens from reviving after reactivation. Ordinary tenant roles
and saved OAuth grants are untouched by designation changes.

The actor/target identities are locked in UUID order, and a bounded PostgreSQL
transaction rechecks the exact session and enabled operator record after waiting.
A designation advisory lock serializes the sole-operator exception and last-operator
rule across replicas. The request, designation transition, session/proof retirement
and append-only audit event commit atomically. `platform_operator_audit_log` records
the actor, target, operation, fixed reason, approver/requester binding and database
time. The initial bootstrap is audited in the same table. The runtime role can
insert audit rows but cannot update or delete them.

An account suspension still does not silently change its operator designation.
Incident responders should disable a compromised operator separately before account
reactivation. Suspension clears any pending designation request involving the
account. Already-issued offline-validated OAuth access JWTs remain valid until
normal expiration; immediate revocation requires the separately tracked resource
server/introspection policy. Operator designation does not itself confer any
delegated OAuth scope.

## Validation

The runtime-role PostgreSQL/HTTP tests exercise distinct approvals, the one-time
bootstrap exception, expiry, replay, concurrent approval, cross-replica state,
rollback, exact recent sessions, audit reasons and suspension token retirement.
`just test`, all-feature workspace tests, schema/bootstrap verification, OpenAPI
drift checks and browser tests pass. An independent Herdr/OMP Grok review found
audit-reason and approver-context gaps and questioned designation lock ordering;
the corrected diff received a second review with no remaining confirmed defects.
