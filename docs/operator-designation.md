# Platform-operator designation

Platform-operator designation is separate from global user roles, organization
membership and delegated OAuth scopes. An active, mailbox-verified account can be
designated through the user-detail console. The API requires an enabled operator's
exact full session with authentication in the last ten minutes. The console uses
the existing OPAQUE password reauthentication flow and asks the operator to type
the target email before submitting. Session cookies authorize these mutations across
Permesi replicas; an admin elevation is not required and adds nothing to them.
The console shows the requester, reason and request time for pending approvals,
and lets the actor choose a fixed audit reason; it does not accept free-form
incident text.
Admin elevation, the OpenBao step-up that opens the infrastructure status route, is
recorded in PostgreSQL against the exact session. Every replica reads the same record,
and it is deleted with the session.

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
required after approval. Every admin elevation binds the operator's current
revision; infrastructure access rechecks it against PostgreSQL, so an elevation
from before disable cannot revive after re-enablement. Infrastructure access
also checks that the operator account is currently active, so suspension blocks an
otherwise valid elevation. Account status transitions rotate the revision,
preventing old elevations from reviving after reactivation. Ordinary tenant roles
and saved OAuth grants are untouched by designation changes.

## Admin elevation

`POST /v1/auth/admin/elevate` takes an OpenBao token carrying the operator policy
from an enabled operator's full session. The token is validated with OpenBao on every
call and never stored. On success Permesi writes one row for that session in
`platform_operator_elevations` and returns only its expiry. `GET /v1/auth/admin/infra`
is then authorized by the session cookie and that row: `401` without a live full
session of an active account, `403` while the session holds no current elevation.

The elevation lasts no longer than `--platform-admin-ttl-seconds` (1 to 46800, default
43200), the remaining life of the OpenBao token, or the session. The OpenBao bound is
a deadline fixed on the database clock before the token is looked up, less one second
for OpenBao's rounding, so time spent waiting for OpenBao or for a lock shortens the
elevation and never extends it; a token with a second or less left grants nothing.
It belongs to one session: another session of the same user is not elevated, and
logout, session replacement, a password change, containment and session cleanup delete
it with the session. The row is written under the same identity and session locks as
every lifecycle change, after the OpenBao call, so a session that ended while OpenBao
was answering gets no elevation. Elevating again replaces the row; step-ups that
overlap on one session are applied in the order they commit, each backed by its own
valid OpenBao token. Responses of the `/v1/auth/admin` routes carry
`Cache-Control: no-store`.

Each elevation or bootstrap attempt is reserved in `admin_attempts` before OpenBao is
asked: three per user and ten per address in ten minutes, and a fifteen-minute
cooldown after three in a row that did not succeed. The limits are checked and the
attempt reserved in one transaction under a lock for the user and one for the
address, so requests that arrive together cannot all be admitted. A successful
elevation marks its attempt in the same transaction that writes the grant, so the two
are recorded together or not at all. When storage fails the answer is `503`; nothing
is recorded unless the failure was the loss of the commit's acknowledgement, in which
case the next status read shows the elevation.

Because the cookie is the credential, a session that has elevated can read
infrastructure status from any tab or client holding that cookie until the elevation
ends. The same cookie already carries the operator's user-management authority.

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

## Testing

Runtime-role PostgreSQL and HTTP tests cover distinct-operator approvals, the
one-time bootstrap exception, request expiry, replay, concurrent approval,
cross-replica state, rollback, exact recent-session checks, fixed audit reasons,
and suspension token retirement.
