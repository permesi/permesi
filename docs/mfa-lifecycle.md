# Password and MFA session lifecycle

Password rotation replaces the OPAQUE registration record and revokes all full,
MFA bootstrap and MFA challenge sessions in one PostgreSQL transaction. It removes
that user's pending OPAQUE/WebAuthn proofs and unconfirmed TOTP enrollments. It also
revokes [refresh families](oauth-refresh-tokens.md) and advances the authorization revision
so older codes cannot issue fresh delegated authority. Permanent
confirmed TOTP credentials, passkeys and hardware keys remain registered. Recovery
codes and MFA policy remain unchanged; a fresh primary login still must satisfy MFA.

## Flow and concurrency

Factor completion rechecks the exact original cookie and active user inside a bounded
transaction. The guard locks the user before the original session, using `FOR NO KEY
UPDATE` to serialize lifecycle writers while permitting foreign-key checks. Password
rotation takes the same user writer lock. If factor completion wins, rotation revokes
its newly issued authority; if rotation wins, completion rejects the removed cookie.
Expired, missing, foreign-user and wrong-kind sessions never elevate. Bootstrap
cookies authorize enrollment only in `required_unenrolled` state. Completion removes
all bootstrap rows; a second
old bootstrap cannot replace or add a factor after that transition.

TOTP enrollment/verification, hardware-key enrollment/verification and recovery use
this guard. Successful factor completion consumes the exact original cookie and commits
replacement authority before returning `Set-Cookie`. Recovery consumes its code, changes
MFA to required enrollment, revokes full/challenge/older bootstrap sessions and issues only a limited
bootstrap session in the same transaction. Recovery likewise revokes refresh families
and advances the user revision. Recovery batch regeneration and factor/passkey
mutation also recheck current authority under lifecycle locks. Internal roles/scopes
remain server-resolved and never become delegated OAuth scopes.

No guarded path acquires another connection from its own pool. TOTP state/audit changes
use the guard's connection. WebAuthn proof state is consumed before opening the guard;
passkey login verifies against current locked credentials and resolves MFA on that same
connection. Hardware-key finish rechecks/locks the current credential before issuing a
session. Enrollment persists the key, MFA state and audit together. Storage/commit failures
publish no replacement cookie. Rejected TOTP proofs commit only their failure audit,
while retaining the original session and never publishing replacement authority. An already confirmed TOTP credential is rejected as a new
enrollment: a known credential identifier and arbitrary code cannot stand in for proof.

These changes intentionally replace the original cookie after enrollment, including
full-session enrollment. Callers must adopt the returned cookie before subsequent API
requests. Hardware-key bootstrap enrollment now returns the replacement full cookie,
matching TOTP enrollment. Failed/canceled transactions roll back authority and protected
factor changes. Single-use WebAuthn references remain consumed even if subsequent SQL
fails, so clients must restart that ceremony.

## Validation boundaries

Real PostgreSQL tests cover both password/elevation ordering, full/limited revocation,
exact-session consumption, rollback, pending ceremony cleanup and wrong-kind rejection.
Real RSA HTTP hardware-key flows register on A and finish on B, replace bootstrap and
challenge cookies, reject replay/rotation and work with a one-connection issuance pool.
Vault/PostgreSQL TOTP tests cover replacement cookies, revoked enrollment/verification/
recovery routes, removed pending TOTP credentials and the confirmed-credential bypass
regression. Existing MFA deletion/state tests stay enabled.

Run `cargo test --locked -p permesi mfa_lifecycle --lib`,
`cargo test --locked -p permesi webauthn_http --lib` and
`cargo test --locked -p permesi mfa::integration_tests --lib`.
Broader browser MFA/account-switching scenarios and multi-host fault/load tests remain
tracked separately. TOTP time-window reuse across independent valid challenge sessions
retains existing policy; this milestone establishes session lifecycle ordering rather
than adding a new TOTP counter protocol.

Successful enrollment preserves other existing full sessions. Recovery retains registered
factors while requiring enrollment again, allowing a recovered user to explicitly replace
or remove them. Recent authentication remains required for TOTP disable and recovery-code
regeneration; extending that policy to every factor mutation is tracked separately.
Shared account/IP budgets now limit enrollment and verification attempts; a separate
per-challenge terminal attempt counter remains a follow-up rather than an implemented claim.
