# Password and MFA session lifecycle

Password rotation replaces the OPAQUE registration record and revokes all full,
MFA bootstrap and MFA challenge sessions in one PostgreSQL transaction. It removes
that user's pending OPAQUE/WebAuthn proofs and unconfirmed TOTP enrollments. It also
revokes [refresh families](oauth-refresh-tokens.md) and advances the authorization revision
so older codes cannot issue fresh delegated authority. Permanent
confirmed TOTP credentials, passkeys and hardware keys remain registered. Recovery
codes and MFA policy remain unchanged; a fresh primary login still must satisfy MFA.
The password finish route rechecks the exact full session, expiry and recent-authentication
time after admission verification and identity/session lock waits. Rotation and revocation
use that same guarded connection, so a stale principal snapshot cannot change the password
after logout, recovery or another rotation.

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
Recovery batch regeneration and TOTP disabling recheck recent authentication from the
locked session row. Full-session TOTP and hardware-key enrollment/deletion use the same
ten-minute policy; required-enrollment bootstrap sessions remain usable only while MFA
is unenrolled. Passkey registration and deletion check recency before issuing options
and again under the current-session lock before persisting credentials. A stale full
session must reauthenticate or sign in again. Storage failures and password/passkey MFA-state
failures return generic 503 without publishing partial authority or new recovery codes.

No guarded path acquires another connection from its own pool. TOTP state/audit changes
use the guard's connection. WebAuthn proof state is consumed before opening the guard;
passkey login verifies against current locked credentials and resolves MFA on that same
connection. Hardware-key finish rechecks/locks the current credential before issuing a
session. Enrollment persists the key, MFA state and audit together. Storage/commit failures
publish no replacement cookie. Rejected TOTP proofs commit their failure audit and challenge attempt,
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
`cargo test --locked -p permesi password_lifecycle --lib`,
`cargo test --locked -p permesi webauthn_http --lib` and
`cargo test --locked -p permesi mfa::integration_tests --lib`.
Broader browser MFA/account-switching scenarios and multi-host fault/load tests remain
tracked separately. TOTP time-window reuse across independent valid challenge sessions
retains existing policy; this milestone establishes session lifecycle ordering rather
than adding a new TOTP counter protocol.

Successful enrollment preserves other existing full sessions. Recovery retains registered
factors while requiring enrollment again, allowing a recovered user to explicitly replace
or remove them. Shared account/IP budgets limit enrollment and verification requests.
Every primary-login MFA challenge also carries its own PostgreSQL failure count and
issuance-time limit, default five and configurable from 1 to 20 with
`--mfa-challenge-max-attempts` / `PERMESI_MFA_CHALLENGE_MAX_ATTEMPTS`. Invalid TOTP,
recovery and hardware-key finish proofs share that count, including malformed JSON and
recovery codes. At the limit, the response has `mfa_challenge_exhausted` and the cookie
can no longer elevate on any replica; the Web console asks the user to sign in again and
routes a reloaded, unresolvable challenge back to login.
Missing dependencies return 503 without spending an attempt. This counter does not
replace the independent account/IP budgets. Deploy the schema before this version and
finish replacing old replicas before relying on terminal lockout: old binaries do not
read the new counter columns.
Completed workspace, real-dependency and independent review results are recorded in
[authentication release validation](authentication-release-validation.md).
