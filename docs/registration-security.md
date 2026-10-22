# Registration and verification security

Public registration creates a pending identity, not an authenticated principal.
Only possession of a valid email-verification capability can activate that identity.
A Genesis admission token authenticates the admission contract; it does not prove
that a caller is human, owns an email address, passed KYC or owns another resource.

This policy addresses synthetic signup and verification-boundary abuse. In the
incident pattern that motivated it, synthetic accounts were followed by application
code trusting self-declared asset ownership and accepting stale business actions.
Those application decisions require independent enforcement even when every account
has a verified email address. No private incident addresses or customer data are
needed to reproduce the IAM abuse cases.

## Signup admission

`--signup-mode` (`PERMESI_SIGNUP_MODE`) defaults to `public`. `restricted` requires
one or more `--signup-allowed-domain` values (`PERMESI_SIGNUP_ALLOWED_DOMAINS`,
comma-separated); matching is exact and does not include subdomains implicitly.
`closed` denies new registrations while existing accounts retain their login flow.
Allow-list settings outside restricted mode fail startup rather than being ignored.
All replicas must use the same policy.

Reserved/example namespaces are rejected by default, including `example.com`,
`example.net`, `example.org`, `.example`, `.test`, `.invalid`, `.localhost` and
`.local`, with their subdomains. Matching respects DNS label boundaries:
`sub.example.com` is reserved, while `notexample.com` and
`example.com.attacker.tld` are not classified as reserved. This classification
is not a reputation judgment about other domains. See
[IANA example domains](https://www.iana.org/help/example-domains) and
[RFC 2606](https://www.rfc-editor.org/rfc/rfc2606.html).

Signup validates domain labels, rejects trailing dots and address literals, and
bounds the normalized email to 255 bytes. International domain names must use ASCII
A-labels. Existing OPAQUE email normalization and login identifiers are unchanged;
new registration eligibility does not disable existing users. Both signup endpoints
apply policy independently, including a direct finish request, and persistence checks
it again before inserting a user. Disallowed registration returns generic 403;
malformed protocol requests retain 400. Accepted and existing-user signup responses
remain indistinguishable. Browser-supplied status, roles and verification claims
are rejected, and registration never creates tenant membership or delegated consent.

For isolated development only, `--signup-development-domain example.test`
(`PERMESI_SIGNUP_DEVELOPMENT_DOMAINS`) permits that exact reserved domain with
`--email-delivery outbox`. Exceptions must be reserved domains and cannot be used
with SMTP. The isolated runner explicitly selects outbox mode and `example.test`;
production defaults never infer exceptions from environment names or debug builds.

The existing PostgreSQL IP/account request budgets still apply: defaults are 100
requests per IP/action and 10 per account/action per 600 seconds. Signup start and
finish both count. Configure these through `--auth-rate-limit-*`; trusted transport
handling is described in [authentication operations](authentication-operations.md).
These controls constrain request volume, not the number of distinct people, and do
not guarantee availability against distributed automation. CAPTCHA integration,
signup analytics and pending-account retention remain separate roadmap items.

## Atomic verification and bounded coordination

Verification first resolves the token's account, then locks that user row before
mutating token state. Only `pending_verification` may become `active`. Disabled
accounts remain disabled, expired/replayed capabilities fail closed and successful
activation retires every sibling link. Database wall-clock time is checked after
lock acquisition, so waiting cannot extend a link's validity. The token table holds
only the hash; the protected outbox necessarily contains the link for delivery.
Neither is a public account-management interface.

Resend takes the same user-first lock before checking status/cooldown and enqueueing.
Concurrent replicas therefore cannot both pass the same cooldown. These are short
per-user row locks; unrelated accounts do not join a global signup lock. OPAQUE
computation and external network calls are outside the protected transactions.

`--auth-registration-timeout-ms` (`PERMESI_AUTH_REGISTRATION_TIMEOUT_MS`) defaults
to 1000 ms and accepts 1–10000 ms. It bounds the complete signup/verification/resend
persistence phase, including pool acquisition and commit. Transaction-local lock and
statement deadlines provide an additional bound. Cancellation before commit drops
and rolls back the tracked transaction. As with any networked database, losing a
commit acknowledgement can leave a valid committed result despite a 503 response;
it cannot undo an accepted commit. Verification retries never reactivate users or
reuse consumed capabilities; after an uncertain verification result, try signing in.
Signup retries retain the existing opaque conflict response. Storage/deadline failure
returns generic 503 without
SQL details; resend retains opaque 204 for ordinary unknown-account/cooldown cases.

## Email delivery

`--email-delivery` (`PERMESI_EMAIL_DELIVERY`) defaults to `outbox`: messages stay
pending, no worker acknowledges delivery and no verification link is logged. For
local development, `just signup-verify-url` explicitly reads the latest link from
the local database. Do not expose this privileged inspection helper to clients.
Public production onboarding requires a configured mail transport and an actual
mailbox verification; outbox acceptance alone never establishes mailbox control.

Use `--email-delivery smtp` with the following operator-owned configuration:

| Option | Environment variable | Default |
| --- | --- | --- |
| `--smtp-host` | `PERMESI_SMTP_HOST` | Required in SMTP mode |
| `--smtp-from` | `PERMESI_SMTP_FROM` | Required in SMTP mode |
| `--smtp-port` | `PERMESI_SMTP_PORT` | `465` |
| `--smtp-tls` | `PERMESI_SMTP_TLS` | `implicit` |
| `--smtp-username` | `PERMESI_SMTP_USERNAME` | Optional, paired with password |
| `--smtp-password` | `PERMESI_SMTP_PASSWORD` | Optional, paired with username |
| `--smtp-timeout-seconds` | `PERMESI_SMTP_TIMEOUT_SECONDS` | `10` (1–60) |
| `--email-lease-seconds` | `PERMESI_EMAIL_LEASE_SECONDS` | `60` (5–600) |

For a provider using STARTTLS submission, configure `PERMESI_EMAIL_DELIVERY=smtp`,
`PERMESI_SMTP_HOST` and `PERMESI_SMTP_FROM`, together with
`PERMESI_SMTP_TLS=starttls` and `PERMESI_SMTP_PORT=587`. Inject the paired
`PERMESI_SMTP_USERNAME`/`PERMESI_SMTP_PASSWORD` through your secret manager.
The implicit TLS default instead uses port 465. These settings configure the
existing instance; no mail infrastructure is provisioned automatically.

SMTP supports TLS on connection or mandatory `starttls`; neither certificate-check
bypasses nor opportunistic plaintext fallback are supported. Use environment/secret
injection for credentials rather than putting passwords on a command line. Unpaired
or empty credentials, inconsistent delivery settings and invalid lease/deadline
ordering fail startup. The lease must exceed the send deadline plus two database
phase budgets. SMTP uses the standard public certificate roots.

Workers claim one eligible row using `SKIP LOCKED`, increment its attempt count,
record a random claim identifier and expiration, and commit before network delivery.
They release the connection as well as database locks before SMTP. A second short
transaction acknowledges only the same still-live claim. Crashed workers lose their
lease; expired attempts remain subject to the configured retry limit. Stale results
cannot overwrite a replacement worker's claim. Delivery failure records a fixed
reason, leaves mail unsent and uses existing bounded backoff/retry settings.

SMTP acceptance and PostgreSQL acknowledgement cannot form one atomic transaction.
A crash between them may duplicate an email. This is at-least-once delivery, while
the contained verification capability remains single-use across replicas. No row
is marked sent merely because a development stub accepted it.

## Upgrade and application responsibilities

Apply the schema before starting the new workers. Replace every old replica/worker
before enabling SMTP or relying on the new signup/verification policy; mixed old
workers do not honor outbox leases and may still log verification payloads. Keep
SMTP disabled during that transition. Review access to prior logs and invalidate
previously logged, unused verification capabilities through controlled maintenance,
then resend links using the secure delivery configuration. Existing rows marked
sent by the legacy logging stub are not evidence of mailbox delivery. This change
does not modify a live deployment or automatically rewrite existing user accounts.

Consuming APIs must validate access-token signature, algorithm, issuer, audience,
type and expiration, then enforce the current operation's tenant/resource authority.
An ID token is not an API access token, a client allow-list is not user consent, and
email or browser-submitted metadata must not become ownership or administrator
permissions. Internal Permesi permissions remain separate from OAuth scopes.

OIDC `email_verified` records affirmative verification of email control, not KYC,
proof of human identity or ownership of an external asset. It remains derived from
server state and disclosed only under the existing `email` scope. See
[OIDC standard claims](https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims).
Business APIs must independently enforce ownership proofs, limits, current status,
operation expiry and replay protection; public endpoints need their own narrowly
scoped authorization policy. CAPTCHA and verified mail do not replace those checks.

Offline signature verification alone cannot observe a newly disabled account or
revoked grant. Existing signed access tokens retain their bounded lifetime;
immediate access-token revocation/introspection is separately tracked. High-risk
consumers must choose an authoritative current-state check rather than assuming
that possession of any valid JWT proves ongoing eligibility. The current access
and ID tokens do not carry an email-verification claim; applications needing it
must use the existing authenticated, scoped UserInfo response and bind its subject
to the authenticated user. Missing verification information must not be treated as
verified. Permesi does not issue a KYC or asset-ownership claim.

## Validation and independent review

The completed batch passes 745 default-feature and 775 all-feature workspace tests,
with both normally ignored real PostgreSQL browser tests exercised explicitly.
Strict native and WASM Clippy, formatting, Web release build, OpenAPI regeneration
and drift checks pass. Canonical owner-authenticated schema verification and actual
least-privilege runtime-login tests include lease persistence across schema reapply.
The full isolated suite passes all 37 cases on both three and five replicas with
zero cleanup errors; each topology's eight harness checks and the eight Python
harness/identity unit tests also pass. `cargo audit --deny unsound --deny yanked`
passes with the previously tracked unmaintained `paste` warning; this batch does
not remove that dependency or change the existing audit exception policy.

The disabled-account regression failed against the old activation implementation.
The SMTP trace/lock regression was deliberately mutated twice: logging a synthetic
verification payload failed its secret assertion, and holding an outbox row lock
during SMTP failed the concurrent `NOWAIT` probe. Both mutations were restored and
the corrected tests passed. All capabilities used for these tests are synthetic
and stay in owned local fixtures, not real recipients or production infrastructure.

Two independent Herdr/OMP reviews used `xai-oauth/grok-4.7`, not GitHub Copilot.
The first review confirmed an existing verification availability defect: an open
transaction waited for a rate-limit query on the same pool, requiring a second
connection. A real one-connection regression reproduced HTTP 503 instead of 204.
Moving the non-authoritative rate-limit lookup/check before transaction acquisition
fixed it without moving account status, expiry or single-use authorization outside
the locked transaction. The reviewer independently ran ten registration and eleven
email integration tests. The second review found no remaining confirmed critical,
high, medium or low issues and additionally tested CLI parser isolation under
hostile inherited signup/SMTP environment values. No confirmed findings were
rejected or left unresolved.

SMTP transport was exercised against owned local TLS peers, including certificate
rejection, mandatory STARTTLS and stalls; no external provider's deliverability,
DNS authentication records or production configuration is certified by these tests.
Outbox mode remains the default until an operator configures SMTP. The documented
commit-acknowledgement ambiguity, at-least-once email delivery, replacement of legacy
workers, and broader distributed-abuse/retention roadmap remain explicit limits.


## Incident containment

The [operator account lifecycle](account-containment.md) complements registration
prevention with auditable suspension and explicit recovery. It revokes durable
session/delegated authority across replicas without letting old verification or
login proofs reactivate an account. Immediate rejection of already-issued access
JWTs at offline resource servers remains separately planned.
