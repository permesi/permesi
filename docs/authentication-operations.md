# Authentication admission and operations

OPAQUE login, password reauthentication, passkey login/enrollment and hardware-key
enrollment/authentication use shared PostgreSQL pending state. An advisory lock
serializes capacity decisions with insertion; expired rows are pruned first. Exact
bounds hold across replicas without a local fallback or sticky sessions.

Login and reauthentication have separate ceilings. Every WebAuthn purpose has its
own ceiling; registration and MFA policy values supply the appropriate purpose's
limit. `--auth-max-pending-states` is an additional ceiling for each purpose.
Defaults are 10,000 login, 1,000 reauthentication, 1,000 per registration purpose
and 1,000 MFA authentication, with 16 pending rows per subject/purpose.
Configure `--auth-pending-login-limit`, `--auth-pending-reauth-limit`,
`--auth-pending-registration-limit`, `--auth-pending-mfa-limit` and
`--auth-pending-subject-limit`; corresponding `PERMESI_AUTH_PENDING_*` variables
use the same clap validation. Limits must be 1–1,000,000. Replicas should share policy.

OPAQUE subjects are normalized account identifiers, including unknown accounts;
bound WebAuthn ceremonies use server-resolved users. Anonymous passkey starts use
the verified transport address, or a shared unknown subject when unavailable.
Subjects are stored only as domain-separated HMAC-SHA256 tags under a Vault-derived
key, not raw accounts/IPs or enumerable plain hashes. The tag is authenticated
with sealed state. One subject cannot occupy an entire flow; existing shared IP/
account request limits also apply. Shared NATs may need a higher explicit budget.
Bounded admission does not guarantee availability under distributed abuse.

## Transport trust

TCP listeners supply their real peer address. The router removes incoming
`X-Permesi-Client-IP`, `X-Forwarded-For`, `Forwarded`, `CF-Connecting-IP` and
`X-Real-IP` before installing its own canonical address. Browser forwarding headers
cannot change throttling identity. Country hints from untrusted peers are removed.

Only peers inside explicit `--auth-trusted-proxy CIDR` networks
(`PERMESI_AUTH_TRUSTED_PROXIES`, comma-separated) may supply one valid `X-Real-IP`.
The edge must overwrite this header from the actual client connection, never copy
an arbitrary forwarded chain. Invalid, duplicate or missing values fall back to
the peer. Do not trust networks containing untrusted callers. Supplied HAProxy
configurations overwrite `X-Real-IP` and strip spoofable inputs. By default no proxy
is trusted, so an unconfigured proxy shares its peer's budget.

Unix listeners accept forwarded identity only with `--auth-trust-unix-proxy`
(`PERMESI_AUTH_TRUST_UNIX_PROXY=true`). Restricted socket permissions and the
same-host edge are the trust boundary. Missing TCP connection metadata never
implicitly grants Unix trust. Deployment upgrades must configure the actual edge.

## Outcomes and deadlines

Pending capacity rejection returns 429 with `Retry-After`; authentication storage
or throttling dependency failure returns generic 503. Invalid, expired, consumed,
mismatched and rejected proofs retain 400/401 behavior. SQL details and submitted
authentication values never enter responses. Verification resend remains opaque
204 for ordinary limits but dependency failure returns 503. Revocation races deny
authority rather than being mistaken for proof success.

`--opaque-exchange-timeout-ms` bounds pool acquisition, transaction locks and each
statement for exchanges and MFA authority operations. It is not a total HTTP
deadline; token exchange has its separate complete-request deadline. Cancellation
rolls back uncommitted changes. Consumption commits before proof interpretation,
so a downstream failure requires a new ceremony rather than reference replay.

Structured `authentication exchange outcome` tracing events carry only fixed flow,
operation, outcome and elapsed milliseconds. Aggregate these dimensions to monitor
capacity, rejected proofs and dependency outages. No subject tags, emails, IPs,
users, challenges, bearer values or ciphertext enter these events. They integrate
with existing tracing/OTLP, without adding a metrics exporter or Prometheus endpoint.

## Encryption lifetime and upgrades

Transient OPAQUE state now uses XChaCha20-Poly1305 with random 192-bit nonces and
a v2 key domain. Permanent OPAQUE registration/setup and password verification
are unchanged. WebAuthn uses a separate XChaCha key domain. Each encryption uses
fresh OS randomness and fails closed on entropy failure. Set an operational ceiling
of 2^48 encryptions per derived key: random-nonce collision probability at that
volume is approximately 2^-97. Pending row limits do not bound lifetime encryption
volume; monitor cumulative starts rather than just current pending rows.

Encryption keys currently derive from the long-lived Vault OPAQUE seed. Independent
exchange-key provisioning/rotation is a separate roadmap item. Rotating that root
also changes permanent OPAQUE setup and needs a deliberate password reenrollment/
recovery migration; do not rotate it merely to clean up transcripts. Encryption
does not promise forward secrecy or erasure from archived WAL/backups.

Apply schema and runtime grants first. This batch changes transient OPAQUE ciphertext
format and authenticated admission metadata in both stores. Drain old starts or let
clients restart outstanding ceremonies; mixed old/new replicas cannot finish older
pending formats. There is no plaintext fallback. Permanent passwords and WebAuthn
credentials remain usable.

## Regression checks

Real PostgreSQL tests cover fair shared account/IP quotas, independent flow capacity,
concurrent abusive starts with one subject winner, legitimate-subject admission,
bounded saturated-pool waits, expiry/replay and schema reapplication. Existing
metadata/lifecycle and real cryptographic regressions stay enabled. Transport tests
reject forged/duplicate hints and implicit proxy trust; clap/dispatch tests preserve
explicit policy and reject invalid limits/networks. Run
`cargo test --locked -p permesi pending_ --lib`,
`cargo test --locked -p permesi operations --lib` and workspace gates.

Advisory locking still serializes starts within each store. Contention regressions
prove safety and bounded waits, not production throughput. Multi-host load/fault
exercises and independent exchange-key rotation remain tracked follow-ups.
