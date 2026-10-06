# Shared OPAQUE authentication exchanges

Password login and password reauthentication reuse Permesi's existing OPAQUE suite,
admission verification and session cookies. Start and finish can execute on different
Permesi replicas behind the same issuer/load balancer. Both use the same PostgreSQL
writer, Vault `opaque_server_seed` and OPAQUE server identifier. Pending exchanges
never depend on a process-local map, sticky sessions or a local file. WebAuthn/passkey
ceremony state also uses [separate sealed PostgreSQL storage](webauthn-exchanges.md).

## Flow and trust boundary

Start validates the existing request and builds the library's credential response.
It generates a random UUID and stores only its SHA-256 hash in `opaque_exchanges`.
The serialized server transcript is encrypted with ChaCha20-Poly1305 using a fresh
96-bit nonce and a domain-separated HMAC-SHA256 key derived from the Vault seed.
AEAD authenticates the reference hash, purpose, user, registered credential hash,
original reauthentication session hash, issuance/expiration and configured server ID.
The raw reference is returned to the client; it and the decrypted transcript are
never logged or persisted in plaintext. Passwords still never reach the server.

PostgreSQL supplies issuance and expiration time. `PERMESI_OPAQUE_LOGIN_TTL_SECONDS`
defaults to 300 seconds and accepts 1–3600 seconds; clap and dispatch both validate
it. `PERMESI_AUTH_MAX_PENDING_STATES` defaults to 10,000. This is now a cluster-wide
capacity shared by OPAQUE login and reauthentication, while WebAuthn uses
separate per-purpose cluster-wide limits. Replicas must use consistent limits.
An advisory transaction lock covers expiry pruning, the capacity check and insertion,
so concurrent replicas cannot each reserve the last slot. Exhaustion returns 429;
database or cryptographic failures fail closed with a generic 500.
Pruning uses the current database statement's time so PostgreSQL can use the expiry
index. The strict global limit still serializes starts and counts pending rows; this
bounded design favors simple capacity correctness. Production throughput/queueing
and alternatives to the exact count remain operational follow-ups, not proven linear
scaling with added replicas.
Existing admission and PostgreSQL IP/email rate limits run before reserving state,
but the store has no per-principal pending quota. Sustained starts for different
accounts can exhaust the shared cap. Production abuse testing, trusted-edge handling
of forwarded IP headers, separate flow capacity controls and fair occupancy quotas
remain tracked hardening work; the global bound alone is not abuse isolation.

`PERMESI_OPAQUE_EXCHANGE_TIMEOUT_MS` bounds each database lock and statement in
start, consumption and identity/session-write transactions. It defaults to 1000 ms
and accepts 1–10,000 ms, validated by clap, dispatch and the store. Transaction-local
settings reuse the existing PostgreSQL deadline helper and do not alter pooled-session
defaults. A timeout returns generic 500 without a successful authentication response;
consumption rolled back before commitment remains unused, while a later issuance
failure leaves the already consumed exchange unavailable. This is a database deadline,
not a claim of a total HTTP/network deadline or a measured production throughput target.
If an original session is revoked between reauthentication's session check and state
insertion, the foreign key rejects the reservation and the handler returns generic
500; classifying that race as 401 and transient database failures as 503 is deferred.

Finish uses `DELETE ... RETURNING` to consume exactly one attempt before verifying
the proof. Expired, tampered, replayed and wrong-purpose/session attempts return 401
without issuing authority. A well-formed wrong password proof also consumes the
exchange. Malformed messages rejected before state lookup do not consume it. Unknown
or inactive login accounts still get a dummy start transcript and generic denial;
browser email fields cannot replace the server-bound user. Reauthentication is bound
to the original verified full session, including when the user has another session.
Logout/revocation removes that session's pending elevation rows through a foreign key.

After protocol verification, the server checks that the user is active and the exact
registered password record is still current. A transaction holds a shared user-row
lock through session insertion or authentication-time elevation. Password rotation
and account-status changes cannot pass that lock and invalidate the identity before
issuance; rotation that follows full-session issuance revokes that session too. MFA
still determines whether login issues a full, bootstrap or challenge session. The
same transaction revokes full sessions before required-MFA bootstrap issuance.
Password rotation's existing revocation covers full sessions; revoking limited MFA
bootstrap/challenge sessions on rotation remains a separate follow-up.
The exchange is already consumed if later issuance fails, so the client must restart
the existing login flow rather than replay a proof.

## Deployment and retention

Reapply `db/sql/02_permesi.sql` as the existing table owner with `ON_ERROR_STOP=1`
before starting the new binary. The change is additive and preserves users, sessions,
OAuth configuration and grants. Bootstrap and schema reapplication grant the runtime
role SELECT/INSERT/DELETE on the exchange table and revoke UPDATE/TRUNCATE/REFERENCES/
TRIGGER/MAINTAIN, including PostgreSQL's broad bootstrap grant. Reapplication is tested
without clearing live encrypted exchanges.

Deploy replicas with the same exchange format, seed and server ID. During migration
from the old in-memory implementation, drain pending password exchanges or have users
restart them after cutover; old and new replicas cannot finish each other's pending
state. Existing session cookies remain valid. Changing the OPAQUE seed also invalidates
registered credentials, as before; it is not an independent exchange-key rotation.
A misconfigured replica fails to decrypt and consumes the attempted row rather than
falling back to a local cache or a different identifier.

Completed exchanges are physically removed because they are transient protocol state,
not tenant resources. New starts prune expired rows, and the existing scheduled/manual
`cleanup_expired_tokens()` maintenance also removes them. Expiration rejects use even
before cleanup runs. Ciphertext may remain in backups, WAL or replicas until normal
retention removes it. Encryption under a long-lived Vault seed does not provide
cryptographic erasure or forward secrecy for archived transcripts after combined
database/seed compromise. Permesi uses independent random HTTPS session cookies;
the OPAQUE session key is not used to encrypt those cookies.
The random 96-bit AEAD nonce has a finite collision bound under the long-lived
seed-derived key. A per-exchange subkey or extended-nonce design and an explicit
encryption-key lifetime policy remain defense-in-depth follow-ups for large cumulative
issuance volumes; this phase retains the existing library's ChaCha20-Poly1305 primitive.

## Regression checks

Run the real PostgreSQL regressions with
`cargo test --locked -p permesi --lib api::handlers::auth::tests::opaque_exchange`.
They cover independent replicas/restart, concurrent single use, real expiry, wrong
purpose/session, revoked sessions, disabled users, password revision/issuance races,
seed/server-ID mismatch, ciphertext/expiry tampering, shared capacity and cleanup,
storage outage, and hash-only/encrypted persistence. The restart regression failed
with 401 on the old in-memory store and passes on the shared store.
Real lock-contention regressions fail on unbounded start, consume and identity waits
and pass with the configured deadlines. Scheduled cleanup preserves a live proof,
and schema reapplication removes excess maintenance privileges.
Nondefault deadlines reach the actual server configuration and transaction settings;
connection settings revert after commit. Database scheduling barriers exercise the
actual login/reauthentication handlers' identity locks and the global capacity
check/insertion race. Metadata-retargeting tests cover purpose, user, credential
revision, original session, external reference and timestamps. Malformed finalizations
preserve pending proofs and their original expiry for both flows.
Cross-replica MFA regressions verify bootstrap/challenge session kinds, required-MFA
full-session revocation, single use and rollback when scoped-session issuance fails.
They do not claim complete multi-replica passkey/TOTP browser coverage.

The isolated binary adds `authentication.shared_exchanges` to the full/security suites.
Run `just oauth-scenario-build`, then
`target/debug/permesi-oauth-scenario --case authentication.shared_exchanges`.
It uses real Vault/Genesis/Permesi A/B and runtime-role PostgreSQL access: start on A,
finish on B, verify a real session, reject replay, then repeat for reauthentication
and reject another session of the same user. No exchange or session is seeded in SQL.
See [scenario instructions](oauth-scenarios.md) and [TODO](../TODO.md) for validation
status and remaining WebAuthn, multi-host/load/fault and operational work.

## Validation and independent review

The local implementation passes 29 real PostgreSQL exchange regressions, 581 default
and 611 all-feature workspace tests, formatting and strict all-target/all-feature Clippy.
OpenAPI generation/comparisons and the native/release WASM builds pass. The two ignored
real PostgreSQL browser tests were exercised separately. Claude independently passed
the console browser stage, both PostgreSQL browser stages and all seven harness checks
again against the final rebuilt native binaries and CSR assets, verified
fresh bootstrap and schema reapplication/privilege verification, and passed all 29 isolated
scenarios twice against the corrected routing. The primary session's restrictions on
direct Node loopback binding and Podman runtime access prevented its combined browser
and isolated-stack commands; the independent reviewer ran those normal workflows.

Four independent Claude reviews through Herdr identified the scenario's A-only routing,
unbounded database waits, nonindexable pruning, bootstrap/reapplication privilege drift,
the missing schema-check guard and overbroad documentation; fixes were independently
reverified. Targeted code reversions in
disposable scratch copies fail on actual assertions for metadata bindings, login and
reauthentication transaction ordering, capacity serialization, deadline propagation/reset,
cleanup, MFA issuance/rollback and malformed-proof handling. The final user-only binding
case deliberately duplicates a record in a privileged fixture so credential-hash checking
cannot mask a missing authenticated user ID. Removing that binding produces 204 instead
of 401; restoring it passes. The final review found no confirmed implementation defects.

A purpose-only metadata change without a session-hash change is rejected by the schema;
a schema-valid purpose change must also alter the authenticated session hash. Therefore
an isolated purpose-removal mutation staying green is not a protocol bypass. Exact-count
throughput, capacity fairness, limited-MFA revocation, HTTP error classification and nonce
lifetimes remain explicitly deferred for the reasons above. The pre-existing `AGENTS.md`
OpenAPI binary example is outside this phase; `just openapi` uses the actual
`permesi-openapi` binary. The implementation is published on `sandbox`; successful
corrected hosted browser CI remains pending; see [validation evidence](oauth-scenarios.md#validation-and-independent-review).
