# Shared WebAuthn ceremony state

Passkey registration, discoverable passkey login, security-key registration and MFA
verification store pending `webauthn-rs` state in PostgreSQL. Start and finish may run
on different replicas or after a process restart. Replicas share the Vault OPAQUE
server seed and relying-party/origin policy; no pending state depends on local memory,
a sticky session or a local file. Permanent passkeys and security keys remain in their
existing tables.

## Flow and bindings

Start creates a random UUID reference and persists only its SHA-256 hash. The library
state is JSON sealed with XChaCha20-Poly1305, a random 192-bit nonce and a separate
HMAC-derived key domain. Authenticated metadata includes the reference hash, ceremony
purpose, exact validated origin, RP ID, authenticated user and original session hash
when applicable, and PostgreSQL-issued creation/expiry timestamps. Discoverable login
starts anonymously and sends no account-specific credential list. The authenticator's
user handle becomes trusted only after verification against the current stored key.

Finish atomically deletes and commits the pending row before checking its bindings
and cryptographic proof. One concurrent request can obtain the state; invalid proofs,
changed origins/sessions, altered ciphertext/metadata and replay cannot reuse it.
Expired rows fail closed. The reference and plaintext library state are never logged
or stored in plaintext. Shared storage failure does not fall back to process memory.

Passkey login holds current user/credential locks through credential updates and
full or limited MFA-session issuance, committing authority and its audit together.
Disabled accounts and deleted credentials cannot log in. Security-key counter updates
reject stale or decreasing counters atomically; counterless authenticators require
both stored and presented counters to be zero. All MFA completion paths also use [current-session lifecycle guards](mfa-lifecycle.md).
Hardware-key assertions bind the fingerprint of the credential offered at start;
finish rechecks its owner and exact revision under a lock through session issuance.
Deleting or replacing that credential cannot validate an outstanding old proof.

## Policy and operation

`PERMESI_PASSKEYS_CHALLENGE_TTL_SECONDS` defaults to 300 and accepts 1–3600 seconds.
`PERMESI_AUTH_MAX_PENDING_STATES` currently bounds each of the four ceremony purposes
cluster-wide. A PostgreSQL advisory transaction lock coordinates capacity across
replicas; expiry cleanup and insertion occur in the same transaction. The configured
`PERMESI_OPAQUE_EXCHANGE_TIMEOUT_MS` also bounds pool acquisition and ceremony
statements/locks. Shared user/anonymous-IP quotas, separate flow/action budgets and
429/503 classification follow [authentication operations](authentication-operations.md).
These capacity guarantees do not claim unlimited throughput.

RP ID/name, allowed origins, challenge TTL and preview mode are clap configuration,
then revalidated at dispatch. Use `PERMESI_PASSKEYS_RP_ID`, `PERMESI_PASSKEYS_RP_NAME`,
`PERMESI_PASSKEYS_ALLOWED_ORIGINS` and `PERMESI_PASSKEYS_PREVIEW_MODE=true|false`.
Invalid values fail startup. Upgrade deployments that previously used empty RP values,
trailing empty origin entries, silent invalid TTL fallbacks or preview aliases (`1`,
`yes`, uppercase booleans): omit optional RP/origin overrides to use defaults, supply
a valid TTL and use lowercase `true`/`false`. These formerly accepted forms now fail
startup intentionally instead of silently substituting security policy. Defaults derive from the configured frontend/CORS policy.
Apply `db/sql/02_permesi.sql` and its runtime grants before rolling out. In-flight
ceremonies from the previous memory-backed implementation must restart. Rotating the
Vault seed or changing origin/RP policy invalidates outstanding ceremonies; permanent
credential records are unaffected. Mixed old/new replicas require draining old starts.

## Regression checks

`cargo test --locked -p permesi webauthn_exchange --lib` exercises real PostgreSQL and
real RSA authenticator proofs, including restart/replica registration and login,
hardware-key MFA, current session binding, expiry, quota, metadata/key-policy changes,
concurrent single-use consumption, counter races and HTTP session issuance. No proof
verifier is mocked. Existing passkey/origin/preview/body parsing tests remain enabled.
Database schema checks cover the table, lifecycle constraints, cleanup and restricted
runtime privileges. Hosted browser CI uses the normal project fixture/build workflow.

Pending admission, transport trust, generic 429/503 responses and outcome/timing events
follow [authentication operations](authentication-operations.md). Apply its transient-format
upgrade/drain guidance together with this schema.
