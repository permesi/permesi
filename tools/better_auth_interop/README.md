# Better Auth interoperability fixture

This package proves that the real Better Auth TypeScript library (pinned to
1.7.18) can authenticate an application through Permesi's OIDC provider. It is
additional interoperability coverage alongside the `openidconnect-rs` standard
client, driven entirely by `tools/oauth_scenario` on the same disposable
PostgreSQL/Vault/Permesi/Genesis/Chromium stack. Everything here is test-only:
no production service, frontend or authentication path imports it, and its npm
dependencies are devDependencies of this isolated package.

## Flow

The genericOAuth plugin performs real OIDC discovery against the per-run Permesi
issuer, requests `openid profile email` for a confidential client registered
through the ordinary management API, and is configured for S256 PKCE, nonce and
state validation, `requireIdTokenVerification`, and explicit
`tokenEndpointAuth: client_secret_basic`. The trusted fixture `organization_id`
is supplied only through `authorizationUrlParams`; library-managed state, nonce
and PKCE parameters are reserved and cannot be overridden. The plugin's standard
`signIn.social`/`callback/:id` handlers and session implementation do all token
and UserInfo work; there are no `getToken`/`getUserInfo` adapters, no mocked
provider, no minted ID tokens and no pre-created sessions.

`server.mjs` is a minimal Node 24 HTTPS app with one sign-in page, a protected
success page, and two read-only inspection routes used by scenario assertions:
`/fixture/state` reports storage counts and `/fixture/identity` reports the
authenticated session's linked provider account through the library's own
`getSession`. Local storage is a disposable SQLite file via Node's built-in
`node:sqlite`, created by the library's own migration runner. Permesi's ID
tokens carry no profile claims, so the linked user's verified email can only
come from the back-channel UserInfo request.

The registered cases are `interop.better_auth_login` (one complete browser
sign-in through Permesi login/consent and the real callback, then verified
linked subject and usable local session) and `interop.better_auth_state_reject`
(a fresh unauthenticated cookie jar receives an actual callback whose state is
tampered by exactly one character; rejection, unchanged storage/issuance state
and an unmodified valid control prove the state check decides the outcome).

## Ownership and lifecycle

The scenario runner spawns one fixture process per Better Auth case with a
fresh storage file inside the run's private mode-0700 directory. Ownership is
established before readiness: the runner journals the child's PID and birth
ticks (the Browser ownership pattern) as soon as it spawns, then awaits the
private ready handshake (bound port and callback path) under a readiness
deadline. The disposable SQLite path is the child's single process argument —
a non-secret run-owned path that keeps the private directory visible in
`/proc/<pid>/cmdline` so the ownership recovery guard can safely identify the
child. Cleanup is unconditional kill/reap on failure, cancellation and case
completion. The runner refuses to count coverage when the package or its
pinned dependency is missing or drifted: those cases fail nonzero with a
static setup error.

## Environment inputs

All values come from the run's generated configuration; none are embedded and
none appear on command lines, in logs or in reports. The runner passes
`PERMESI_FIXTURE_ISSUER`, `PERMESI_FIXTURE_CLIENT_ID`,
`PERMESI_FIXTURE_CLIENT_SECRET`, `PERMESI_FIXTURE_ORGANIZATION_ID`,
`PERMESI_FIXTURE_SECRET` (the generated Better Auth session secret) and
`PERMESI_FIXTURE_CERT`/`PERMESI_FIXTURE_KEY` (run-owned TLS material) through
the child environment, and sets `NODE_EXTRA_CA_CERTS` to the run CA so the
back-channel keeps TLS verification enabled against the trusted per-run
issuer. The disposable SQLite path arrives as the process argument described
above, never on a secret-bearing surface.

## Key-set revalidation precondition

Fixture startup revalidates the issuer's cached key set once with
`Cache-Control: no-cache` — the issuer's documented refresh contract, the
same directive the openidconnect fixture uses for its unknown-kid refresh.
The precondition is specific: `/jwks.json` serves a bounded per-replica
cache, and the full suite's `interop.signing_key_rotation` case runs directly
before these cases, so a replica's cache can hold retired key versions for up
to the cache TTL after that rotation. Without the revalidation, the library's
plain JWKS fetch (it exposes no cache-control hook) verifies new ID tokens
against the stale set and the callback fails with `unable_to_get_user_info`.
This is not universal key-rotation coverage: a deployment whose JWKS fetches
never revalidate can still fail verification for up to the issuer's cache TTL
after a rotation, and this fixture does not exercise rotation during an
in-flight sign-in.

## Local invocation

```sh
just oauth-scenario-better-auth            # npm ci + both cases on a disposable stack
just oauth-scenario-better-auth-setup      # install pinned dependencies only
npm run check                              # fixture syntax check
npm audit                                  # dependency audit (test-only tree)
```

The same cases run through `target/debug/permesi-oauth-scenario --case ...` like
any other selection, and are part of `--suite interop`, `--suite full` and the
CI OAuth scenario matrix. `--better-auth-fixture <dir>` points the runner at a
fixture package outside `tools/better_auth_interop`.

## Limits

This fixture exercises one Better Auth release and one provider shape; it is
not a formal OIDC conformance suite and does not cover account linking,
sign-out, refresh or additional plugins. The inspection routes are fixture
surface, not product API. The success-case back-channel evidence is the
committed Permesi issuance row (token exchange, exact scopes) plus the linked
email that only UserInfo can supply; the library's ID-token verification is
proven by the flow completing at all, since a failed verification aborts the
callback. Storage assertions are exact because each case owns a fresh database;
they do not model production retention.
