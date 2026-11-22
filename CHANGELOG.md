# Changelog

Notable changes to Permesi, newest first. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html); until 1.0, a minor
release (0.x.0) may break compatibility and says so under **Breaking**.

This file records what an operator, integrator or contributor needs to know
about a release. The GitHub release for each tag lists every commit and carries
the signed artifacts. Releases before 0.5.0 are described only there.

## [0.6.0] - 2026-11-22

Permesi now runs on OpenBao and PostgreSQL 19. Nothing from the Vault setup is
kept as an alias, so read [Upgrading from 0.5](SETUP.md#8-upgrading-from-05)
before moving an existing environment. 0.5.2 is the last release that runs
against HashiCorp Vault and PostgreSQL 18.

### Breaking

- HashiCorp Vault is replaced by OpenBao 2.7. Every `--vault-*` flag is now
  `--openbao-*`, and every `PERMESI_VAULT_*` and `GENESIS_VAULT_*` variable is
  now `PERMESI_OPENBAO_*` and `GENESIS_OPENBAO_*`. The old names are not read.
- The platform operator endpoints take `openbao_token` instead of `vault_token`,
  and the infrastructure status response reports `openbao` instead of `vault`.
- The database root roles are `openbao_permesi` and `openbao_genesis` (formerly
  `vault_permesi` and `vault_genesis`).
- PostgreSQL 19 is the supported and tested server version.
- Vault data is not migrated. A newly provisioned OpenBao has a new OPAQUE server
  seed, recovery pepper and Transit keys, so existing OPAQUE registrations and
  TOTP enrollments do not work against it.
- `PERMESI_MFA_REQUIRED` accepts only `true` or `false`. Other spellings, which
  used to be read as "not required", now fail startup. It is also available as
  `--mfa-required`.
- The Terraform module moved to `openbao/contrib/terraform`. It no longer manages
  an audit device (OpenBao only accepts one declared in the server
  configuration), and `database_sslmode` defaults to `verify-full`.
- Password-change start (`/v1/auth/opaque/password/start`) requires a recent
  authentication, as its finish step already did.
- Development recipes are renamed from `just vault-*` to `just openbao-*`, and the
  `bao` CLI replaces `vault` on the host.

### Added

- `just status` reports container, PostgreSQL, OpenBao and service health for
  the development stack in one read-only pass.
- The development environment enables the OIDC routes, so discovery and JWKS
  work after `just start`.
- A TOTP code is accepted once. Each credential records the highest time step it
  has accepted, including the one used at enrollment.
- Tests that run against a real OpenBao: rejected, replayed, revoked and expired
  credentials, policy denials, signature verification across key rotation, an
  unreachable server, recovery after a restart, and a token reaching its max TTL.
- An upgrade guide in `SETUP.md` and this changelog.

### Changed

- Services request their own restart one minute before an OpenBao token or
  database lease reaches its max TTL, while the credentials still work. They
  used to notice only after the lease had expired.
- A failed lease renewal is retried with backoff for as long as the lease still
  leaves time to drain, so an OpenBao restart or leader change no longer stops
  every replica that happened to renew during it.
- Login, signup, reauthentication and password-change start share one
  per-account budget of password guesses.
- Runtime TLS certificates issued by the PKI roles are server-only; only the
  bootstrap certificates can authenticate to OpenBao's cert auth.
- The persistent development OpenBao uses single-node Raft storage and runs
  unprivileged.
- The development PostgreSQL data directory is named after the major version
  (`db/data/19`), and `just reset` removes only that directory.
- The API documentation loads a pinned, integrity-checked Redoc 3 module, with
  links that name the spec and the operation.
- Database readiness in the development recipes and CI waits for the final
  server over TCP and is bounded, instead of trusting a socket probe that
  answers during initialization.

### Fixed

- `genesis_tokens_rollover` failed on every run once a token had been issued
  before that day's partition existed, so no partition was created and nothing
  was ever expired. It now moves those rows into the new partition and applies
  retention to the default partition.
- The renewal tasks polled OpenBao without pause during the last second of a
  lease.
- A stalled admission keyset fetch from Genesis blocked every request that
  verifies a zero token. The fetch is bounded and stale refreshes are spaced out.
- An OpenBao Agent that sent response headers and then stalled held the caller
  open indefinitely.
- Permesi started and reported healthy when the active TOTP key could not be
  loaded, leaving that replica unable to enroll or verify TOTP until restarted.
  Startup now fails instead.
- The platform operator cooldown was treated as absent when the database could
  not be read.
- Genesis ended the process from inside a request handler when its database role
  lost its privileges; it now drains and restarts.
- `/authorize` rejected `response_mode=query` although discovery advertises it.
- Expired MFA bootstrap and challenge sessions were never purged.
- The API documentation page was blank after its floating Redoc URL moved to a
  new major version.
- The documented systemd setup for the OpenBao Agent could not start its socket.

### Security

- Closes a way to replay a TOTP code, and three ways to obtain password guesses
  outside the login rate limit, one of them unlimited for a stolen session.
- Closes a path by which a leaked runtime TLS key could obtain the service's
  OpenBao token.
- OpenBao connects to PostgreSQL over verified TLS unless told otherwise.
- The MFA requirement can no longer be disabled by a misspelled setting.
- Findings from the stabilization review that remain open are listed in
  `TODO.md`.

## [0.5.2] - 2026-11-21

### Changed

- Time handling uses `jiff` instead of `chrono`.
- `opaque-ke` moves from a pinned upstream revision to the published
  `5.0.0-pre.0` release, on the backend, in the browser and in the scenario
  runner.
- Service images are built from the binaries CI built and tested, instead of
  compiling again.
- Release tools and container base images are pinned.
- Local builds check that the installed Rust matches current stable.

### Added

- `AI_POLICY.md`.

## [0.5.1] - 2026-11-13

### Changed

- Dependencies updated, with the lint fixes the newer Rust required.
- Browser tests pass their values as arguments instead of building code strings.

### Fixed

- A build failure on the release image's Rust toolchain.

## [0.5.0] - 2026-11-09

### Added

- Last login time and organization owners in the web console.

### Changed

- The web console uses Lucide icons instead of Material icons.

[0.6.0]: https://github.com/permesi/permesi/compare/0.5.2...0.6.0
[0.5.2]: https://github.com/permesi/permesi/compare/0.5.1...0.5.2
[0.5.1]: https://github.com/permesi/permesi/compare/0.5.0...0.5.1
[0.5.0]: https://github.com/permesi/permesi/compare/0.4.10...0.5.0
