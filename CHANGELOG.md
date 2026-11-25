# Changelog

Notable changes to Permesi, newest first. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Permesi has not been
deployed to production, so before 1.0 each release is described as what it
contains, and anything that would affect an existing installation will be
called out under **Breaking** once there is one.

This file records what an operator, integrator or contributor needs to know
about a release. The GitHub release for each tag lists every commit and carries
the signed artifacts.

## [0.6.0] - 2026-11-25

The first release on OpenBao and PostgreSQL 19.

### Breaking

- Admission verification reads approved Ed25519 keys and the minimum accepted
  version from core OpenBao. Initialize the operator-owned authority before
  rollout. Remove the previous `--admission-paserk-url` and `--admission-paserk-ca-path` options. Genesis signs with the explicitly activated Transit version.
- Public health responses contain `status` and `commit`. Genesis has removed
  the request-header echo endpoint.
- OpenBao is provisioned with OpenTofu 1.11 or later (1.13 is tested) instead of
  Terraform. The module moved from `openbao/contrib/terraform` to
  `openbao/contrib/opentofu`, and the `openbao-tf-apply` and `openbao-tf-env`
  recipes are now `openbao-tofu-apply` and `openbao-tofu-env`. Before the first
  apply, create the Transit key `transit/opentofu/keys/permesi-state`, which
  encrypts the state. An existing Terraform state stays in the old directory and
  must be moved, then migrated once through an unencrypted fallback, as the module
  README describes; `just openbao-tofu-apply` does both for the development state.

### Added

- Sandbox CI qualifies its immutable application images against shared and isolated
  Helm OpenBao profiles and records the successful application and chart revisions.

- Secrets, Transit signing and encryption, PKI and dynamic database credentials
  come from OpenBao 2.7, through AppRole, OpenBao Agent or Kubernetes
  authentication. OpenTofu provisioning lives in `openbao/contrib/opentofu`.
- PostgreSQL 19 is the supported and tested server version, in development, CI
  and the test fixtures.
- `just status` reports container, PostgreSQL, OpenBao and service health for
  the development stack in one read-only pass, and `just start` brings the
  stack up with the OIDC routes enabled.
- Services request their own restart one minute before an OpenBao token or
  database lease reaches its max TTL, while the credentials still work, and
  retry a failed renewal with backoff for as long as the lease leaves time to
  drain, so an OpenBao restart or leader change does not stop every replica.
- A TOTP code is accepted once: each credential records the highest time step it
  has accepted, including the one used at enrollment.
- Login, signup, reauthentication and password-change start share one
  per-account budget of password guesses, and password-change start requires a
  recent authentication.
- `--mfa-required` / `PERMESI_MFA_REQUIRED` accepts only `true` or `false`, so a
  misspelled value fails startup instead of leaving MFA optional.
- Tests that run against a real OpenBao: rejected, replayed, revoked and expired
  credentials, policy denials, signature verification across key rotation, an
  unreachable server, recovery after a restart, and a token reaching its max TTL.
- The OpenTofu state and saved plans are encrypted with a data key from an
  OpenBao Transit key, so reading them needs an OpenBao token. The PostgreSQL
  root passwords are write-only and never reach the state or a plan;
  `permesi_database_password_version` and `genesis_database_password_version`
  re-send one after a deliberate reset.
- The provider lock file is committed and installed with `-lockfile=readonly`.
- `just openbao-tofu-test` checks the module offline against mocked providers
  (CI runs the same checks), and `just openbao-tofu-test-live` provisions throwaway OpenBao and PostgreSQL
  containers from zero and checks every engine the services use, including the
  refusals between Permesi and Genesis and a re-apply after the root passwords
  are rotated.
- This changelog.

### Changed

- Sandbox CI runs its builds, OAuth scenarios, browser tests and chart
  qualification alongside the tests instead of after them, so a full run no
  longer waits for each stage in turn. `CI OK` still requires every job, and
  the qualification status is recorded only when `CI OK` passed as well. A chart
  push during an application run now leaves that run unrecorded.
- `just release` and the release workflow refuse to release a commit until
  `permesi/permesi-helm`'s `main` contains the chart revision that sandbox CI
  qualified with it, so a release can no longer pair new images with older
  charts. Merge the chart repository's `sandbox` into its `main` first.
- Genesis and Permesi reject excess public work before database and cryptographic
  operations. Session and OAuth traffic have a separate Permesi budget. Management paths use an independent bucket with the protocol limits, including requests that subsequently fail authentication.
- Genesis database leases receive column-level privileges and connection limits.
  The manager uses the maintenance database during service database saturation.

- The API documentation loads a pinned, integrity-checked Redoc 3 module, and its
  links name both the spec and the operation.
- Database readiness in the development recipes and CI waits for the final
  server over TCP and is bounded, instead of trusting a socket probe that
  answers during initialization.
- The development PostgreSQL data directory is named after the major version
  (`db/data/19`), and `just reset` removes only that directory.
- The persistent development OpenBao uses single-node Raft storage and runs
  unprivileged.

### Fixed

- On a fresh OpenBao installation, the module creates the root issuer before signing the intermediate used by Genesis certificate login and its quota.
- The module set a daily `rotation_period` on both database connections, which
  OpenBao accepts but ignores (scheduled root rotation is a Vault Enterprise
  feature), so the root passwords were never rotated. The setting is gone and the
  docs describe rotating with `bao write -f database/rotate-root/<service>`.
- Every apply replaced the Genesis AppRole and cert-auth rate quotas, briefly
  leaving those login paths without a limit, because OpenBao stores the auth
  path with a trailing slash.
- `just status` reported healthy services as down after the public health
  response was reduced to `status` and `commit`.

- `genesis_tokens_rollover` failed once a token had been issued before that day's
  partition existed, so no partition was created and nothing was expired.
- A stalled admission keyset fetch from Genesis blocked every request that
  verifies a zero token. The fetch is bounded and stale refreshes are spaced out.
- An OpenBao Agent that sent response headers and then stalled held the caller
  open indefinitely.
- Permesi started and reported healthy when the active TOTP key could not be
  loaded; startup now fails instead.
- The platform operator cooldown was treated as absent when the database could
  not be read.
- Genesis ended the process from inside a request handler when its database role
  lost its privileges; it now drains and restarts.
- `/authorize` rejected `response_mode=query` although discovery advertises it.
- Expired MFA bootstrap and challenge sessions were never purged.
- The API documentation page was blank after its floating Redoc URL moved to a
  new major version.

### Security

- Runtime TLS certificates issued by the PKI roles are server-only, so a leaked
  runtime key cannot obtain the service's OpenBao token; only the bootstrap
  certificates authenticate to cert auth.
- OpenBao connects to PostgreSQL over verified TLS unless told otherwise.
- The four WebAuthn finish endpoints (passkey login, passkey registration and the
  MFA security-key register and authenticate) parse the browser credential straight
  into its typed form and share one 32 KiB body cap; the MFA endpoints previously
  accepted up to 2 MB of arbitrary JSON. They now require
  `Content-Type: application/json`, answer an oversized body with 413 after the
  usual session check, and no longer echo parser errors back to the caller.
- A verification link no longer activates a password someone else registered for
  the address. Signup finish sets an `HttpOnly` `permesi_signup` cookie bound to the
  exact registration, and `POST /v1/auth/verify-email` activates the account only
  when the link arrives with it; in any other browser the link answers 409 and stays
  usable. A new signup for a still-unverified address replaces the pending
  registration and retires its links. Users must open the link in the browser they
  signed up with, and API clients must send both requests with credentials.
- The services refuse HTTP redirects from OpenBao on every request, as the
  Kubernetes login already did. A followed redirect would have carried the
  service token, a wrapping token or the AppRole SecretID to the host it named.
  OpenBao standbys forward requests to the active node by default; a cluster with
  request forwarding disabled must be reached through its active node or a load
  balancer.
- Findings from the stabilization review that remain open are listed in
  `TODO.md`.

[0.6.0]: https://github.com/permesi/permesi/releases/tag/0.6.0
