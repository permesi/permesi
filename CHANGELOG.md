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

## [Unreleased]

### Changed

- The release qualifies the image digests it has just built with both containment
  profiles before it signs them or creates the tag, the GitHub release or the
  version tags. Until now only the sandbox candidates of the same commit ran the
  full suite, and images were signed as soon as they were pushed. A failed
  qualification leaves only unsigned images tagged `:sha-<commit>`; fix the cause
  and dispatch the release again. The chart bump is dispatched only if
  `permesi-helm`'s `main` is still the chart revision the images were qualified
  with. This adds about 20 minutes to a release.

### Fixed

- Permesi accepts an admission token whose issue time is up to five seconds ahead
  of its own clock (`--admission-iat-leeway-seconds`,
  `PERMESI_ADMISSION_IAT_LEEWAY_SECONDS`, 0 to 30). A Genesis host whose clock ran
  slightly ahead previously had every fresh token rejected. The allowance applies
  to the issue time only; expiry and the lifetime bounds are unchanged.
- Genesis no longer answers `500` to a token request whose country header is not a
  two-character code. The header is stored for audit only; a value of any other
  shape is now ignored, as an unparseable client address already was, and a
  stored `User-Agent` is cut to 512 characters.

### Security

- The email outbox erases a message's payload, which holds the verification link,
  as soon as the message is delivered or given up on. Delivered rows previously
  kept a usable link for as long as the row existed.
- Startup diagnostics no longer carry OpenBao or database credentials. The
  startup configuration block shows `openbao_role_id_set` in place of the AppRole
  RoleID, shows the OpenBao address without userinfo or query string, and shows
  the database DSN without its userinfo and with every query parameter that is
  not a known setting replaced by one `REDACTED` marker. A value that is not an
  `http(s)` address, an Agent socket path or a `postgres://` URL is not printed at
  all (an address appears as `<address not shown>`, a DSN as `invalid-dsn`), nor
  is one whose host is not a host name or IP address or that holds anything but
  printable ASCII inside it, and a path that holds anything but plain path
  characters is left out. A database name that is not one plain segment shows as
  `REDACTED`, and `sslmode`, `port` and `connect_timeout` are shown only with a
  value they can take. The
  AppRole login and token unwrap no longer record the address or RoleID on a
  span, a login error no longer names the full request URL, and formatting the
  startup arguments, the OpenBao options or the transport with `Debug` prints
  none of them. Anything that read `openbao_role_id` from the startup log has to
  stop doing so.
- `permesi --help` and `genesis --help` no longer print the current values of
  the DSN, the OpenBao address, the RoleID, the SecretID and the wrapped token
  when those are set in the environment.
- Both services refuse at startup an `http(s)` OpenBao address whose host is not
  a host name or IP address, or that has whitespace or a control character inside
  it, instead of connecting to whatever the URL parser made of it. Whitespace
  around the address is still ignored. The error for a rejected address no longer
  repeats its scheme, and an Agent socket path with text appended to it is no
  longer shown in request spans or connection errors.
- The manual OpenBao recipe in `SETUP.md` now writes the policy files the OpenTofu
  module applies instead of repeating them. The copies had drifted: they let a
  service token renew any lease, let Genesis sign without a pinned key version,
  left Permesi unable to read the admission authority or use its OIDC signing
  key, set the Genesis signing key to rotate by itself, and gave the Agent
  certificate roles policies that do not exist. If you configured OpenBao by hand
  from the earlier text, apply section D and E again, remove
  `auto_rotate_period` from `transit/genesis/keys/genesis-signing`, and check the
  PKI and AppRole settings listed in the new section F. The live
  provisioning test now asserts that a service can renew its own lease and
  nothing else.

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
