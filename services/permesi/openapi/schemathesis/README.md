# Schemathesis for Permesi

This directory stores Schemathesis configuration for validating the `permesi` HTTP contract against the generated OpenAPI document in `docs/openapi/permesi.json`. The goal is to keep exploratory and property-based API checks versioned with the service-level API docs, next to the existing Bruno collection.

Run the baseline contract checks from the workspace root with:

```sh
just schemathesis-permesi
```

The workspace recipe is version-aware: it uses `--config-file` on older Schemathesis releases and switches to equivalent inline CLI flags on Schemathesis `4.x`, where `--config-file` is no longer available.
By default, it runs `examples,coverage` so tests still run even when OpenAPI examples are sparse.

By default, the command targets `https://api.permesi.localhost` and disables TLS certificate verification to support local mkcert setups behind HAProxy. Override this behavior with:

```sh
export PERMESI_API_BASE_URL="https://api.permesi.localhost"
export PERMESI_API_TLS_VERIFY=true
export PERMESI_SCHEMATHESIS_PHASES="examples,coverage"
export PERMESI_SCHEMATHESIS_MAX_EXAMPLES=25
export PERMESI_SCHEMATHESIS_MODE=positive
export PERMESI_SCHEMATHESIS_HYPOTHESIS_DIR="/tmp/permesi-schemathesis-hypothesis"
export PERMESI_SCHEMATHESIS_EXCLUDE_LOGOUT=true
export PERMESI_SCHEMATHESIS_LOGOUT_COVERAGE=true
```

`PERMESI_SCHEMATHESIS_MODE` defaults to `positive` to reduce noisy negative-case failures in baseline runs. Set it to `all` for deeper fuzzing.
`PERMESI_SCHEMATHESIS_HYPOTHESIS_DIR` defaults to `/tmp/permesi-schemathesis-hypothesis` so local `cargo watch` sessions do not restart on `.hypothesis` writes inside the repository.
`PERMESI_SCHEMATHESIS_EXCLUDE_LOGOUT` defaults to `true` so the main run does not invalidate session cookies during a full API sweep.
`PERMESI_SCHEMATHESIS_LOGOUT_COVERAGE` defaults to `true` and runs a dedicated `/v1/auth/logout` coverage pass after the baseline run.

When you want to exercise authenticated routes, provide optional headers via environment variables before running the recipe:

```sh
export PERMESI_SESSION_COOKIE="your-session-token"
export PERMESI_ADMIN_TOKEN="your-admin-bearer-token"
just schemathesis-permesi
```

For local automation, you can generate a fixture user session (and optionally an admin bearer token) with:

```sh
just schemathesis-permesi-auth
just schemathesis-permesi-auth-admin
```

`just schemathesis-permesi-auth-admin` now generates a unique fixture email when one is not provided, which avoids repeated admin-elevation cooldown (`429`) on the same account. You can still pass an explicit email:

```sh
just schemathesis-permesi-auth-admin "custom@example.com" "owner"
```

To export auth variables without running Schemathesis:

```sh
just --quiet schemathesis-permesi-auth-env > /tmp/permesi-schemathesis.env
source /tmp/permesi-schemathesis.env
just schemathesis-permesi
```

The OpenAPI source can be refreshed at any time with:

```sh
just openapi-permesi
```

Known warnings in authenticated runs are expected until richer test fixtures are added: MFA challenge endpoints can still return `401`, org/project slug routes can return `404` without seeded resources, and some operations still report schema-validation mismatch when generated payloads do not satisfy stricter server-side validation.
