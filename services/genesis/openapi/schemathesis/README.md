# Schemathesis for Genesis

This directory stores Schemathesis configuration for validating the `genesis` HTTP contract against the generated OpenAPI document in `docs/openapi/genesis.json`. The goal is to keep contract checks versioned with service-level API docs, next to the existing Bruno collection.

Run baseline checks from the workspace root with:

```sh
just schemathesis-genesis
```

The workspace recipe is version-aware: it uses `--config-file` on older Schemathesis releases and equivalent inline CLI flags on Schemathesis `4.x`, where `--config-file` is no longer available. By default, it runs `examples,coverage`.

By default, the command targets `https://genesis.permesi.localhost` and disables TLS certificate verification to support local mkcert setups behind HAProxy. Override with:

```sh
export GENESIS_API_BASE_URL="https://genesis.permesi.localhost"
export GENESIS_API_TLS_VERIFY=true
export GENESIS_SCHEMATHESIS_PHASES="examples,coverage"
export GENESIS_SCHEMATHESIS_MAX_EXAMPLES=25
export GENESIS_SCHEMATHESIS_MODE=positive
export GENESIS_SCHEMATHESIS_HYPOTHESIS_DIR="/tmp/genesis-schemathesis-hypothesis"
```

`GENESIS_SCHEMATHESIS_MODE` defaults to `positive` to reduce noisy negative-case failures in baseline runs. Set it to `all` for deeper fuzzing.
`GENESIS_SCHEMATHESIS_HYPOTHESIS_DIR` defaults to `/tmp/genesis-schemathesis-hypothesis` so local `cargo watch` sessions do not restart on `.hypothesis` writes inside the repository.

Refresh the OpenAPI source at any time with:

```sh
just openapi-genesis
```
