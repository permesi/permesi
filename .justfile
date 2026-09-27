set shell := ["zsh", "-uc"]

uid := `id -u`
gid := `id -g`
root := justfile_directory()
# Dedicated podman network for every permesi dev container, so other projects on the
# same host never share its bridge or address range. Override the subnet when it
# overlaps a host route (172.31.16.0/20 is an AWS default-VPC subnet).
net := env_var_or_default("PERMESI_NET", "permesi-net")
subnet := env_var_or_default("PERMESI_SUBNET", "172.31.20.0/24")

# Unique container names and a shared label keep permesi's containers apart from
# other projects' (`podman run --replace --name vault` would delete a foreign one).
vault_ctr := "permesi-vault"
jaeger_ctr := "permesi-jaeger"
stack_label := "io.permesi.stack=dev"
# Herdr names workspaces after their directory, so the dev session gets a label that
# cannot be mistaken for the workspace you already have open in this checkout.
herdr_label := "permesi-dev"

# Where published container ports listen, and the browser-facing HTTPS port.
# PERMESI_BIND_ADDR defaults to loopback because Postgres uses trust auth and
# vault/keys.json holds the Vault root token; 0.0.0.0 restores LAN access. Host clients
# hard-code loopback (VAULT_ADDR, the DSNs, terraform), so no other address works.
# PERMESI_HTTPS_PORT is the HAProxy port the browser uses; every browser-facing URL
# carries it when it is not 443, because CORS and WebAuthn compare origins including
# the port. Over an SSH forward, use the same number on both ends.
# Precedence: the environment, then the values `just dev-envrc` baked into .envrc
# (so `just restart`, `just web` or `just genesis-token` keep the running stack's
# port without re-exporting it), then the defaults.
_envrc_bind_addr := `sed -n 's/^export PERMESI_BIND_ADDR="\${PERMESI_BIND_ADDR:-\(.*\)}"$/\1/p' .envrc 2>/dev/null || true`
_envrc_https_port := `sed -n 's/^export PERMESI_HTTPS_PORT="\${PERMESI_HTTPS_PORT:-\(.*\)}"$/\1/p' .envrc 2>/dev/null || true`
# A baked value is used only when it looks valid: `just --dry-run` leaves backticks
# unevaluated, and a hand-edited .envrc should not break every recipe.
bind_addr := env_var_or_default("PERMESI_BIND_ADDR", if _envrc_bind_addr =~ '^[0-9.]+$' { _envrc_bind_addr } else { "127.0.0.1" })
https_port := env_var_or_default("PERMESI_HTTPS_PORT", if _envrc_https_port =~ '^[0-9]+$' { _envrc_https_port } else { "443" })
https_suffix := if https_port == "443" { "" } else { ":" + https_port }
publish_ip := if bind_addr == "0.0.0.0" { "" } else { bind_addr + ":" }

# Validated eagerly so a bad override fails before any recipe runs.
_knobs_ok := if net !~ '^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$' { error("PERMESI_NET must be a podman network name (letters, digits, '.', '_', '-')") } else if subnet !~ '^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])/([89]|[12][0-9]|30)$' { error("PERMESI_SUBNET must be an IPv4 CIDR with a /8 to /30 prefix, such as 172.31.20.0/24") } else if bind_addr !~ '^(127\.0\.0\.1|0\.0\.0\.0)$' { error("PERMESI_BIND_ADDR must be 127.0.0.1 or 0.0.0.0") } else if https_port !~ '^([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$' { error("PERMESI_HTTPS_PORT must be a TCP port (1-65535)") } else if https_port =~ '^(4317|4318|5432|8000|8001|8081|8200|16686)$' { error("PERMESI_HTTPS_PORT collides with a dev service port") } else { "" }

# Local infra images: pinned and fully qualified, so rootless podman never has to
# resolve a short name and every developer runs the same versions.
vault_image := "docker.io/hashicorp/vault:2.0"
jaeger_image := "docker.io/jaegertracing/jaeger:2.19.0"
haproxy_image := "docker.io/library/haproxy:3.4"

branch := if `git rev-parse --abbrev-ref HEAD` == "main" { "latest" } else { `git rev-parse --abbrev-ref HEAD` }

[default]
_default:
  @just default

import '.justfiles/core.just'
import '.justfiles/web.just'
import '.justfiles/services.just'
import '.justfiles/docs_openapi.just'
import '.justfiles/schemathesis.just'
import '.justfiles/helpers.just'
import '.justfiles/vault.just'
import '.justfiles/infra.just'
