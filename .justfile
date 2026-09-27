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

# Validated eagerly so a bad override fails before any recipe runs.
_knobs_ok := if subnet !~ '^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$' { error("PERMESI_SUBNET must be an IPv4 CIDR such as 172.31.20.0/24") } else { "" }

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
