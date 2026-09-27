set shell := ["zsh", "-uc"]

uid := `id -u`
gid := `id -g`
root := justfile_directory()
net := "permesi-net"
subnet := "172.31.20.0/24"

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
