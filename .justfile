set shell := ["zsh", "-uc"]

uid := `id -u`
gid := `id -g`
root := justfile_directory()
net := "permesi-net"
subnet := "172.31.20.0/24"

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
