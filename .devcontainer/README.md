# Permesi DevPod / Dev Containers workspace

A **portable contributor setup** for Permesi based on [DevPod](https://devpod.sh) and
the [Dev Containers](https://containers.dev) spec. It is designed to work the same on
**Linux, macOS, and Linux Atomic** (e.g. fedora-atomic/sway), locally or on a remote
VM, with an almost tooling-free host.

## Design: one self-contained compose stack

The devcontainer is **Compose-based**: a single compose project
(`compose.yaml`) defines the **app** dev container *and* every backing service
(`postgres`, `vault`, `jaeger`, `haproxy`). `devpod up` brings the whole stack up
together, so the environment is fully self-contained — no host-side dependency
management — and the *same* flow runs locally and on a remote VM. `scripts/dev-up`
selects local mode when `.devpod.env` is absent and remote mode when it exists;
`--local` and `--remote` override the selection.

```
        host: devpod (+ podman + podman-compose in local mode)
          │  scripts/dev-up   →   devpod up   (brings up the whole compose project)
          ▼
   ┌──────────────── compose project "permesi" ───────────────────┐
   │  app  (service "app", user vscode)                           │
   │   ├─ rust + mise (just, vault, terraform, node…)             │
   │   └─ genesis:8000  permesi:8001  web:8081  (HAProxy → app:*) │
   │                                                              │
   │  postgres:5432   vault:8200   jaeger:4317   haproxy:443      │
   └──────────────────────────────────────────────────────────────┘
```

Inside the project network services resolve each other by name (`postgres:5432`,
`http://vault:8200`, `jaeger:4317`); HAProxy terminates TLS on `:443` and proxies to
the in-app services as `app:8000/8001/8081`. The app needs **no podman access** — it
only talks to the other services over the network. `just` runs app tasks inside the
container: build/run/test the three binaries and configure Vault
(init/unseal/terraform/certs).

## Files

| File | Purpose |
| --- | --- |
| `compose.yaml` | The whole stack: `app` + `postgres` + `vault` + `jaeger` + `haproxy`. |
| `compose.podman.yaml` | Local override: `userns_mode: keep-id` so the bind-mounted workspace stays editable as `vscode` under rootless podman. |
| `devcontainer.json` | Compose-based devcontainer (`compose.yaml` + rootless podman override). |
| `haproxy/haproxy.deps.cfg` | HAProxy config; backends `app:*` with a `resolvers` section. |
| `postcreate.sh` | One-time provisioning + `just devpod-bootstrap`. |
| `post-start.sh` | Every start: `just devpod-start` (unseal + .envrc + services). |
| `configure-git.sh` | Rebind Git authentication/signing to the current forwarded SSH agent. |
| `setup-zsh.sh` | Fallback zsh config when no dotfiles are applied. |
| `../scripts/dev-up` | Host entrypoint: local without `.devpod.env`, remote with it; explicit flags override. |
| `../scripts/dev-up-remote` | Compatibility entry point for remote mode. |

## Prerequisites (host)

- `devpod` (https://devpod.sh).
- Local mode: `podman` (rootless is fine) and `podman-compose`. The script points
  DevPod's internally named `docker` provider at persistent Podman/podman-compose
  adapters. It also installs a user-level Podman Compose provider drop-in, so later
  lifecycle commands work without a Docker daemon or shell-specific environment
  variables. The adapter supplies the project-list operation that DevPod needs but
  `podman-compose` does not currently implement. Podman's user-level `nodocker`
  marker and Compose warning setting keep compatibility banners out of that JSON.
- Linux local mode only: ability to bind `:443` under rootless podman — `scripts/dev-up --local` lowers
  `net.ipv4.ip_unprivileged_port_start` to `443` via `sudo` (one prompt). Persist with
  `echo 'net.ipv4.ip_unprivileged_port_start=443' | sudo tee /etc/sysctl.d/99-permesi.conf`.
  On macOS, the Podman machine handles this in the VM. Skip with
  `PERMESI_DEVUP_SKIP_PORTCHECK=1` if you've already set it.

`DEVPOD` / `DEVPOD_WORKSPACE_ID` are set on the `app` service in `compose.yaml`
(compose containers don't get DevPod's automatic injection), so the legacy-recipe
guard and tooling still detect the workspace.

Optional env forwarded by `scripts/dev-up`:
- `GIT_USER_NAME`, `GIT_USER_EMAIL`, `GIT_SIGNING_KEY`, `GIT_SSH_SIGNING_PROGRAM`
- `GITHUB_TOKEN` (falls back to `gh auth token`)
- `DEVPOD_DOTFILES` (chezmoi dotfiles repo; set `none` to skip)
- `PERMESI_DEVPOD_NO_AUTOSTART=1` (bootstrap but don't auto-start the services)

Chezmoi defaults to the SSH URL for the private `nbari/dotfiles` repository, which
provides Atuin and Herdr configuration and installs integrations for the Mise-managed
AI agents. The forwarded SSH agent authenticates that clone. Chezmoi's post-apply
hook reruns `configure-git.sh`, because the host-oriented SSH agent path and signing
helper are not valid inside DevPod. Agent state and Atuin history live in named
volumes.

`scripts/dev-ssh` connects as the workspace's `vscode` user so Git sees the
bind-mounted repository under its owning account and the forwarded SSH signing
agent remains available. Set `PERMESI_DEVPOD_USER` only when a custom image uses
a different non-root workspace user.

## Quickstart — one command

```bash
git clone https://github.com/permesi/permesi.git
cd permesi
scripts/dev-up
#   devpod up brings up app + postgres/vault/jaeger/haproxy, then:
#     postCreate → just devpod-bootstrap (DB verify, Vault init/unseal/terraform,
#                  mkcert frontend cert + Vault PKI backend certs, .envrc)
#     postStart  → just devpod-start (unseal Vault, refresh .envrc, start services)
#   then reloads HAProxy so it picks up the freshly issued certs and the app backend

# With no .devpod.env this is the local workspace:
devpod ssh permesi
tmux attach -t permesi      # genesis / permesi / web (detach with your tmux prefix + d)
# Already inside a host tmux? Avoid nesting and just tail logs instead:
just devpod-logs            # or: just devpod-logs genesis|permesi|web
```

To use a remote provider, copy `.devpod.env.example` to `.devpod.env`, edit it,
and run `scripts/dev-up` again. Its presence selects remote mode. Set
`DEVPOD_REMOTE_PROVIDER` in that file to use a provider other than `coyote`, then
enter the default remote workspace with `devpod ssh permesi-remote`. Keep the remote
workspace name distinct from `permesi`, which is reserved for local mode. If the named
provider does not exist, the script creates an SSH provider automatically from the
configured remote host, user, and port. It requires Podman and `podman-compose` on
that remote and does not require a Docker-compatible socket. DevPod 0.6.15 looks up
one command by the legacy name `docker-compose`; the setup installs a managed shim
at that name which executes `podman-compose` directly.

Remote mode does not bind privileged port 443 on the VM. Its Podman services bind
only to remote loopback, HAProxy uses remote `127.0.0.1:8443`, and `scripts/dev-up`
opens a persistent SSH tunnel from local `127.0.0.1:443`. Consequently the browser
still uses `https://permesi.localhost` while the remote development services are not
published on the VM's network interfaces. The script also imports only the remote
workspace's public development CA into the local system trust store; the CA private
key stays remote. Set `DEVPOD_REMOTE_LOCAL_HTTPS_PORT=8443` when the local host cannot
bind port 443, `DEVPOD_REMOTE_TUNNEL=0` to manage the tunnel yourself, or
`PERMESI_TRUST_CA=0` to skip CA installation.
Only one workspace can own local port 443. Run `devpod stop permesi` before using
the default remote tunnel when the local workspace is active, or choose another
local tunnel port.

## Local mode

Without `.devpod.env`, local mode is automatic. Use `--local` to force the local
provider even when the remote configuration file exists:

```bash
scripts/dev-up --local
devpod ssh permesi          # then: tmux attach -t permesi
```

Browse: https://permesi.localhost, https://api.permesi.localhost/health,
https://genesis.permesi.localhost/health, Jaeger UI http://localhost:16686.

## App tasks (inside the container)

```bash
just devpod-dev          # (re)start genesis/permesi/web in tmux
just devpod-bootstrap    # re-run the one-time Vault/DB/TLS setup (idempotent)
just devpod-start        # unseal + refresh .envrc + (re)start services
just fmt / clippy / test # the usual workspace checks
```

## Trusting the dev CA on the host

HAProxy serves the frontend with an **mkcert** cert (the Vault PKI roles only allow the
`api.`/`genesis.` service names, not `permesi.localhost`/wildcards), so the host must
trust the issuing CA for `https://permesi.localhost` to be valid in a browser.

**Default — the host owns the CA (automatic, survives recreates):**

Local mode does this for you (disable with `PERMESI_TRUST_CA=0`):

```bash
scripts/dev-up --local                      # trusts the CA on the host by default
PERMESI_TRUST_CA=0 scripts/dev-up --local   # opt out (e.g. CI / non-interactive)
scripts/trust-ca                    # run the trust step on its own
```

It installs `mkcert` into `~/.local/bin`, runs `mkcert -install` (adds the CA to the
system trust store + Firefox/Chromium NSS via `certutil`; needs `sudo` only the first
time), and shares the host CAROOT into `certs/mkcert-caroot/` (gitignored). The
container then issues the frontend cert from that host-trusted CA, so the certs are
valid with no manual import and no re-trust after `--recreate`. The dev CA private key
stays local (gitignored), exactly like mkcert's normal `~/.local/share/mkcert` storage.

**Manual alternative — import the exported CA once:**

```bash
just devpod-trust-ca     # prints steps; CA is at certs/mkcert-root.pem
# /etc/hosts on the HOST:
127.0.0.1 permesi.localhost api.permesi.localhost genesis.permesi.localhost
```

Remote mode performs the equivalent public-CA trust automatically after bootstrap.
It does not copy the host mkcert private key to the VM. If a remote workspace is
deleted and rebuilt with a new CA, the next `scripts/dev-up` replaces that
workspace's named trust anchor. Restart browsers opened before the trust update if
necessary.

## Lifecycle & resetting

```bash
devpod stop permesi-remote      # stop the default remote workspace
scripts/dev-up                  # remote when .devpod.env exists
devpod stop permesi             # stop the local workspace
scripts/dev-up --local          # explicitly start local mode
devpod delete permesi --force   # remove the local workspace (containers + volumes)
```

- Re-run `just devpod-bootstrap` any time (idempotent).
- Wipe Vault (host): `just vault-reset` removes the `*_vault-data` volume plus
  `vault/keys.json` and Terraform state; then `scripts/dev-up --local --recreate` re-bootstraps.
- Reload DB schema after changing `db/sql/*`: remove the `*_pgdata` volume and recreate
  (`devpod delete permesi --force` then `scripts/dev-up --local`); the schema is applied on the
  first Postgres init.

## Notes & caveats

- The app image is `mcr.microsoft.com/devcontainers/rust:trixie` + Dev Container
  features (Neovim). The first `scripts/dev-up` pulls images and can take a while; the
  toolchain and cargo/target are cached in named volumes.
- HAProxy starts before the in-app services and their certs exist; its `resolvers`
  section re-resolves `app` and the selected `scripts/dev-up` mode reloads HAProxy once after bootstrap.
- Local rootless Podman uses `userns_mode: keep-id` (via `compose.podman.yaml`) so the
  bind-mounted workspace maps the container `vscode` to your host user and stays
  editable. Remote mode also uses rootless Podman.
- Development only: Postgres uses trust auth and Vault is bootstrapped with locally
  generated keys (`vault/keys.json`). Never reuse outside a dev machine.
- The legacy host-podman flow (`just start`, `.justfiles/infra.just` / `vault.just`)
  remains available and unchanged for those who prefer running infra natively on the
  host.
