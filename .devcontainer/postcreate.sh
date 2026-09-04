#!/usr/bin/env bash
set -euo pipefail

# Provision the Permesi workspace container: system deps, mise-managed toolchain,
# dotfiles, and shell. Backing services (postgres/vault/jaeger/haproxy) run as
# compose siblings and are bootstrapped separately via `just devpod-bootstrap`.

export PATH="$HOME/.local/bin:$HOME/.local/share/mise/shims:$PATH"

# 1. Create and take ownership of user dirs. The mise/cargo volume mounts cause
#    podman to create their parents (~/.local, ~/.cache) as root, so vscode cannot
#    write into them until we fix ownership up front.
sudo mkdir -p \
    "$HOME/.local/bin" "$HOME/.local/share" "$HOME/.cache" "$HOME/.config"
sudo chown -R "$(id -u):$(id -g)" \
    "$HOME/.local" "$HOME/.cache" "$HOME/.config" \
    /home/vscode/.cargo /home/vscode/.rustup 2>/dev/null || true

# 2. System dependencies.
sudo apt-get update
sudo apt-get install -y \
    build-essential ca-certificates curl delta dnsutils fd-find fzf git gnupg iputils-ping jq \
    libbz2-dev libcap2-bin libffi-dev liblzma-dev libnss3-tools libreadline-dev libsqlite3-dev \
    libssl-dev luarocks make netcat-openbsd openssh-client pkg-config rsync \
    tmux unzip wget xz-utils yq zip zlib1g-dev

sudo setcap cap_net_raw+ep /usr/bin/ping
sudo chsh -s /usr/bin/zsh vscode

# 3b. mkcert (frontend HAProxy cert) is provided by mise (see mise.toml) — installed
#     with the rest of the toolchain in step 4 below.

# 3. Rust components (image ships rustup; ensure tooling is present).
rustup update stable
rustup default stable
rustup component add rustfmt clippy rust-analyzer
rustup target add wasm32-unknown-unknown

# 3c. Cargo dev tools (cargo-watch for `just genesis`/`just permesi`; cargo-edit for
#     `cargo upgrade`/`cargo add`) are provided by mise via the cargo backend with
#     binstall enabled (see mise.toml) — installed in step 4 below.

# 4. mise: installs just, vault, terraform, node, pgcli, and the rest from mise.toml.
if ! command -v mise >/dev/null 2>&1; then
    curl -fsSL https://mise.run | sh
fi
mise trust --yes
mise install
mise reshim || true

sudo tee /etc/profile.d/mise.sh >/dev/null <<'EOF'
export PATH="$HOME/.local/bin:$HOME/.local/share/mise/shims:$PATH"
EOF
grep -qxF 'export PATH="$HOME/.local/bin:$HOME/.local/share/mise/shims:$PATH"' ~/.zshenv 2>/dev/null ||
    echo 'export PATH="$HOME/.local/bin:$HOME/.local/share/mise/shims:$PATH"' >>~/.zshenv

# Note: the UTF-8 locale (LANG/LC_ALL) is set via devcontainer.json containerEnv
# (global, inherited by ssh/tmux) and, for portability across other devpods, by the
# chezmoi dotfiles. No per-shell locale shim is needed here.

mise run setup-postgres-client
mise run setup-valkey
mise run setup-tig

# 5. Dotfiles (chezmoi), matching the bloque workflow. Opt-in via DEVPOD_DOTFILES.
dotfiles_repo="${DEVPOD_DOTFILES:-https://github.com/nbari/dotfiles-devpod.git}"
if [ "$dotfiles_repo" != "" ]; then
    if ! command -v chezmoi >/dev/null 2>&1; then
        sh -c "$(curl -fsSL get.chezmoi.io)" -- -b ~/.local/bin
    fi
    chezmoi init --apply --force "$dotfiles_repo" ||
        echo "chezmoi dotfiles step failed (continuing)"
fi

# 6. Base zsh config (only if dotfiles did not already provide one).
if [ ! -f "$HOME/.zshrc" ]; then
    bash .devcontainer/setup-zsh.sh
fi

# 7. One-time bootstrap of the dev stack: verify the DB schema, initialize/unseal
#    Vault, apply the Vault Terraform config, issue TLS material, and write .envrc.
#    Idempotent and safe to re-run. The compose siblings are already up at this
#    point, so `scripts/dev-up` leaves a fully provisioned environment; the
#    services themselves are started by post-start.sh on every container start.
export PATH="$HOME/.local/bin:$HOME/.local/share/mise/shims:$PATH"
just devpod-bootstrap

echo "✓ postCreate complete: workspace provisioned and Vault bootstrapped."
