#!/usr/bin/env sh
set -eu

system_ssh=/usr/bin/ssh

# DevPod creates a forwarded agent socket for each connection. A Chezmoi-managed
# IdentityAgent path can therefore be stale even though SSH_AUTH_SOCK is valid.
if [ "${SSH_AUTH_SOCK:-}" != "" ] && [ -S "$SSH_AUTH_SOCK" ]; then
  exec "$system_ssh" -o IdentityAgent=SSH_AUTH_SOCK "$@"
fi

exec "$system_ssh" "$@"
