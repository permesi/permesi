#!/usr/bin/env sh
set -eu

git_identity_file="/run/secrets/git-identity.env"
if [ -r "$git_identity_file" ]; then
  # shellcheck disable=SC1090
  . "$git_identity_file"
fi

if [ "${GIT_USER_NAME:-}" != "" ]; then
  git config --global --replace-all user.name "$GIT_USER_NAME"
fi

if [ "${GIT_USER_EMAIL:-}" != "" ]; then
  git config --global --replace-all user.email "$GIT_USER_EMAIL"
fi

script_dir="$(unset CDPATH; cd -- "$(dirname -- "$0")" && pwd)"
repository_dir="$(dirname -- "$script_dir")"
git_ssh_command="ssh -o IdentityAgent=SSH_AUTH_SOCK"

# Keep every SSH consumer on the connection-scoped DevPod agent. Chezmoi's
# host-oriented SSH config may otherwise point at a socket that does not exist
# inside the container. Git also gets an explicit override below.
ssh_wrapper="$script_dir/ssh-wrapper.sh"
if [ -f "$ssh_wrapper" ]; then
  install -Dm 0755 "$ssh_wrapper" "$HOME/.local/bin/ssh"
fi

git config --global --replace-all core.sshCommand "$git_ssh_command"
if git -C "$repository_dir" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  git -C "$repository_dir" config --local --replace-all core.sshCommand "$git_ssh_command"
fi

signing_key="${GIT_SIGNING_KEY:-}"
if [ "$signing_key" = "" ]; then
  signing_key="$(git config --global --get user.signingkey 2>/dev/null || true)"
fi

if [ "$signing_key" != "" ]; then
  ssh_signing_program="$(command -v ssh-keygen || printf '%s' ssh-keygen)"
  git config --global --replace-all gpg.format ssh
  git config --global --replace-all gpg.ssh.program "$ssh_signing_program"
  git config --global --replace-all user.signingkey "$signing_key"
  git config --global --replace-all commit.gpgsign true
  git config --global --replace-all tag.gpgSign true

  # DevPod or Chezmoi may replace the global signing program with a helper that
  # cannot use the forwarded agent. Keep a repository-local ssh-keygen override.
  if git -C "$repository_dir" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    git -C "$repository_dir" config --local --replace-all gpg.ssh.program "$ssh_signing_program"
  fi

  allowed_signers="$HOME/.config/git/allowed_signers"
  mkdir -p "$(dirname "$allowed_signers")"
  printf '%s %s\n' "${GIT_USER_EMAIL:-$(git config --global --get user.email 2>/dev/null || printf '%s' '*')}" "$signing_key" >"$allowed_signers"
  git config --global --replace-all gpg.ssh.allowedSignersFile "$allowed_signers"
fi
