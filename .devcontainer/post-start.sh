#!/usr/bin/env bash
set -uo pipefail

# Runs on every container start (DevPod postStartCommand). Brings the dev stack to
# a ready state so `scripts/dev-up` leaves nothing to do by hand: it waits for the
# compose siblings, unseals Vault (which re-seals across restarts), refreshes
# .envrc, and starts genesis/permesi/web in a tmux session.
#
# It is best-effort: a transient hiccup must not make `devpod up` fail and leave an
# unusable workspace, so problems are reported but the start still succeeds.

export PATH="$HOME/.local/bin:$HOME/.local/share/mise/shims:$PATH"
cd /workspaces/permesi 2>/dev/null || true

# Apply forwarded git identity + SSH signing (best-effort; needs GIT_* in .devpod.env).
if command -v just >/dev/null 2>&1; then
    just devpod-git-config || echo "post-start: git identity setup skipped (continuing)." >&2
fi

if command -v just >/dev/null 2>&1 && just devpod-start; then
    echo
    echo "✓ Workspace ready. Services run in tmux session 'permesi'."
    echo "  Watch:  devpod ssh permesi  then  tmux attach -t permesi   (detach: <prefix> d)"
    echo "  Logs:   just devpod-logs [genesis|permesi|web]"
    echo "  Browse: https://permesi.localhost   (run 'just devpod-trust-ca' once)"
else
    echo "post-start: could not fully ready the stack (continuing)." >&2
    echo "  Inspect/repair inside the workspace with:" >&2
    echo "    just devpod-bootstrap   # re-run one-time setup" >&2
    echo "    just devpod-start       # unseal + refresh .envrc + start services" >&2
fi

exit 0
