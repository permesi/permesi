web: web-clean
  #!/usr/bin/env zsh
  set -euo pipefail
  mkdir -p {{root}}/.tmp/xdg-cache
  cd {{root}}/apps/web
  npm run css:watch &
  css_pid=$!
  cleanup() {
    if kill -0 "$css_pid" >/dev/null 2>&1; then
      kill "$css_pid" >/dev/null 2>&1 || true
    fi
  }
  trap cleanup EXIT INT TERM
  : "${PERMESI_API_BASE_URL:=https://api.permesi.localhost}"
  : "${PERMESI_TOKEN_BASE_URL:=https://genesis.permesi.localhost}"
  : "${PERMESI_CLIENT_ID:=00000000-0000-0000-0000-000000000000}"
  XDG_CACHE_HOME="{{root}}/.tmp/xdg-cache" \
    PERMESI_API_BASE_URL="${PERMESI_API_BASE_URL}" \
    PERMESI_TOKEN_BASE_URL="${PERMESI_TOKEN_BASE_URL}" \
    PERMESI_CLIENT_ID="${PERMESI_CLIENT_ID}" \
  env -u NO_COLOR trunk serve --verbose --address 0.0.0.0 --port 8081 --dist dist-dev

web-build: web-node-setup
  #!/usr/bin/env zsh
  set -euo pipefail
  if ! command -v trunk >/dev/null 2>&1; then
    just web-setup
  fi
  mkdir -p {{root}}/.tmp/xdg-cache
  cd {{root}}/apps/web
  dist_dir="dist"
  if pgrep -f "trunk serve" >/dev/null 2>&1; then
    dist_dir="dist-build"
    echo "Detected running trunk serve; building into ${dist_dir} to avoid staging conflicts."
  fi
  mkdir -p "${dist_dir}"
  rm -rf "${dist_dir}/.stage"
  mkdir -p "${dist_dir}/.stage"
  : "${PERMESI_API_BASE_URL:=https://api.permesi.localhost}"
  : "${PERMESI_TOKEN_BASE_URL:=https://genesis.permesi.localhost}"
  : "${PERMESI_CLIENT_ID:=00000000-0000-0000-0000-000000000000}"
  XDG_CACHE_HOME="{{root}}/.tmp/xdg-cache" \
    PERMESI_API_BASE_URL="${PERMESI_API_BASE_URL}" \
    PERMESI_TOKEN_BASE_URL="${PERMESI_TOKEN_BASE_URL}" \
    PERMESI_CLIENT_ID="${PERMESI_CLIENT_ID}" \
    env -u NO_COLOR trunk build --release --dist "${dist_dir}"
  if [[ "${dist_dir}" != "dist" ]]; then
    echo "Build output available at apps/web/${dist_dir}"
  fi
  if [[ ! -s assets/app.gen.css ]]; then
    echo "Missing generated CSS: apps/web/assets/app.gen.css" >&2
    exit 1
  fi

web-clean: web-node-setup
  #!/usr/bin/env zsh
  set -euo pipefail
  if ! command -v trunk >/dev/null 2>&1; then
    just web-setup
  fi
  rm -rf {{root}}/.tmp/xdg-cache
  mkdir -p {{root}}/.tmp/xdg-cache
  cd {{root}}/apps/web
  XDG_CACHE_HOME="{{root}}/.tmp/xdg-cache" env -u NO_COLOR trunk clean --dist dist-dev
  npm run css:build
  if [[ ! -s assets/app.gen.css ]]; then
    echo "Missing generated CSS: apps/web/assets/app.gen.css" >&2
    exit 1
  fi

web-check:
  cargo check -p permesi_web

web-setup:
  #!/usr/bin/env zsh
  set -euo pipefail
  mkdir -p {{root}}/.tmp
  rustup target add wasm32-unknown-unknown
  if ! command -v trunk >/dev/null 2>&1; then
    cargo install --locked trunk
  fi

web-node-setup:
  #!/usr/bin/env zsh
  set -euo pipefail
  if ! command -v node >/dev/null 2>&1; then
    echo "Install Node.js to build Tailwind assets." >&2
    exit 1
  fi
  if ! command -v npm >/dev/null 2>&1; then
    echo "Install npm to build Tailwind assets." >&2
    exit 1
  fi
  cd {{root}}/apps/web
  npm install

web-css-watch: web-node-setup
  #!/usr/bin/env zsh
  set -euo pipefail
  cd {{root}}/apps/web
  npm run css:build
  npm run css:watch

web-css-build: web-node-setup
  #!/usr/bin/env zsh
  set -euo pipefail
  cd {{root}}/apps/web
  npm run css:build

firefox-dev:
  #!/usr/bin/env zsh
  set -euo pipefail
  script="{{root}}/firefox-dev.sh"
  if [[ ! -x "$script" ]]; then
    echo "Missing executable: ${script}" >&2
    exit 1
  fi
  nohup "$script" >/tmp/firefox-dev.log 2>&1 &
  disown
  echo "Firefox dev launched (log: /tmp/firefox-dev.log)"

firefox:
  #!/usr/bin/env zsh
  set -euo pipefail
  if ! command -v hyprctl >/dev/null 2>&1; then
    echo "hyprctl not found; run: just firefox-dev" >&2
    exit 1
  fi
  hyprctl dispatch exec "[workspace 2] bash -lc 'cd {{root}} && just firefox-dev'"
