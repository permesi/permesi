#!/usr/bin/env bash
set -euo pipefail

# firefox-dev: clean, isolated Firefox profile for web-dev testing.
#
# Defaults:
#   PROFILE_NAME=dev
#   WM_CLASS=firefox-dev
#   FIREFOX_BIN=firefox-developer-edition
#   START_URL=https://permesi.localhost
#   START_URLS=https://permesi.localhost,https://api.permesi.localhost/health,https://genesis.permesi.localhost/health
#   HOME_URLS=https://permesi.localhost|https://api.permesi.localhost/health|https://genesis.permesi.localhost/health
#   FORCE_LIGHT_THEME=1 (default: force Light theme)
#   FIREFOX_THEME_ID=firefox-compact-light@mozilla.org
#
# Optional env toggles:
#   PROFILE_NAME=permesi-dev
#   WM_CLASS=firefox-dev-permesi
#   DISABLE_PASSWORD_PROMPTS=1   (default: disable password save prompts)
#   DISABLE_SERVICE_WORKERS=1   (more deterministic, less realistic)
#   DISABLE_CACHES=1            (more deterministic, less realistic)

PROFILE_NAME="${PROFILE_NAME:-dev}"
WM_CLASS="${WM_CLASS:-firefox-dev}"
FIREFOX_BIN="${FIREFOX_BIN:-firefox-developer-edition}"
START_URL="${START_URL:-}"
START_URLS="${START_URLS:-}"
HOME_URLS="${HOME_URLS:-https://permesi.localhost|https://api.permesi.localhost/health|https://genesis.permesi.localhost/health}"
FORCE_LIGHT_THEME="${FORCE_LIGHT_THEME:-1}"
FIREFOX_THEME_ID="${FIREFOX_THEME_ID:-firefox-compact-light@mozilla.org}"

DISABLE_SERVICE_WORKERS="${DISABLE_SERVICE_WORKERS:-0}"
DISABLE_CACHES="${DISABLE_CACHES:-0}"
DISABLE_PASSWORD_PROMPTS="${DISABLE_PASSWORD_PROMPTS:-1}"

FF_DIR="${HOME}/.mozilla/firefox"
INI="${FF_DIR}/profiles.ini"

die() {
    echo "error: $*" >&2
    exit 1
}

if ! command -v "$FIREFOX_BIN" >/dev/null 2>&1; then
    if [[ "$FIREFOX_BIN" == "firefox-developer-edition" ]] && command -v firefox >/dev/null 2>&1; then
        echo "warning: firefox-developer-edition not found; falling back to firefox" >&2
        FIREFOX_BIN="firefox"
    else
        die "firefox binary not found in PATH"
    fi
fi
mkdir -p "$FF_DIR"

# Return Path= for the profile Name= from profiles.ini
get_profile_path() {
    local name="$1"
    [[ -f "$INI" ]] || return 0
    awk -v name="$name" -v ff_dir="$FF_DIR" '
    BEGIN { in_profile=0; path=""; }
    /^\[Profile[0-9]+\]/ { in_profile=0; path=""; }
    $0 == "Name="name { in_profile=1; }
    in_profile && /^Path=/ { path=$0; sub(/^Path=/,"",path); }
    in_profile && /^$/ {
      if (path!="") {
        if (path ~ /^\//) { print path; } else { print ff_dir "/" path; }
        exit
      }
    }
    END {
      if (in_profile && path!="") {
        if (path ~ /^\//) { print path; } else { print ff_dir "/" path; }
      }
    }
  ' "$INI" 2>/dev/null || true
}

profile_path="$(get_profile_path "$PROFILE_NAME")"

# Create profile if missing (keeps it deterministic under ~/.mozilla/firefox/)
if [[ -z "$profile_path" ]]; then
    echo "Creating Firefox profile '${PROFILE_NAME}'..."
    "$FIREFOX_BIN" -CreateProfile "${PROFILE_NAME} ${FF_DIR}/${PROFILE_NAME}" >/dev/null || die "failed to create profile"
    profile_path="$(get_profile_path "$PROFILE_NAME")"
fi

# Resolve profile directory (handles both relative and direct path cases)
profile_dir="${profile_path:-${FF_DIR}/${PROFILE_NAME}}"
mkdir -p "$profile_dir"

userjs="${profile_dir}/user.js"
home_urls_escaped="${HOME_URLS//\"/\\\"}"

cat >"$userjs" <<'JS'
// ---- Clean dev profile (generic) ----

// Force light mode for chrome + content.
user_pref("ui.systemUsesDarkTheme", 0);
user_pref("browser.theme.toolbar-theme", 1);
user_pref("browser.theme.content-theme", 1);
user_pref("layout.css.prefers-color-scheme.content-override", 1);
user_pref("browser.in-content.dark-mode", false);
user_pref("devtools.theme", "light");
user_pref("widget.content.allow-gtk-dark-theme", false);

// Disable address / payment autofill
user_pref("extensions.formautofill.addresses.enabled", false);
user_pref("extensions.formautofill.creditCards.enabled", false);

// Disable Firefox Sync (prevents state bleed)
user_pref("services.sync.enabled", false);
user_pref("identity.fxaccounts.enabled", false);

// Reduce Referer leakage (useful for token/magic-link testing)
user_pref("network.http.sendRefererHeader", 0);
JS

if [[ "$DISABLE_PASSWORD_PROMPTS" == "1" ]]; then
    cat >>"$userjs" <<'JS'
// Disable password saving & login autofill
user_pref("signon.rememberSignons", false);
user_pref("signon.autofillForms", false);
user_pref("signon.autofillForms.http", false);
user_pref("signon.generation.enabled", false);
JS
fi

if [[ "$FORCE_LIGHT_THEME" == "1" ]]; then
    theme_id="${FIREFOX_THEME_ID//\"/\\\"}"
    printf 'user_pref("extensions.activeThemeID", "%s");\n' "$theme_id" >>"$userjs"
    printf 'user_pref("lightweightThemes.selectedThemeID", "%s");\n' "$theme_id" >>"$userjs"
fi

printf 'user_pref("browser.startup.page", 1);\n' >>"$userjs"
printf 'user_pref("browser.startup.homepage", "%s");\n' "$home_urls_escaped" >>"$userjs"

if [[ "$DISABLE_SERVICE_WORKERS" == "1" ]]; then
    cat >>"$userjs" <<'JS'
user_pref("dom.serviceWorkers.enabled", false);
JS
fi

if [[ "$DISABLE_CACHES" == "1" ]]; then
    cat >>"$userjs" <<'JS'
user_pref("browser.cache.disk.enable", false);
user_pref("browser.cache.memory.enable", false);
JS
fi

echo "Profile:     ${PROFILE_NAME}"
echo "WM_CLASS:    ${WM_CLASS}"
echo "Profile dir: ${profile_dir}"

if [[ -z "$START_URLS" && -z "$START_URL" ]]; then
    START_URLS="${HOME_URLS//|/,}"
fi

launch_urls=()
if [[ -n "$START_URLS" ]]; then
    IFS=',' read -r -a launch_urls <<<"$START_URLS"
elif [[ -n "$START_URL" ]]; then
    launch_urls=("$START_URL")
fi

if [[ ${#launch_urls[@]} -gt 0 ]]; then
    exec "$FIREFOX_BIN" -profile "$profile_dir" --no-remote --class "$WM_CLASS" "${launch_urls[@]}"
fi
exec "$FIREFOX_BIN" -profile "$profile_dir" --no-remote --class "$WM_CLASS"
