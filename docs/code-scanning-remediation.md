# Code-scanning remediation

The November 6, 2026 review covered all 130 open CodeQL alerts against released
`main` revision `04783bc009cdef4e8ba71910c12ecbd25aa74dfd`. Each alert was traced
using its location and SARIF data flow, including the owning test compilation
boundary. GitHub records an individual explanation on each dismissed alert.

| Rule | Alerts | Disposition and evidence |
| --- | ---: | --- |
| `rust/hard-coded-cryptographic-value` | 75 | Dismissed as used in tests. Every reported key/password is behind `#[cfg(test)]`, including inherited test modules and `AppState::for_tests`. Deterministic keys exercise wrong-key, replay and persistence rejection; they are not production credentials. |
| `rust/cleartext-logging` | 5 | Four test-only clap validation reports were dismissed as used in tests; one CORS-vector insertion report was dismissed as a false positive. SARIF treats clap argument definitions and numeric attempt limits as sensitive values. The reported operations do not log credentials. |
| `rust/cleartext-transmission` | 5 | Three disposable integration-fixture reports were dismissed as used in tests. Health requests use HTTPS with the test CA; the dev-only Vault fixture publishes synthetic credentials on IPv4 loopback. Two production reports were dismissed as false positives: SARIF incorrectly propagates numeric account/MFA attempt budgets through `Args` into the Vault URL. Those budgets are not secrets and are not inserted into the URL. |
| `js/bad-code-sanitization` | 13 | Dismissed as false positives. These browser helpers embed `JSON.stringify(string)` as JavaScript literals for local CDP evaluation, without an HTML parsing boundary. Fifteen executions of the actual control/fill/wait/callback/replay helpers preserved quote, backslash, newline, Unicode separator, template and script-tag payloads without executing them. |
| `js/file-access-to-http` | 3 | Dismissed as used in tests. Chromium writes its debugging port to `DevToolsActivePort`; the harness queries the local CDP endpoint. Shared discovery now validates decimal port syntax/range and constructs a fixed IPv4-loopback URL. All four browser suites use private random profile directories. |
| `actions/unpinned-tag` | 19 | Fixed in workflow sources. All 87 remote action references, including composite-action steps and first-party actions, now use full commit hashes resolved from their existing tags. Version comments and Dependabot retain update visibility. The required format job rejects mutable references. |
| `js/insecure-temporary-file` | 9 | Fixed in browser test sources. Eight console screenshots and the sibling consent screenshot use a private random directory and exclusive, owner-only file creation. The unused request-body dump was removed. A pre-created symlink cannot overwrite another file. |
| `js/http-to-file-access` | 1 | Fixed by removing the unused request-body JSON dump. Request assertions still use the in-memory trace. |

This closes 101 verified fixture/false-positive alerts and prepares source fixes
for the remaining 29. GitHub's default CodeQL setup scans released `main`; those
29 remain open until the fixed sources reach that branch and are scanned. An
open dashboard entry during promotion does not establish that the sandbox fix
was rescanned. Production Vault HTTP/HTTPS/Agent connectivity policy is preserved;
the dismissed numerical-budget flows do not certify arbitrary HTTP deployments.

The browser file regressions assert private directory/file permissions, distinct
run directories, symlink and path rejection, preservation of the protected target,
successful screenshot writes, and rejection of malformed discovery ports.
Restoring the original nonexclusive write behavior makes the symlink test fail;
restoring unvalidated port interpolation makes the port test fail. The action
guard failed on the original workflows and rejects a reintroduced mutable tag.
Run `node apps/web/tests/browser_files.test.mjs` and
`python3 scripts/check-action-pins.py` for the focused checks. Both run in CI, and
the browser recipe runs the file tests before the compiled console and real
PostgreSQL browser suites.

Validation passed with 820 workspace tests (`cargo test --workspace --locked`),
the compiled-console smoke test, and all three normally ignored real PostgreSQL
browser tests run explicitly through `just web-test-browser-built`. Native
all-target/all-feature Clippy, strict WASM Clippy, formatting, Actionlint 1.7.12,
the action pin guard, the two browser file regressions, and the existing 21 CI
helper tests passed. `npm audit --audit-level=high` reported no vulnerabilities.
Cargo audit passed under the existing RSA advisory exception, with the existing
`paste` and `astral-tokio-tar` maintenance warnings; these are separate from the
130 reviewed CodeQL alerts.
