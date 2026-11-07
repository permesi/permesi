# Build actual service binaries and the same CSR assets that the isolated runner serves.
[doc("Build the standalone OAuth runner, real services and Web assets")]
oauth-scenario-build: (web-build "dist")
  cargo build --locked -p permesi -p genesis -p permesi-oauth-scenario

[doc("Run the full OAuth scenario suite on a disposable local Podman stack")]
oauth-scenario *args: oauth-scenario-build
  "{{root}}/target/debug/permesi-oauth-scenario" {{args}}

[doc("List stable OAuth scenario IDs without starting infrastructure")]
oauth-scenario-list:
  cargo run --locked -p permesi-oauth-scenario -- --list

[doc("Install the pinned Better Auth interoperability fixture dependencies")]
oauth-scenario-better-auth-setup:
  npm --prefix "{{root}}/tools/better_auth_interop" ci

[doc("Run only the two Better Auth interoperability cases on a disposable local Podman stack")]
oauth-scenario-better-auth *args: oauth-scenario-build oauth-scenario-better-auth-setup
  "{{root}}/target/debug/permesi-oauth-scenario" --case interop.better_auth_login --case interop.better_auth_state_reject {{args}}

[doc("Verify recovery guards, interruptions, restart SIGKILL, startup/deadline failures and isolation")]
oauth-scenario-harness-test *args:
  python3 -m unittest discover -s "{{root}}/tools/oauth_scenario/tests" -p '*_test.py'
  python3 "{{root}}/tools/oauth_scenario/tests/harness.py" {{args}}
