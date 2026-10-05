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

[doc("Verify runner interruption, startup failure, deadlines, cleanup faults and concurrent isolation")]
oauth-scenario-harness-test:
  python3 "{{root}}/tools/oauth_scenario/tests/harness.py"
