// Test-only Better Auth interoperability fixture driven by tools/oauth_scenario.
//
// Flow Overview: the harness starts this process with private configuration and
// run-owned TLS/database paths. The genericOAuth plugin performs real discovery,
// S256 PKCE, nonce-bound ID-token verification and client_secret_basic exchange
// against the per-run Permesi issuer. The app serves one sign-in page, a protected
// success page and read-only fixture inspection routes used by scenario assertions.
//
// This fixture never mocks the provider, mints tokens, pre-creates sessions or
// replaces the library's token/userinfo code. All secrets arrive through the
// process environment, never command lines, and nothing sensitive is logged.

import { createServer } from "node:https";
import { readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { fromNodeHeaders, toNodeHandler } from "better-auth/node";
import { genericOAuth } from "better-auth/plugins/generic-oauth";

// Every input is required; a partial configuration must fail before serving.
function required(name) {
  const value = process.env[name];
  if (!value) {
    process.stderr.write(`Missing required fixture configuration: ${name}\n`);
    process.exit(1);
  }
  return value;
}

const certPath = required("PERMESI_FIXTURE_CERT");
const keyPath = required("PERMESI_FIXTURE_KEY");
// The run-owned storage path is the sole process argument: it is non-secret and
// keeps the private directory visible in the command line for recovery guards.
const databasePath = process.argv[2];
if (!databasePath) {
  process.stderr.write("Missing fixture storage path argument.\n");
  process.exit(1);
}
const secret = required("PERMESI_FIXTURE_SECRET");
const issuer = required("PERMESI_FIXTURE_ISSUER");
const clientId = required("PERMESI_FIXTURE_CLIENT_ID");
const clientSecret = required("PERMESI_FIXTURE_CLIENT_SECRET");
const organizationId = required("PERMESI_FIXTURE_ORGANIZATION_ID");

const database = new DatabaseSync(databasePath);

function options(baseURL) {
  return {
    appName: "Permesi Better Auth interop fixture",
    baseURL,
    secret,
    database,
    logger: { level: "error", disabled: true, log: () => {} },
    plugins: [
      genericOAuth({
        config: [
          {
            providerId: "permesi",
            name: "Permesi",
            discoveryUrl: `${issuer}/.well-known/openid-configuration`,
            requireIdTokenVerification: true,
            clientId,
            clientSecret,
            tokenEndpointAuth: { method: "client_secret_basic" },
            scopes: ["openid", "profile", "email"],
            redirectURI: `${baseURL}${callbackPath}`,
            pkce: true,
            // Permesi requires the trusted fixture organization on every request.
            // Library-managed state, nonce and PKCE parameters stay reserved and
            // cannot be overridden through these extra authorization parameters.
            authorizationUrlParams: { organization_id: organizationId },
          },
        ],
      }),
    ],
  };
}

const callbackPath = "/api/auth/callback/permesi";

const signInPage = `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Permesi sign-in fixture</title></head><body>
<h1>Permesi sign-in fixture</h1>
<button id="sign-in" style="cursor:pointer">Sign in with Permesi</button>
<script>
document.querySelector("#sign-in").addEventListener("click", async () => {
  const response = await fetch("/api/auth/sign-in/social", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      provider: "permesi",
      callbackURL: location.origin + "/done",
      errorCallbackURL: location.origin + "/sign-in-error",
      disableRedirect: true,
    }),
  });
  const body = await response.json();
  if (body && body.url) location.href = body.url;
});
</script>
</body></html>`;

// Static failure pages: the scenario reads the error code from the redirect URL.
const errorPage = `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Sign-in failed</title></head><body><h1>Sign-in failed</h1></body></html>`;

function json(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json",
    "cache-control": "no-store",
  });
  res.end(payload);
}

function html(res, status, body) {
  res.writeHead(status, {
    "content-type": "text/html; charset=utf-8",
    "cache-control": "no-store",
  });
  res.end(body);
}

function counts() {
  const count = (table) =>
    database.prepare(`SELECT count(*) AS n FROM ${table}`).get().n;
  return {
    users: count("user"),
    accounts: count("account"),
    sessions: count("session"),
    verifications: count("verification"),
  };
}

async function route(auth, req, res) {
  const url = new URL(req.url, "https://fixture.invalid");
  if (url.pathname === "/") return html(res, 200, signInPage);
  if (url.pathname === "/sign-in-error") {
    return html(res, 200, errorPage);
  }
  if (url.pathname === "/done") {
    const session = await auth.api.getSession({
      headers: fromNodeHeaders(req.headers),
    });
    if (!session) return json(res, 401, { error: "unauthenticated" });
    return html(res, 200, `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Authenticated</title></head><body><h1>Authenticated</h1></body></html>`);
  }
  if (url.pathname === "/fixture/state") return json(res, 200, counts());
  if (url.pathname === "/fixture/identity") {
    const session = await auth.api.getSession({
      headers: fromNodeHeaders(req.headers),
    });
    if (!session) return json(res, 401, { error: "unauthenticated" });
    const linked = database
      .prepare('SELECT "providerId", "accountId" FROM account WHERE "userId" = ?')
      .all(session.user.id)
      .map((row) => ({ providerId: row.providerId, accountId: row.accountId }));
    return json(res, 200, {
      userId: session.user.id,
      email: session.user.email,
      linked,
    });
  }
  return json(res, 404, { error: "not_found" });
}

let auth;
const server = createServer(
  { cert: readFileSync(certPath), key: readFileSync(keyPath) },
  (req, res) => {
    const handler = () =>
      route(auth, req, res).catch(() => json(res, 500, { error: "fixture_failure" }));
    if (req.url.startsWith("/api/auth/")) return toNodeHandler(auth)(req, res).catch(handler);
    return handler();
  },
);

await new Promise((resolve, reject) => {
  server.once("error", reject);
  server.listen(0, "127.0.0.1", resolve);
});
const baseURL = `https://127.0.0.1:${server.address().port}`;
const config = options(baseURL);
const migrations = await getMigrations(config);
await migrations.runMigrations();
auth = betterAuth(config);
// Fail fast unless discovery registered the provider with verified ID-token support;
// a skipped provider must never look like successful interoperability coverage.
const context = await auth.$context;
if (!context.socialProviders.some((provider) => provider.id === "permesi")) {
  process.stderr.write("Permesi provider registration failed during discovery.\n");
  process.exit(1);
}
process.stdout.write(JSON.stringify({ ready: true, port: server.address().port, callback: callbackPath }) + "\n");
