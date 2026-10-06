# permesi_web

CSR-only Leptos frontend built with Trunk. Outputs static assets for hosting on Cloudflare Pages.
Tailwind runs via Node at build/dev time only (no Node at runtime).

## Commands

- `just web`: Tailwind build/watch + Trunk dev server (recommended).
- `just web-build`: production build (`apps/web/dist`).
- `just web-css-watch`: Tailwind watch (CSS only).
- `just web-css-build`: Tailwind minified build (CSS only).
- `just web-node-setup`: install Node deps for Tailwind CLI.
- `just web-setup`: install the pinned, checksum-verified official Trunk binary
  and the wasm target. Using the release binary avoids host C compiler
  incompatibilities in Trunk's build-only dependencies.
- `just web-check`: `cargo check -p permesi_web`.
- `podman build -f apps/web/Dockerfile -t web:dev .`: build a container image that serves `dist/` with nginx.

Note: running `trunk serve` directly will skip CSS generation unless you also run `npm run css:watch`.

## Layout

- `src/main.rs`: wasm entrypoint and `mount_to_body`.
- `src/app.rs`: App component, router, and auth provider.
- `src/routes/`: route definitions and pages.
- `src/components/`: layout and reusable UI pieces.
- `src/features/`: domain logic for auth and users.
- `src/lib/`: shared config, API wrapper, and errors.
- `public/`: static files copied to the dist root (reference with `/logo.svg`, `/favicon.ico`, etc.).
- `assets/app.css`: Tailwind v4 entrypoint (`@config`, `@source`, `@import "tailwindcss"`).
- `assets/app.gen.css`: generated Tailwind output (ignored in git).
- `index.html`: Trunk pipeline (copies `public/`, pulls CSS and wasm).

## Routes

- `/`: Dashboard
- `/health`: Build version (git commit)
- `/login`: Sign in
- `/signup`: Sign up
- `/verify-email`: Verify email token + resend link
- `/users`: Users list
- `/users/:id`: User detail
- any other path: Not Found

## Environment management

Projects own independent sibling environments at
`/console/orgs/:slug/projects/:project_slug`. The creation form offers both tiers
even for an empty Project and defaults to `non_production`, matching the API.
Names and slugs identify development, QA, staging, or other environments; tier
classifies their security/operational use without imposing creation order.
Each Project permits zero or one active production environment and any number of
non-production environments. The active list disables Production when it is already
configured, while the backend and PostgreSQL remain authoritative. Soft-deleted
production environments do not occupy that slot. Creation uses the shared
keyboard-accessible dialog and preserves input on API errors.

## OAuth configuration console

Navigate through Organizations → Organization → Project → Environment → Application,
then open **OAuth Configuration**. Environment cards now open their application list;
an application has an Overview and OAuth Configuration navigation. The OAuth summary
links to Clients and Scopes and shows their configured counts.

The nested routes below `/console/orgs/:slug/projects/:project_slug/envs/:env_slug/apps/:app_id`
are the application overview, `/oauth`, `/oauth/clients`, `/oauth/clients/:client_id`,
and `/oauth/scopes`. The parent environment route lists applications and can create
them. Application metadata comes from the existing collection endpoint; no new
backend contract or detail GET is assumed.

Client pages support creation, name changes, exact redirect URI allow-lists, delegated
scope allow-lists, enable/disable, and deletion. Redirect edits are staged until Save;
the API performs URI validation and failed saves retain the draft. Client deletion
requires typing the public client ID. Scope names are immutable; application scope
descriptions can be edited, and deletion requires typing the scope name. Server-defined
OIDC scopes are shown as read-only system entries but can be assigned to client
allow-lists. Assignment limits what a client may request and never grants user authority.

Create Scope uses Resource (the thing protected) and Action (the delegated operation)
with a live `resource:action` preview. Correcting either field clears obsolete validation errors. Actions are free text, so `runs:cancel` and
`deployments:approve` are supported alongside `jobs:read`. The API still receives only
`name` and `description`; derived labels are not additional persisted fields. Scope
cards expose resource/action labels, and client choices group by exact resource while
retaining full OAuth names. Application scope creation and client assignment require exactly one resource and action.
Protocol scopes stay system-managed and are never parsed as resource/action. Already-configured
unsupported names remain visible with removal-only controls; changes require explicit Save.
The reserved `users:`/`platform:` namespaces cannot be used, including `users:invite`.

Organization owners/admins may mutate configuration. The current API omits organization
roles from response DTOs, so the console does not infer them from platform roles or
internal permissions. Management controls explain the required role; the server remains
authoritative and inaccessible-resource errors keep the backend's 404 convention.
Confidential-client detail pages manage secrets through metadata, create, rotate and
revoke APIs. Secrets are shown once with copy/acknowledgement; closing or navigating
clears disclosure. A retiring secret shows its server deadline, and another rotation
waits for expiry or explicit revocation. Public clients have no credential controls.
Pending actions prevent duplicate submission/dismissal. After an ambiguous issuance
failure, metadata refresh and explicit revoke/create recovery preserve the old overlap
deadline; the UI never retries issuance automatically or stores plaintext in browser storage.

Minimal authorization consent is rendered by the backend and login/MFA resume is supported.
Authorization-code token exchange and signed access/ID tokens are implemented by the service;
broader grants management and refresh tokens remain planned. [TODO](../../TODO.md) tracks
completion; the [OAuth roadmap](../../docs/oauth-foundation.md#roadmap) describes dependencies.
Confidential secret management does not implement the OAuth `client_credentials` M2M grant.

`src/features/oauth/client.rs` uses the existing cookie-authenticated HTTP helpers;
PATCH and PUT use the same API base, request timeout and error decoder. Pure DTOs,
paths and edit transitions are exported by `src/lib.rs` so `cargo test -p permesi_web`
runs their regressions natively. `cargo check -p permesi_web --target wasm32-unknown-unknown`
checks the actual browser components; `just web-check` retains its existing native
tooling check, and `just web-build` builds the production WASM and CSS.

`just web-test-browser` builds the console and runs the dependency-free Node/Chromium
smoke test against isolated local API fixtures. It exercises navigation, public IDs,
copy feedback, retained validation drafts, scope assignment, system scope controls,
lifecycle and credential confirmations, one-time secret clearing/copy, rotation overlap,
response-loss recovery, forced closure during pending mutations, disabled buttons,
and a fixed 390px layout. It also captures desktop/mobile/dark screenshots under
`/tmp/permesi-oauth-ui-client-*.png`. It uses no dev session or database data; real
tenant enforcement and database invariants stay covered by the backend integration
tests. Node 22 or later and `chromium` in PATH are required. Set
`PERMESI_WEB_TEST_DIST` to select an already built distribution explicitly when
running `node apps/web/tests/oauth_console.mjs` from the repository root.
The test recipe passes its selected build directory explicitly so an older
`dist-build` cannot shadow a fresh `dist`; direct Node runs default to `dist`.
Dark-mode verification emulates `prefers-color-scheme` and checks actual card and
heading colors rather than toggling a class the stylesheet does not use.

The same recipe explicitly runs the normally ignored real PostgreSQL browser tests for
authorization consent/redirects and organization deletion with OPAQUE reauthentication.
`just web-test-browser-built dist` runs all three stages against an existing distribution
without rebuilding it; a missing `index.html` or undiscoverable exact backend test fails
before test startup. `Test & Build` uses this helper with the frontend artifact from the
same commit and a private Podman
runtime in a fresh hosted browser job. Its result is required by `CI OK`. The job adapts
native Google Chrome, falling back to Chromium, through a private `chromium` alias,
and uploads no browser profiles, request dumps, credentials or screenshots. WASM Clippy remains a separate
tracked gate; the browser job does not suppress or replace native lint checks.
Selection requires headless startup with a host-visible port file and reachable loopback
DevTools endpoint, using an empty private probe profile that is stopped and removed.
An installed browser's successful version command alone cannot satisfy this check.
The console fixture explicitly overrides API/admission origins and fixture client/server
identity, with a browser regression for the admission origin. All three scripts block
non-loopback hostname resolution and request reduced background networking. External
font links remain in `index.html` but cannot resolve in these test browsers. The resolver
rule does not act as an operating-system firewall or block literal external IP addresses;
fixture API/callback URLs are explicitly loopback and these tests claim that narrower boundary.

Application sections use primary tabs with Material Symbols and an underline for the current section. Inside OAuth Configuration, Summary, Clients and Scopes use a smaller segmented navigation; client details keep Clients selected. Both levels retain text labels, keyboard focus styles and independent active states in light and dark themes.

The API permits credentialed PUT preflights from its existing configured frontend origins so the redirect and scope replacement editors work across origins. This preserves the origin allow-list and server authorization checks.

Tenant deletion controls load `GET /v1/orgs/{org_slug}/capabilities` before showing a
Danger Zone. Owners/admins may delete children; only owners see organization deletion.
The flags are uncached presentation hints and every mutation still authorizes server-side.
Opening a dialog pins the account and organization UUID; organization DELETE sends
`X-Permesi-Expected-Organization-Id` so slug reuse cannot change the confirmed target.

A `reauthentication_required` response opens password verification in the same Dialog,
using the existing OPAQUE/admission endpoints and shared client helper also used for
passkey removal. Success refreshes session identity, capabilities and projects, preserves
the typed slug, and returns to confirmation with another explicit deletion confirmation required.
The form ignores auto-repeated Enter so a held password-submit key cannot trigger deletion;
a fresh Enter press and the Delete button remain available.
Wrong passwords, unavailable/rate-limited requests, account changes and permission loss
never trigger deletion. Inputs clear after an attempt or dismissal; no password is placed
in storage, URLs or logs. OPAQUE exchanges now use [shared encrypted PostgreSQL state](../../docs/opaque-exchanges.md):
start/finish can reach different replicas, and reauthentication remains bound to the
original session. The Web API/payloads and explicit final deletion confirmation are unchanged.

`just web-test-browser` additionally runs the compiled console against real PostgreSQL,
OPAQUE handlers and signed admission verification through an isolated loopback fixture.
It covers wrong/correct password proofs, explicit final confirmation, new projects, role
loss, account switching and slug reuse. The fixture never changes production TLS policy.

Confirmation dialogs ignore queued close events from an earlier opening if the browser has already reopened the dialog. Pending requests remain visible until they settle; browser regressions cover immediate reopening as well as repeated Escape.

## Signup + Email Verification Flow

```mermaid
sequenceDiagram
  autonumber
  participant User
  participant Web as permesi.dev (CSR)
  participant Genesis as genesis.permesi.dev
  participant API as api.permesi.dev
  participant DB as Postgres
  participant Outbox as Email outbox worker
  participant Mail as Email provider

  Note over Web,API: Each auth POST includes X-Permesi-Zero-Token minted by Genesis (verified offline).

  Note over Web,API: OPAQUE signup start
  User->>Web: Open signup form
  Web->>Genesis: Mint zero token (signup start)
  Genesis-->>Web: Zero token
  Web->>API: POST /v1/auth/opaque/signup/start (registration_request)
  API->>API: Verify token (PASERK keyset)
  API-->>Web: registration_response

  Note over Web,API: OPAQUE signup finish
  Web->>Genesis: Mint zero token (signup finish)
  Genesis-->>Web: Zero token
  Web->>API: POST /v1/auth/opaque/signup/finish (registration_record)
  API->>API: Verify token (PASERK keyset)
  Note over API,DB: Single transaction
  API->>DB: Insert user (pending_verification)
  API->>DB: Insert verification token (hashed, TTL)
  API->>DB: Insert email_outbox row
  API-->>Web: 201 generic response

  Outbox->>DB: Poll pending emails
  Outbox->>Mail: Send verification email
  Mail-->>User: Link https://permesi.dev/verify-email#token=...

  Note over Web,API: Email verification
  User->>Web: Open verify link
  Web->>Genesis: Mint zero token (verify)
  Genesis-->>Web: Zero token
  Web->>API: POST /v1/auth/verify-email
  API->>API: Verify token (PASERK keyset)
  API->>DB: Consume token + activate user
  API-->>Web: 204

      opt Resend verification (optional)
      User->>Web: Request new link
      Web->>Genesis: Mint zero token (resend)
      Genesis-->>Web: Zero token
      Web->>API: POST /v1/auth/resend-verification
      API->>API: Verify token (PASERK keyset)
      API->>DB: Enqueue new token/outbox (cooldown)
      API-->>Web: 204
    end
  ```
  
  Legend:
  - `registration_request`: OPAQUE client message (start)
  - `registration_response`: OPAQUE server message (start)
  - `registration_record`: OPAQUE client registration upload (finish)
  
  ## Admin Elevation Flow
  
  Platform operators must elevate their session to access administrative routes. This flow ensures that powerful actions require a short-lived step-up token backed by Vault.
  
  ```mermaid
  sequenceDiagram
    autonumber
    participant User
    participant Web as permesi.dev (CSR)
    participant API as api.permesi.dev
    participant Vault
  
    User->>Web: Enter Vault token at /admin/claim
    Web->>API: POST /v1/auth/admin/elevate (vault_token)
    Note over API,Vault: Session elevation check
    API->>Vault: GET /v1/auth/token/lookup-self (X-Vault-Token)
    Vault-->>API: Valid + operator policy
    API->>API: Mint short-lived Admin PASETO (v4.public)
    API-->>Web: admin_token + expires_at
  
    Note over Web,API: Authenticated Admin Request
    Web->>API: GET /v1/auth/admin/infra (Bearer admin_token)
    API->>API: Verify PASETO signature
    API-->>Web: Infrastructure status
  ```
  
  1. **Vault Step-up**: The operator provides a Vault token which is exchanged for a short-lived, signed PASETO admin token. The Vault token is never persisted or stored in the browser; it is only used once to mint the admin token.
  2. **PASETO Admin Token**: Subsequent administrative requests use this token in the `Authorization: Bearer` header. The backend verifies the signature offline using its internal signing key.
  3. **In-Memory Only**: The admin token is kept strictly in-memory. Reloading the page or closing the tab clears the elevation state, requiring re-entry of a Vault token for security.
  4. **Chained Bootstrap**: During the initial setup (zero operators), the UI automatically chains the bootstrap and elevation calls. Entering the Vault token once creates the first operator and immediately issues an elevated admin token.

  Endpoint auth split for admin:
  - `/v1/auth/admin/status`, `/v1/auth/admin/bootstrap`, and `/v1/auth/admin/elevate` use the session cookie (`credentials: include`).
  - Vault token is sent in JSON payload for bootstrap/elevate (`{ "vault_token": "..." }`).
  - `/v1/auth/admin/infra` uses `Authorization: Bearer <admin_token>` (admin token only).
  
  ## Password Change Flow (OPAQUE)
  
  Users can change their password without the plaintext ever reaching the server. This uses a 4-step OPAQUE handshake that combines re-authentication with a fresh registration.
  
  1. **Secure Re-auth**: The user provides their *current* password. The client and server perform a re-authentication exchange.
  2. **Grant Elevation**: On success, the server grants a short-lived (10 min) elevation to the session, allowing sensitive changes.
  3. **New Registration**: The user provides a *new* password. The client initiates a registration flow.
  4. **Commit Record**: The client seals the new password into a registration record and commits it to the server.
  5. **Revocation**: The server replaces the old record and immediately revokes all active sessions for the user to ensure security.
  
## Current UI state

The health page at `/health` shows frontend build metadata (version and commit)
alongside backend health details so deploys can be verified quickly.
- Home (`/`) is a placeholder ("Home").
- Header shows "Sign In" or "Sign Up" depending on the current route; authenticated sessions see "Sign Out".
- Login performs OPAQUE (`/v1/auth/opaque/login/start` + `/finish`) and fetches a Genesis zero token for each step; permesi sets an HttpOnly session cookie and the frontend reads `/v1/auth/session` to hydrate state.
- Session-authenticated frontend calls rely on the HttpOnly cookie (`credentials: include`); the UI does not use `Authorization: Bearer` for normal session flows.
- Signup performs an OPAQUE registration (`/v1/auth/opaque/signup/start` + `/finish`) with Genesis zero tokens and shows a verify-email prompt.
- Verify email reads the fragment token and POSTs to `/v1/auth/verify-email`; resend is available on the same page (both require zero tokens).
- Auth is UX-only; real access control must be enforced by the API.

## UX behavior and feedback

Forms validate the minimum required fields before submitting. Login checks that email and password are present, while signup also normalizes the email, enforces matching passwords, and requires a 12-character minimum. Errors render as alert banners with safe copy; configuration and crypto failures are mapped to user-facing strings without exposing sensitive details.

Async actions disable the triggering button and show a spinner below the form. Success states render green alerts in place, such as the signup verification prompt or the resend confirmation. The verify-email page reads the token from the URL fragment, clears it immediately to reduce accidental exposure, and offers a resend option with a generic success message to avoid account enumeration.

Session hydration happens once on app mount by calling `/v1/auth/session`. Navigation switches between sign-in/sign-up and sign-out based on that session signal, and sign-out clears local state after hitting the API. Route guards are strictly a UX convenience; backend authorization remains the source of truth.

## API base URL configuration

- Build-time: `PERMESI_API_BASE_URL=https://api.permesi.dev trunk build --release`
- Fallback: `PERMESI_API_HOST` is also supported.
- Default: empty base URL (uses relative `/api/...`).
- CI default: `main` builds use `https://api.permesi.com`, `develop` builds use `https://api.permesi.dev` unless `PERMESI_API_BASE_URL` is set as a GitHub Actions Variable.
- OPAQUE server identifier: `PERMESI_OPAQUE_SERVER_ID` (default `api.permesi.dev`).

## Runtime config (optional)

The UI can override build-time config by loading `public/config.js`, which sets `window.PERMESI_CONFIG`.
This keeps the build static but lets deployers change endpoints and client IDs without rebuilding.
All values are public, so never store secrets in this file.

The container image (`apps/web/Dockerfile`) serves the built assets with nginx using a production cache profile:
`config.js` and `index.html` are `no-store`, while fingerprinted assets (`*.wasm`, `*.js`, `*.css`) are served with
long-lived immutable caching headers.

## Admission token configuration

- Token host: `PERMESI_TOKEN_BASE_URL=https://genesis.permesi.dev`.
- Client ID: `PERMESI_CLIENT_ID=<uuid>` (required to mint `/token`).
- These values are compile-time (`option_env!`). Set them before `trunk build`.
- `PERMESI_CLIENT_ID` is public (embedded in the WASM). In CI, store it as a GitHub Actions **Variable**, not a Secret.
- CI default: `main` builds use `https://genesis.permesi.com`, `develop` builds use `https://genesis.permesi.dev` unless `PERMESI_TOKEN_BASE_URL` is set as a GitHub Actions Variable.

## Styling

Tailwind v4 is built via Node in `apps/web/` (`npm install`, then `npm run css:watch` or `npm run css:build`).
Trunk consumes the generated `apps/web/assets/app.gen.css` (no Node at runtime).
The entry file (`assets/app.css`) declares explicit `@source` globs so `.rs` templates are scanned.
Avoid dynamic Tailwind class construction so content scanning stays deterministic.
PostCSS config (`apps/web/postcss.config.cjs`) is provided for tooling parity.

## Authorization login resume

The existing login/MFA flow accepts an opaque `oauth_request` UUID and nonauthoritative
`oauth_expires` cleanup hint on `/login`. Expiry or navigation outside that flow clears
both; a later console login cannot silently resume an abandoned request. The auth provider
retains no authority in tab-local session storage and returns
to the configured API's `/authorize/resume` after a full session exists. Enrollment and
recovery-driven re-enrollment wait for “I've saved my codes - Continue” before navigation;
without a valid pending request, completion goes to the dashboard. Scopes, tenant,
redirect, nonce and PKCE state remain in PostgreSQL and are protected by the API's
host-only HttpOnly binding cookie; browser state confers no authority. Deploy the Web
API base URL against the same HTTPS issuer origin. Minimal consent is rendered by
the backend, with read-only registry descriptions and Allow/Cancel. Token issuance
and broader consent/grant management remain deferred.

`just web-test-browser` runs both the compiled console/login-resume fixtures and
a real Chromium consent flow against an isolated PostgreSQL-backed authorization
handler. The latter uses distinct trusted loopback HTTP origins for issuer and client, without any
production TLS override or external client callback, and validates the actual secure
binding cookie, read-only consent, rejected scope injection, single-use form and
exact cross-origin code/state/cancel redirects for IPv4 and IPv6 loopback clients.
