# permesi_web

CSR-only Leptos frontend built with Trunk. Outputs static assets for hosting on Cloudflare Pages.
Tailwind runs via Node at build/dev time only (no Node at runtime).

## Commands

- `just web`: Tailwind build/watch + Trunk dev server (recommended).
- `just web-build`: production build (`apps/web/dist`).
- `just web-css-watch`: Tailwind watch (CSS only).
- `just web-css-build`: Tailwind minified build (CSS only).
- `just web-node-setup`: install Node deps for Tailwind CLI.
- `just web-setup`: install Trunk + wasm target.
- `just web-check`: `cargo check -p permesi_web`.

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
  
  ## Password Change Flow (OPAQUE)
  
  Users can change their password without the plaintext ever reaching the server. This uses a 4-step OPAQUE handshake that combines re-authentication with a fresh registration.
  
  1. **Secure Re-auth**: The user provides their *current* password. The client and server perform a re-authentication exchange.
  2. **Grant Elevation**: On success, the server grants a short-lived (10 min) elevation to the session, allowing sensitive changes.
  3. **New Registration**: The user provides a *new* password. The client initiates a registration flow.
  4. **Commit Record**: The client seals the new password into a registration record and commits it to the server.
  5. **Revocation**: The server replaces the old record and immediately revokes all active sessions for the user to ensure security.
  
  ## Current UI state
- Home (`/`) is a placeholder ("Home").
- Header shows "Sign In" or "Sign Up" depending on the current route; authenticated sessions see "Sign Out".
- Login performs OPAQUE (`/v1/auth/opaque/login/start` + `/finish`) and fetches a Genesis zero token for each step; permesi sets an HttpOnly session cookie and the frontend reads `/v1/auth/session` to hydrate state.
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
