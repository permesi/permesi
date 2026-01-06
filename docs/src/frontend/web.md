# Web Application

The Permesi frontend is a CSR-only (Client-Side Rendered) application built with **Leptos** and **Trunk**.

## Architecture

The frontend communicates with both `genesis` and `permesi`:

- **Genesis**: Used to fetch "Zero Tokens" required for all sensitive authentication operations (signup, login, email verification).
- **Permesi**: Used for session management, user profile updates, and administrative actions.

## Authentication Flow

All authentication requests are gated by a Genesis admission token.

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
```

## State Management

- **Session Hydration**: Happens once on app mount via `/v1/auth/session`.
- **In-Memory Tokens**: Session and Admin tokens are stored in Leptos `RwSignal` signals and are never persisted to local storage to prevent leakage.
- **Role-Gating**: The UI provides UX-level gating for "Workspace" and "Platform Admin" sections based on the user's role and elevation status.

## Configuration

Configuration is provided at build-time via environment variables (e.g., `PERMESI_API_BASE_URL`, `PERMESI_CLIENT_ID`). These can be overridden at runtime by a `public/config.js` file if necessary.