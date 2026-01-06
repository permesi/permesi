# Architecture

Permesi employs a **Split-Trust Architecture** to separate network noise from core identity logic.

## System Overview

```mermaid
flowchart LR
  subgraph Internet
    U[User / Client]
  end

  subgraph Edge
    G[Genesis edge admission token mint]
    PASERK[(PASERK keyset)]
  end

  subgraph Core
    P[Permesi core IAM authority]
  end

  subgraph Data
    DB[(Audit / Revocation DB)]
  end

  U -->|"1: Request admission"| G
  G -->|"2: Signed Admission Token<br/>(PASETO)"| U

  G -->|"Publishes public keys"| PASERK
  P -->|"Loads PASERK keyset"| PASERK

  U -->|"3: Credentials + Admission Token"| P
  P -->|"4: Offline verify:<br/>sig, exp, aud, iss"| P

  G -.->|"Optional audit write"| DB
  P -.->|"Optional revocation check"| DB
```

## Admission Token Verification (Offline)

Admission token verification never calls `genesis` on the hot path. The flow is:

1. `genesis` signs a PASETO v4.public token with Vault Transit and puts the PASERK ID (`k4.pid...`) in the token footer as `kid`.
2. `permesi` parses the footer `kid`, looks up the matching `k4.public...` key in the PASERK keyset, and verifies the signature.
3. `permesi` validates claims (`iss`, `aud`, `action`, `iat/exp`, TTL). If any check fails, the request is rejected.

### Keyset Behavior

- **Active KID**: `active_kid` is only used by `genesis` to choose the signing key. Verification always uses the token's footer `kid`.
- **Caching**: When configured with a PASERK URL, `permesi` caches `/paserk.json` (default TTL 5 minutes) and refreshes it on unknown `kid` with a cooldown. No per-request calls are made.
- **Offline Mode**: When configured with a local file or JSON string, verification is fully offline (no network fetches).

## User Authentication (OPAQUE + Zero Token)

All auth POSTs require a Genesis zero token (validated offline using the PASERK keyset).

```mermaid
sequenceDiagram
    autonumber
    participant U as User / Client
    participant G as Genesis (Edge)
    participant P as Permesi (Core)
    participant DB as Postgres

    Note over U, G: Zero token mint
    U->>G: Request zero token
    G-->>U: Zero token

    Note over U, P: OPAQUE login
    U->>P: Login start with zero token
    P->>P: Verify token (PASERK keyset)
    P-->>U: credential response + login_id

    U->>P: Login finish with zero token
    P->>P: Verify token (PASERK keyset)
    P->>P: OPAQUE finish
    P->>DB: Persist session
    P-->>U: 204 + Set-Cookie (session)

    Note over U, P: Session hydration
    U->>P: /v1/auth/session (cookie)
    P->>DB: Load session
    P-->>U: 200 session or 204
```
