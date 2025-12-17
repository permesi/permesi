# permesi

**permesi** Identity and Access Management

[![crates.io](https://img.shields.io/crates/v/permesi.svg)](https://crates.io/crates/permesi)
[![Test & Build](https://github.com/permesi/permesi/actions/workflows/build.yml/badge.svg)](https://github.com/permesi/permesi/actions/workflows/build.yml)
[![codecov](https://codecov.io/gh/permesi/permesi/graph/badge.svg?token=ODC4S2YHPF)](https://codecov.io/gh/permesi/permesi)


<img src="permesi.svg" height="400">

## Architecture

permesi employs a **Split-Trust Architecture** to separate network noise from core identity logic.

### The Components

#### 1. `genesis` (The Edge / "The Bouncer")
* **Role:** Public-facing edge service.
* **Responsibility:** Handles raw TCP/HTTP connections, enforces strict rate limits, performs PoW (Proof of Work) challenges for abuse prevention, and sanitizes inputs.
* **Output:** Issues a short-lived, cryptographically signed **Admission Token**.
* **State:** Stateless / Ephemeral.

#### 2. `permesi` (The Core / "The Authority")
* **Role:** The OIDC Authority.
* **Responsibility:** Validates User Credentials and OIDC flows.
* **Trust Model:** Verifies **Admission Tokens** from `genesis` *offline* (using public key cryptography) without needing runtime API calls to the edge.
* **Output:** Issues standard OIDC Access/ID Tokens (JWTs).

#### 3. Database
* **Role:** System of Record.
* **Usage:** Primarily for **Audit Logs** and **Revocation Lists**. It is **not** required for the hot-path verification of Admission Tokens, ensuring high availability even during DB latency spikes.

---

## The Authentication Flow

```mermaid
sequenceDiagram
    participant U as User / Client
    participant G as Genesis (Edge)
    participant P as Permesi (Core)
    participant DB as Audit DB

    Note over U, G: 1. Admission Phase
    U->>G: Connection Request
    G->>G: Check Rate Limits / Abuse
    G-->>U: Signed Admission Token (Short-lived)

    Note over U, P: 2. Authorization Phase
    U->>P: Login (Creds) + Admission Token
    P->>P: Verify Admission Sig (Offline)
    alt Invalid Admission
        P-->>U: 401 Unauthorized (Drop)
    else Valid Admission
        P->>DB: Read Hash (Async/Cached)
        P->>P: Verify Credentials
        P-->>U: OIDC Access Token (JWT)
        P->>DB: Async Audit Log
    end
```
