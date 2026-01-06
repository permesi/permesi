# Admin Elevation

Platform operators must elevate their session to access administrative routes. This flow ensures that powerful actions require a short-lived step-up token backed by Vault.

## The Flow

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

## Security Design

1. **Vault Step-up**: The operator provides a Vault token which is exchanged for a short-lived, signed PASETO admin token. The Vault token is never persisted or stored in the browser; it is only used once to mint the admin token.
2. **PASETO Admin Token**: Subsequent administrative requests use this token in the `Authorization: Bearer` header. The backend verifies the signature offline using its internal signing key.
3. **Memory Storage**: The admin token is stored in memory and is automatically cleared upon expiration or logout, ensuring no persistent administrative privileges.
4. **Rate Limiting**: The elevation endpoint is strictly rate-limited to 3 attempts per 10 minutes per user to protect against Vault token brute-forcing.