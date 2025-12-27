# permesi_web

CSR-only Leptos frontend built with Trunk. Outputs static assets for hosting on Cloudflare Pages.

## Commands

- `trunk serve --open`
- `trunk build --release`

Build output lands in `apps/web/dist`.

## Local ports

- `web` (Trunk): `http://localhost:8080`
- `genesis`: `http://localhost:8000`
- `permesi`: `http://localhost:8001`

Local overrides:
- `PERMESI_API_HOST=http://localhost:8001`
- `PERMESI_API_TOKEN_HOST=http://localhost:8000`
- `PERMESI_CLIENT_ID=00000000-0000-0000-0000-000000000000`

## Cloudflare Pages

- Build command: `trunk build --release`
- Output directory: `dist`

## API base URL configuration

This app reads the API base URL from either a runtime config object or a build-time env var.

Runtime (recommended for Pages):
- Edit `apps/web/public/config.js` to set `window.__PERMESI_CONFIG__` values:
  - `API_HOST` (e.g. `https://api.permesi.dev`)
  - `API_TOKEN_HOST` (e.g. `https://genesis.permesi.dev`)
  - `CLIENT_ID` (UUID for the admission mint)
- Defaults: `api/genesis.permesi.dev` for development hosts, `api/genesis.permesi.com` for production hosts.

Build-time:
- `PERMESI_API_HOST=https://api.permesi.com PERMESI_API_TOKEN_HOST=https://genesis.permesi.com trunk build --release`
- `PERMESI_API_HOST=https://api.permesi.dev PERMESI_API_TOKEN_HOST=https://genesis.permesi.dev trunk serve`
- `PERMESI_CLIENT_ID=...` overrides the client ID if set.
- `PERMESI_API_BASE_URL` is still supported for backwards compatibility and maps to `API_HOST`.
- Build-time config overrides `config.js` if set.

If you use a non-default API origin, update `apps/web/public/_headers` to allow it in
`Content-Security-Policy` `connect-src`.

## Styling

Tailwind is not included. The current UI uses minimal custom CSS in `apps/web/styles.css`.
