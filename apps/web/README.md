# permesi_web

CSR-only Leptos frontend built with Trunk. Outputs static assets for hosting on Cloudflare Pages.

## Commands

- `trunk serve --open`
- `trunk build --release`

Build output lands in `apps/web/dist`.

## Cloudflare Pages

- Build command: `trunk build --release`
- Output directory: `dist`

## API base URL configuration

This app reads the API base URL from either a runtime config object or a build-time env var.

Runtime (recommended for Pages):
- Edit `apps/web/public/config.js` to set `window.__PERMESI_CONFIG__.API_BASE_URL`.
- Defaults: `https://permesi.dev` for development hosts, `https://permesi.com` for production hosts.

Build-time:
- `PERMESI_API_BASE_URL=https://permesi.com trunk build --release`
- `PERMESI_API_BASE_URL=https://permesi.dev trunk serve`
- Build-time config overrides `config.js` if set.

If you use a non-default API origin, update `apps/web/public/_headers` to allow it in
`Content-Security-Policy` `connect-src`.

## Styling

Tailwind is not included. The current UI uses minimal custom CSS in `apps/web/styles.css`.
