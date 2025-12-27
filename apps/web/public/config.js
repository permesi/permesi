window.__PERMESI_CONFIG__ = window.__PERMESI_CONFIG__ || {};

if (!window.__PERMESI_CONFIG__.API_BASE_URL) {
  const host = window.location.hostname || "";
  window.__PERMESI_CONFIG__.API_BASE_URL = host.endsWith("permesi.com")
    ? "https://permesi.com"
    : "https://permesi.dev";
}
