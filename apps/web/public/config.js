window.__PERMESI_CONFIG__ = window.__PERMESI_CONFIG__ || {};

const config = window.__PERMESI_CONFIG__;
const host = window.location.hostname || "";
const baseDomain = host.endsWith("permesi.com") ? "permesi.com" : "permesi.dev";

if (!config.API_HOST) {
  config.API_HOST = `https://api.${baseDomain}`;
}

if (!config.API_TOKEN_HOST) {
  config.API_TOKEN_HOST = `https://genesis.${baseDomain}`;
}

if (!config.API_BASE_URL) {
  config.API_BASE_URL = config.API_HOST;
}

if (!config.CLIENT_ID) {
  config.CLIENT_ID = "00000000-0000-0000-0000-000000000000";
}
