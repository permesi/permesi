// Public runtime config for the Permesi web UI.
// Replace values here to override the build-time defaults without rebuilding.
// Do not put secrets in this file.
//
// Expected keys:
// - api_base_url (string)
// - token_base_url (string)
// - client_id (string)
// - opaque_server_id (string)
//
// Example:
// window.PERMESI_CONFIG = {
//   api_base_url: "https://api.permesi.dev",
//   token_base_url: "https://genesis.permesi.dev",
//   client_id: "00000000-0000-0000-0000-000000000000",
//   opaque_server_id: "api.permesi.dev",
// };
window.PERMESI_CONFIG = {
  api_base_url: "",
  token_base_url: "",
  client_id: "",
  opaque_server_id: "",
};
