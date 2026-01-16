use crate::cli::globals::GlobalArgs;
use anyhow::Result;
use tracing::instrument;

/// Get DB credentials from Vault
/// # Errors
/// Returns an error if the Vault request fails, Vault returns a non-success status, or the response is missing expected fields.
#[instrument(skip(globals))]
pub async fn database_creds(globals: &mut GlobalArgs) -> Result<()> {
    let creds = vault_client::database_creds(
        crate::APP_USER_AGENT,
        &globals.vault_url,
        &globals.vault_token,
        "/v1/database/creds/permesi",
    )
    .await?;

    globals.vault_db_lease_id = creds.lease_id;
    globals.vault_db_lease_duration = creds.lease_duration;
    globals.vault_db_username = creds.username;
    globals.vault_db_password = creds.password;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::database_creds;
    use crate::cli::globals::GlobalArgs;
    use anyhow::Result;
    use secrecy::{ExposeSecret, SecretString};
    use serde_json::json;
    use std::net::TcpListener;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn can_bind_localhost() -> bool {
        TcpListener::bind("127.0.0.1:0").is_ok()
    }

    #[tokio::test]
    async fn database_creds_updates_globals() -> Result<()> {
        if !can_bind_localhost() {
            eprintln!("Skipping test: cannot bind localhost");
            return Ok(());
        }
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1/database/creds/permesi"))
            .and(header("X-Vault-Token", "vault-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "lease_id": "lease-123",
                "lease_duration": 55,
                "data": {"username": "user", "password": "pass"}
            })))
            .mount(&server)
            .await;

        let mut globals = GlobalArgs::new(server.uri());
        globals.set_token(SecretString::from("vault-token".to_string()));

        database_creds(&mut globals).await?;

        assert_eq!(globals.vault_db_lease_id, "lease-123");
        assert_eq!(globals.vault_db_lease_duration, 55);
        assert_eq!(globals.vault_db_username, "user");
        assert_eq!(globals.vault_db_password.expose_secret(), "pass");
        Ok(())
    }
}
