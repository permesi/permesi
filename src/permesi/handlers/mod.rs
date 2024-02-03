pub mod health;
pub use self::health::health;

pub mod user_register;
pub use self::user_register::register;

pub mod user_login;
pub use self::user_login::login;

// common functions for the handlers
use crate::permesi;
use regex::Regex;
use reqwest::{Client, StatusCode};
use std::collections::HashMap;
use tracing::{error, instrument};
use ulid::Ulid;

pub fn valid_email(email: &str) -> bool {
    Regex::new(r"^[^@\s]+@[^@\s]+\.[^@\s]+$").map_or(false, |re| re.is_match(email))
}

pub fn valid_password(password: &str) -> bool {
    // length must be between 64 hex characters
    Regex::new(r"^[0-9a-fA-F]{64}$").map_or(false, |re| re.is_match(password))
}

#[instrument]
pub async fn verify_token(token: &str) -> bool {
    if Ulid::from_string(token).is_err() {
        return false;
    }

    let Ok(token_url) = std::env::var("PERMESI_TOKEN_URL") else {
        error!("PERMESI_TOKEN_URL not defined");
        return false;
    };

    let client = match Client::builder()
        .user_agent(permesi::APP_USER_AGENT)
        .build()
    {
        Ok(client) => client,
        Err(e) => {
            error!("Error creating reqwest client: {:?}", e);

            return false;
        }
    };

    let mut map = HashMap::new();
    map.insert("token", token);

    // check if the token is valid by sending a request to the token service
    // endpoint /verify
    match client
        .post(format!("{token_url}/verify"))
        .json(&map)
        .send()
        .await
    {
        Ok(response) => {
            if response.status() == StatusCode::ACCEPTED {
                true
            } else {
                error!("Token validation failed: {}", response.status());

                false
            }
        }
        Err(e) => {
            error!("Error validating token: {:?}", e);

            false
        }
    }
}
