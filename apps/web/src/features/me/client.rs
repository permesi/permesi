//! Client helpers for current-user endpoints.

use crate::{
    app_lib::{AppError, get_json_with_credentials},
    features::me::types::MeProfile,
};

/// Fetch the authenticated user's profile.
pub async fn fetch_me() -> Result<MeProfile, AppError> {
    get_json_with_credentials("/v1/me").await
}
