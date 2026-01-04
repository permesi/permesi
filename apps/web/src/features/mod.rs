//! Domain-level frontend features (auth, users) and their shared logic. Routes
//! import these modules to keep view code focused while keeping security and API
//! handling in dedicated feature areas.

pub(crate) mod auth;
pub(crate) mod me;
pub(crate) mod users;
