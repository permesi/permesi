//! OAuth configuration contracts shared by the browser and native tests.
//!
//! Paths bind every request to an application ancestry. DTOs mirror the committed
//! API, and edit helpers preserve exact scope and URI values without interpreting
//! them as internal administrator permissions or user grants.

#[path = "model.rs"]
pub mod model;
#[path = "paths.rs"]
pub mod paths;
#[path = "scope.rs"]
pub mod scope;
#[path = "types.rs"]
pub mod types;

#[cfg(test)]
mod tests;
