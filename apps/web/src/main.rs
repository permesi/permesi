#[cfg(target_arch = "wasm32")]
mod app;
#[cfg(target_arch = "wasm32")]
#[path = "lib/mod.rs"]
mod app_lib;
#[cfg(target_arch = "wasm32")]
mod components;
#[cfg(target_arch = "wasm32")]
mod features;
#[cfg(target_arch = "wasm32")]
mod routes;

#[cfg(target_arch = "wasm32")]
use crate::app::App;
#[cfg(target_arch = "wasm32")]
use leptos::prelude::mount_to_body;
#[cfg(target_arch = "wasm32")]
pub fn main() {
    mount_to_body(App);
}

#[cfg(not(target_arch = "wasm32"))]
pub fn main() {}
