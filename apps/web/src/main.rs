//! Frontend entrypoint for the wasm build. This module mounts the CSR app only when
//! targeting `wasm32`, while the native `main` stays empty to keep tooling and build
//! pipelines happy. A single mount point keeps DOM ownership predictable and avoids
//! duplicate roots. It handles no secrets; failures surface as a blank page with
//! console errors.

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

/// Mounts the root `App` into the document body for wasm builds.
#[cfg(target_arch = "wasm32")]
pub fn main() {
    mount_to_body(App);
}

/// No-op entrypoint for non-wasm targets to satisfy tooling and CI builds.
#[cfg(not(target_arch = "wasm32"))]
pub fn main() {}
