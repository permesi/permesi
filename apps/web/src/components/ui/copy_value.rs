//! Clipboard access for public configuration identifiers, with accessible feedback.

use leptos::{prelude::*, task::spawn_local};
use wasm_bindgen_futures::JsFuture;

/// Shows the complete public value and reports clipboard success or failure.
#[component]
pub fn CopyValue(value: String) -> impl IntoView {
    let text = StoredValue::new(value.clone());
    let status = RwSignal::new(String::new());
    view! {
        <div class="min-w-0 space-y-1">
            <div class="flex items-start gap-2">
                <code class="min-w-0 break-all text-sm">{value}</code>
                <button type="button" aria-label="Copy client ID"
                    class="shrink-0 cursor-pointer rounded border border-gray-300 px-2 py-1 text-xs hover:bg-gray-100 focus:ring-2 focus:ring-blue-500 dark:border-gray-600 dark:hover:bg-gray-700"
                    on:click=move |_| {
                        spawn_local(async move {
                            let Some(window) = web_sys::window() else { status.set("Copy unavailable.".to_owned()); return; };
                            if !window.is_secure_context() {
                                status.set("Copy unavailable. Select the value to copy it.".to_owned());
                                return;
                            }
                            let promise = window.navigator().clipboard().write_text(&text.get_value());
                            status.set(if JsFuture::from(promise).await.is_ok() { "Copied." } else { "Copy failed. Select the value to copy it." }.to_owned());
                        });
                    }>"Copy"</button>
            </div>
            <p aria-live="polite" class="text-xs text-gray-500 dark:text-gray-400">{move || status.get()}</p>
        </div>
    }
}
