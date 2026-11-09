//! Clipboard access for public identifiers, with accessible feedback.
//!
//! The complete value is always rendered (wrapping instead of truncating) so it can be
//! inspected and selected even when the Clipboard API is unavailable. The compact variant
//! is an inline identifier with an icon-only button; success swaps the icon for a check
//! mark without changing the button's size, and failures are shown as visible text.

use super::{Icon, IconName, icon_size};
use gloo_timers::callback::Timeout;
use leptos::{prelude::*, task::spawn_local};
use wasm_bindgen_futures::JsFuture;

/// How long the success check mark replaces the copy icon.
const COPIED_MS: u32 = 2000;

/// Writes `text` to the clipboard and records the outcome in the shared signals.
async fn copy_text(
    text: String,
    status: RwSignal<String>,
    copied: RwSignal<bool>,
    failed: RwSignal<bool>,
    generation: RwSignal<u64>,
    attempt: u64,
) {
    let Some(window) = web_sys::window() else {
        status.set("Copy unavailable. Select the value to copy it.".to_owned());
        failed.set(true);
        return;
    };
    if !window.is_secure_context() {
        status.set("Copy unavailable. Select the value to copy it.".to_owned());
        failed.set(true);
        return;
    }
    let promise = window.navigator().clipboard().write_text(&text);
    let result = JsFuture::from(promise).await;
    if generation.try_get() != Some(attempt) {
        return;
    }
    if result.is_ok() {
        status.set("Copied.".to_owned());
        copied.set(true);
        Timeout::new(COPIED_MS, move || {
            if generation.try_get() == Some(attempt) {
                copied.try_set(false);
                status.try_set(String::new());
            }
        })
        .forget();
    } else {
        status.set("Copy failed. Select the value to copy it.".to_owned());
        failed.set(true);
    }
}

/// Reserves the longest feedback message at the current width, without duplicate accessible text.
#[component]
fn CopyFeedback(status: RwSignal<String>, failed: RwSignal<bool>) -> impl IntoView {
    view! {
        <p role="status" aria-live="polite"
            class=move || if failed.get() { "grid min-h-4 text-xs text-red-700 dark:text-red-300" } else { "grid min-h-4 text-xs text-gray-500 dark:text-gray-400" }>
            <span class="invisible col-start-1 row-start-1" aria-hidden="true">"Copy unavailable. Select the value to copy it."</span>
            <span class="col-start-1 row-start-1">{move || status.get()}</span>
        </p>
    }
}

/// Shows the complete public value and reports clipboard success or failure.
///
/// `label` names the value for assistive technology ("client ID" gives the button the
/// accessible name "Copy client ID"). `compact` renders a monospaced inline identifier
/// with an icon-only button instead of the labelled "Copy" button.
#[component]
pub fn CopyValue(
    #[prop(into)] value: String,
    label: &'static str,
    #[prop(optional)] compact: bool,
    #[prop(optional)] code_id: Option<&'static str>,
    #[prop(default = "Copy")] button_text: &'static str,
) -> impl IntoView {
    let text = StoredValue::new(value.clone());
    let status = RwSignal::new(String::new());
    let copied = RwSignal::new(false);
    let failed = RwSignal::new(false);
    let generation = RwSignal::new(0u64);
    let on_copy = move |_: web_sys::MouseEvent| {
        generation.update(|value| *value += 1);
        copied.set(false);
        failed.set(false);
        status.set(String::new());
        spawn_local(copy_text(
            text.get_value(),
            status,
            copied,
            failed,
            generation,
            generation.get_untracked(),
        ));
    };
    let aria_label = format!("Copy {label}");
    let icon = move || {
        if copied.get() {
            view! { <Icon name=IconName::Check size=icon_size::INLINE class="text-green-600 dark:text-green-400" /> }
                .into_any()
        } else {
            view! { <Icon name=IconName::Copy size=icon_size::INLINE /> }.into_any()
        }
    };
    if compact {
        // Bound the tail for unsegmented technical IDs; UUIDs retain their final chunk.
        let split = value
            .rfind(['-', ' ', '/'])
            .map_or(0, |index| index + 1)
            .max(
                value
                    .char_indices()
                    .rev()
                    .nth(11)
                    .map_or(0, |(index, _)| index),
            );
        let mut prefix = value;
        let suffix = prefix.split_off(split);
        return view! {
            <div class="copy-value min-w-0 space-y-1">
                <div class="copy-value-content min-w-0">
                    <code class="break-all font-mono text-sm" title=text.get_value()>{prefix}<span class="inline-flex max-w-full items-center gap-1.5 align-middle"><span class="min-w-0 break-all">{suffix}</span>
                        <button type="button" aria-label=aria_label.clone() title=aria_label
                            class="inline-flex h-6 w-6 shrink-0 cursor-pointer items-center justify-center rounded text-gray-400 hover:bg-gray-100 hover:text-gray-700 focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:outline-none dark:hover:bg-gray-700 dark:hover:text-gray-200"
                            on:click=on_copy>{icon}</button>
                    </span></code>
                </div>
                <CopyFeedback status failed />
            </div>
        }
        .into_any();
    }
    view! {
        <div class="copy-value min-w-0 space-y-1">
            <div class="copy-value-content inline-flex max-w-full flex-wrap items-start gap-1.5">
                <code id=code_id class="min-w-0 break-all text-sm">{value}</code>
                <button type="button" aria-label=aria_label.clone() title=aria_label
                    class="inline-flex shrink-0 cursor-pointer items-center gap-1.5 rounded border border-gray-300 px-2 py-1 text-xs hover:bg-gray-100 focus-visible:ring-2 focus-visible:ring-blue-500 dark:border-gray-600 dark:hover:bg-gray-700"
                    on:click=on_copy>{icon}{button_text}</button>
            </div>
            <CopyFeedback status failed />
        </div>
    }
    .into_any()
}
