//! Native modal using the console's existing card styles. The browser traps focus,
//! handles Escape, and restores focus; pending mutations block dismissal.

use leptos::prelude::*;

/// Opens a named modal with native keyboard semantics; busy actions prevent dismissal.
#[component]
pub fn Dialog(
    #[prop(into)] id: String,
    title: &'static str,
    open: RwSignal<bool>,
    #[prop(into)] busy: Signal<bool>,
    children: Children,
) -> impl IntoView {
    let dialog = NodeRef::<leptos::html::Dialog>::new();
    let title_id = format!("{id}-title");
    Effect::new(move |_| {
        if let Some(node) = dialog.get() {
            if open.get() && !node.open() {
                let _ = node.show_modal();
            } else if !open.get() && node.open() {
                node.close();
            }
        }
    });
    view! {
        <dialog node_ref=dialog id=id aria-labelledby=title_id.clone()
            on:cancel=move |ev: leptos::ev::Event| { if busy.get_untracked() { ev.prevent_default(); } else { open.set(false); } }
            on:close=move |_| {
                // Native close events are queued. Ignore an earlier opening's
                // event if the dialog has already been opened again.
                if dialog.get_untracked().is_some_and(|node| node.open()) { return; }
                if busy.get_untracked() {
                    // Repeated Escape can force a non-cancelable browser close.
                    // Keep the action and its eventual error visible until it settles.
                    if let Some(node) = dialog.get_untracked() { let _ = node.show_modal(); }
                } else { open.set(false); }
            }
            class="inset-0 m-auto w-[calc(100%-2rem)] max-w-lg max-h-[90vh] overflow-y-auto rounded-xl border border-gray-200 bg-white p-6 text-gray-900 shadow-xl backdrop:bg-black/50 dark:border-gray-700 dark:bg-gray-800 dark:text-white">
            <div class="mb-4 flex items-center justify-between gap-4">
                <h2 id=title_id.clone() class="text-lg font-semibold">{title}</h2>
                <button type="button" aria-label="Close dialog" disabled=move || busy.get()
                    class="cursor-pointer rounded p-1 text-gray-500 hover:bg-gray-100 focus:ring-2 focus:ring-blue-500 disabled:opacity-50 dark:hover:bg-gray-700"
                    on:click=move |_| open.set(false)>"✕"</button>
            </div>
            {children()}
        </dialog>
    }
}
