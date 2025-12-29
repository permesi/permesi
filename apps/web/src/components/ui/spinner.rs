use leptos::prelude::*;

#[component]
pub fn Spinner() -> impl IntoView {
    view! {
        <div
            class="inline-block h-7 w-7 animate-spin rounded-full border-4 border-blue-200 border-t-blue-600"
            role="status"
            aria-live="polite"
            aria-label="Loading"
        ></div>
    }
}
