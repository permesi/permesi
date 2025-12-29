use leptos::prelude::*;

#[derive(Clone, Copy)]
pub enum AlertKind {
    Error,
}

#[component]
pub fn Alert(kind: AlertKind, message: String) -> impl IntoView {
    let class = match kind {
        AlertKind::Error => {
            "rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700 dark:border-red-400 dark:bg-red-900/30 dark:text-red-200"
        }
    };

    view! { <div class=class role="alert">{message}</div> }
}
