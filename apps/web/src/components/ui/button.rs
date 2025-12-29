use leptos::prelude::*;

#[component]
pub fn Button(
    #[prop(optional)] button_type: Option<&'static str>,
    #[prop(optional, into, default = Signal::from(false))] disabled: Signal<bool>,
    children: Children,
) -> impl IntoView {
    let button_type = button_type.unwrap_or("button");

    view! {
        <button
            type=button_type
            class="text-white bg-blue-700 hover:bg-blue-800 focus:ring-4 focus:outline-none focus:ring-blue-300 font-medium rounded-lg text-sm w-full sm:w-auto px-5 py-2.5 text-center dark:bg-blue-600 dark:hover:bg-blue-700 dark:focus:ring-blue-800"
            class:cursor-not-allowed=move || disabled.get()
            class:opacity-70=move || disabled.get()
            disabled=move || disabled.get()
        >
            {children()}
        </button>
    }
}
