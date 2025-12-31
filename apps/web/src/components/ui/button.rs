use leptos::ev::MouseEvent;
use leptos::prelude::*;

#[component]
pub fn Button(
    #[prop(optional)] button_type: Option<&'static str>,
    #[prop(optional, into, default = Signal::from(false))] disabled: Signal<bool>,
    #[prop(optional, into)] on_click: Option<Callback<MouseEvent>>,
    children: Children,
) -> impl IntoView {
    let button_type = button_type.unwrap_or("button");
    let on_click = on_click.unwrap_or_else(|| Callback::new(|_: MouseEvent| ()));

    view! {
        <button
            type=button_type
            class="text-white bg-blue-700 hover:bg-blue-800 focus:ring-4 focus:outline-none focus:ring-blue-300 font-medium rounded-lg text-sm w-full sm:w-auto px-5 py-2.5 text-center dark:bg-blue-600 dark:hover:bg-blue-700 dark:focus:ring-blue-800"
            class:cursor-not-allowed=move || disabled.get()
            class:opacity-70=move || disabled.get()
            disabled=move || disabled.get()
            on:click=move |event| on_click.run(event)
        >
            {children()}
        </button>
    }
}
