use crate::components::{Alert, AlertKind, AppShell, Button};
use leptos::ev::SubmitEvent;
use leptos::prelude::*;

#[component]
pub fn SignUpPage() -> impl IntoView {
    let (email, set_email) = signal(String::new());
    let (password, set_password) = signal(String::new());
    let (confirm_password, set_confirm_password) = signal(String::new());
    let (error, set_error) = signal::<Option<String>>(None);

    let on_submit = move |event: SubmitEvent| {
        event.prevent_default();
        set_error.set(None);

        let email_value = email.get_untracked().trim().to_string();
        let password_value = password.get_untracked();
        let confirm_value = confirm_password.get_untracked();

        if email_value.is_empty()
            || password_value.trim().is_empty()
            || confirm_value.trim().is_empty()
        {
            set_error.set(Some(
                "Email and both password fields are required.".to_string(),
            ));
            return;
        }

        if password_value != confirm_value {
            set_error.set(Some("Passwords do not match.".to_string()));
            return;
        }

        set_error.set(Some("Sign up is not available yet.".to_string()));
    };

    view! {
        <AppShell>
            <form class="max-w-sm mx-auto" on:submit=on_submit>
                <div class="mb-5">
                    <label
                        class="block mb-2 text-sm font-medium text-gray-900 dark:text-white"
                        for="email"
                    >
                        "Your email"
                    </label>
                    <input
                        id="email"
                        type="email"
                        class="bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-blue-500 focus:border-blue-500 block w-full p-2.5 dark:bg-gray-700 dark:border-gray-600 dark:placeholder-gray-400 dark:text-white dark:focus:ring-blue-500 dark:focus:border-blue-500"
                        autocomplete="email"
                        placeholder="name@inbox.im"
                        required
                        on:input=move |event| set_email.set(event_target_value(&event))
                    />
                </div>
                <div class="mb-5">
                    <label
                        class="block mb-2 text-sm font-medium text-gray-900 dark:text-white"
                        for="password"
                    >
                        "Your password"
                    </label>
                    <input
                        id="password"
                        type="password"
                        class="bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-blue-500 focus:border-blue-500 block w-full p-2.5 dark:bg-gray-700 dark:border-gray-600 dark:placeholder-gray-400 dark:text-white dark:focus:ring-blue-500 dark:focus:border-blue-500"
                        autocomplete="new-password"
                        required
                        on:input=move |event| set_password.set(event_target_value(&event))
                    />
                </div>
                <div class="mb-5">
                    <label
                        class="block mb-2 text-sm font-medium text-gray-900 dark:text-white"
                        for="confirm_password"
                    >
                        "Confirm password"
                    </label>
                    <input
                        id="confirm_password"
                        type="password"
                        class="bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-blue-500 focus:border-blue-500 block w-full p-2.5 dark:bg-gray-700 dark:border-gray-600 dark:placeholder-gray-400 dark:text-white dark:focus:ring-blue-500 dark:focus:border-blue-500"
                        autocomplete="new-password"
                        required
                        on:input=move |event| {
                            set_confirm_password.set(event_target_value(&event));
                        }
                    />
                </div>
                <Button button_type="submit">"Submit"</Button>
                {move || {
                    error.get().map(|message| {
                        view! {
                            <div class="mt-4">
                                <Alert kind=AlertKind::Error message=message />
                            </div>
                        }
                    })
                }}
            </form>
        </AppShell>
    }
}
