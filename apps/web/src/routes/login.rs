use crate::app_lib::AppError;
use crate::components::{Alert, AlertKind, AppShell, Button, Spinner};
use crate::features::auth::state::use_auth;
use crate::features::auth::types::LoginRequest;
use crate::features::auth::{client, crypto, token};
use leptos::ev::SubmitEvent;
use leptos::prelude::*;
use leptos_router::hooks::use_navigate;

#[derive(Clone)]
struct LoginInput {
    email: String,
    password: String,
}

#[component]
pub fn LoginPage() -> impl IntoView {
    let auth = use_auth();
    let navigate = use_navigate();
    let (email, set_email) = signal(String::new());
    let (password, set_password) = signal(String::new());
    let (error, set_error) = signal::<Option<AppError>>(None);

    let login_action = Action::new_local(move |input: &LoginInput| {
        let input = input.clone();
        async move {
            let token_value = token::fetch_admission_token().await?;
            let hashed_password = crypto::hash_password(&input.password);
            let request = LoginRequest {
                email: input.email,
                password: hashed_password,
                token: token_value,
            };
            client::login(&request).await
        }
    });

    Effect::new(move |_| {
        if let Some(result) = login_action.value().get() {
            match result {
                Ok(session) => {
                    auth.set_session(session);
                    navigate("/", Default::default());
                }
                Err(err) => set_error.set(Some(err)),
            }
        }
    });

    let on_submit = move |event: SubmitEvent| {
        event.prevent_default();
        set_error.set(None);

        let email_value = email.get_untracked().trim().to_string();
        let password_value = password.get_untracked();
        if email_value.is_empty() || password_value.trim().is_empty() {
            set_error.set(Some(AppError::Config(
                "Email and password are required.".to_string(),
            )));
            return;
        }

        login_action.dispatch(LoginInput {
            email: email_value,
            password: password_value,
        });
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
                        autocomplete="current-password"
                        required
                        on:input=move |event| set_password.set(event_target_value(&event))
                    />
                </div>
                <Button button_type="submit" disabled=login_action.pending()>
                    "Submit"
                </Button>
                {move || {
                    login_action
                        .pending()
                        .get()
                        .then_some(view! { <div class="mt-4"><Spinner /></div> })
                }}
                {move || {
                    error
                        .get()
                        .map(|err| {
                            view! {
                                <div class="mt-4">
                                    <Alert kind=AlertKind::Error message=err.to_string() />
                                </div>
                            }
                        })
                }}
            </form>
        </AppShell>
    }
}
