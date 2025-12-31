use crate::app_lib::AppError;
use crate::app_lib::config::AppConfig;
use crate::components::{Alert, AlertKind, AppShell, Button, Spinner};
use crate::features::auth::client;
use crate::features::auth::opaque::{OpaqueSuite, identifiers, ksf, normalize_email};
use crate::features::auth::state::use_auth;
use crate::features::auth::token;
use crate::features::auth::types::{
    OpaqueLoginFinishRequest, OpaqueLoginStartRequest, UserSession,
};
use base64::Engine;
use leptos::ev::SubmitEvent;
use leptos::prelude::*;
use leptos_router::hooks::use_navigate;
use opaque_ke::{ClientLogin, ClientLoginFinishParameters, CredentialResponse};
use rand::rngs::OsRng;

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
            let config = AppConfig::load();
            let client_id = normalize_email(&input.email);
            let server_id = config.opaque_server_id;

            let mut rng = OsRng;
            let start = ClientLogin::<OpaqueSuite>::start(&mut rng, input.password.as_bytes())
                .map_err(|_| AppError::Config("Unable to start secure login.".to_string()))?;
            let start_request = OpaqueLoginStartRequest {
                email: input.email.clone(),
                credential_request: base64::engine::general_purpose::STANDARD
                    .encode(start.message.serialize()),
            };
            let zero_token = token::fetch_zero_token().await?;
            let start_response = client::opaque_login_start(&start_request, &zero_token).await?;

            let response_bytes = base64::engine::general_purpose::STANDARD
                .decode(start_response.credential_response)
                .map_err(|_| AppError::Config("Invalid login response.".to_string()))?;
            let credential_response =
                CredentialResponse::<OpaqueSuite>::deserialize(&response_bytes).map_err(|_| {
                    AppError::Config("Unable to complete secure login.".to_string())
                })?;

            let ksf_params = ksf();
            let params = ClientLoginFinishParameters::new(
                None,
                identifiers(client_id.as_bytes(), server_id.as_bytes()),
                Some(&ksf_params),
            );
            let finish = start
                .state
                .finish(input.password.as_bytes(), credential_response, params)
                .map_err(|_| AppError::Config("Unable to complete secure login.".to_string()))?;

            let finish_request = OpaqueLoginFinishRequest {
                login_id: start_response.login_id,
                email: input.email.clone(),
                credential_finalization: base64::engine::general_purpose::STANDARD
                    .encode(finish.message.serialize()),
            };
            let zero_token = token::fetch_zero_token().await?;
            client::opaque_login_finish(&finish_request, &zero_token).await?;
            Ok(UserSession {
                user_id: client_id,
                access_token: String::new(),
            })
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
                            let message = format_error(&err);
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

fn format_error(err: &AppError) -> String {
    match err {
        AppError::Config(message) => message.clone(),
        _ => err.to_string(),
    }
}
