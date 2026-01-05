//! Login route that implements the client-side OPAQUE exchange. It keeps passwords
//! local, uses zero-token headers for permesi calls, and hydrates session state
//! via cookie-based auth while capturing the bearer token for future requests.
//!
//! Flow Overview: Start OPAQUE with the server, finish the exchange, then fetch
//! the session and redirect to the home route.

use crate::{
    app_lib::{AppError, config::AppConfig},
    components::{Alert, AlertKind, AppShell, Button, Spinner},
    features::auth::{
        client,
        opaque::{OpaqueSuite, identifiers, ksf, normalize_email},
        state::use_auth,
        token,
        types::{OpaqueLoginFinishRequest, OpaqueLoginStartRequest, UserSession},
    },
};
use base64::Engine;
use leptos::{ev::SubmitEvent, prelude::*};
use leptos_router::hooks::use_navigate;
use opaque_ke::{ClientLogin, ClientLoginFinishParameters, CredentialResponse};
use rand::rngs::OsRng;

#[derive(Clone)]
/// Captures login form input for the async action without borrowing signals.
struct LoginInput {
    email: String,
    password: String,
}

#[derive(Clone)]
struct LoginResult {
    session: UserSession,
    session_token: Option<String>,
}

/// Renders the login form and drives the OPAQUE login flow.
/// On success it fetches the session cookie and updates auth state.
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
            // Start OPAQUE locally so the password never leaves the browser.
            let start = ClientLogin::<OpaqueSuite>::start(&mut rng, input.password.as_bytes())
                .map_err(|_| AppError::Config("Unable to start secure login.".to_string()))?;
            let start_request = OpaqueLoginStartRequest {
                email: input.email.clone(),
                credential_request: base64::engine::general_purpose::STANDARD
                    .encode(start.message.serialize()),
            };
            // Zero tokens gate permesi auth calls and are separate from sessions.
            let zero_token = token::fetch_zero_token().await?;
            let start_response = client::opaque_login_start(&start_request, &zero_token).await?;

            // Decode the server's OPAQUE response before finishing the exchange.
            let response_bytes = base64::engine::general_purpose::STANDARD
                .decode(start_response.credential_response)
                .map_err(|_| AppError::Config("Invalid login response.".to_string()))?;
            let credential_response =
                CredentialResponse::<OpaqueSuite>::deserialize(&response_bytes).map_err(|_| {
                    AppError::Config("Unable to complete secure login.".to_string())
                })?;

            let ksf_params = ksf();
            // Bind identifiers and KSF params so the finish step is scoped correctly.
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
            // Finish login so the server can mint the session cookie.
            let session_token = client::opaque_login_finish(&finish_request, &zero_token).await?;
            // Hydrate auth state by fetching the session established via cookie or bearer token.
            let session = client::fetch_session(session_token.as_deref())
                .await?
                .ok_or_else(|| {
                    AppError::Config("Login succeeded but no session found.".to_string())
                })?;
            Ok(LoginResult {
                session,
                session_token,
            })
        }
    });

    Effect::new(move |_| {
        if let Some(result) = login_action.value().get() {
            match result {
                Ok(login) => {
                    auth.set_session(login.session);
                    if let Some(token) = login.session_token {
                        auth.set_session_token(token);
                    }
                    navigate("/", Default::default());
                }
                Err(err) => set_error.set(Some(err)),
            }
        }
    });

    let on_submit = move |event: SubmitEvent| {
        event.prevent_default();
        set_error.set(None);

        // Trim input before validation to avoid accidental whitespace failures.
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

/// Maps internal errors to user-facing strings without leaking details.
fn format_error(err: &AppError) -> String {
    match err {
        AppError::Config(message) => message.clone(),
        _ => err.to_string(),
    }
}
