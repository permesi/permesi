#[cfg(any(target_arch = "wasm32", test))]
mod config;

#[cfg(target_arch = "wasm32")]
mod app {
    use super::config::AppConfig;
    use gloo_net::http::Request;
    use leptos::ev::SubmitEvent;
    use leptos::prelude::*;
    use leptos::task::spawn_local;
    use serde::Serialize;
    use wasm_bindgen::prelude::wasm_bindgen;

    #[derive(Clone, Debug)]
    enum SubmitStatus {
        Idle,
        Working,
        Success(String),
        Error(String),
    }

    #[derive(Serialize)]
    struct LoginRequest<'a> {
        email: &'a str,
        password: &'a str,
    }

    #[component]
    fn App() -> impl IntoView {
        let config = AppConfig::load();

        view! {
            <>
                <NavBar />
                <br />
                <div class="container mx-auto p-4">
                    <SignIn config=config />
                </div>
            </>
        }
    }

    #[component]
    fn SignIn(config: Result<AppConfig, String>) -> impl IntoView {
        let (email, set_email) = signal(String::new());
        let (password, set_password) = signal(String::new());
        let (status, set_status) = signal(SubmitStatus::Idle);
        // TODO: Keep tokens in memory only; avoid localStorage or sessionStorage.
        let (_session_token, set_session_token) = signal::<Option<String>>(None);
        let config_error = config.clone().err();

        let on_submit = move |event: SubmitEvent| {
            event.prevent_default();
            if matches!(status.get_untracked(), SubmitStatus::Working) {
                return;
            }

            let config = config.clone();
            let email = email.get_untracked();
            let password = password.get_untracked();
            let set_status = set_status.clone();
            let set_session_token = set_session_token.clone();

            set_status.set(SubmitStatus::Working);
            set_session_token.set(None);

            spawn_local(async move {
                let (base_url, _token_host, _client_id) = match config {
                    Ok(config) => (config.api_host, config.token_host, config.client_id),
                    Err(err) => {
                        set_status.set(SubmitStatus::Error(err));
                        return;
                    }
                };

                if email.trim().is_empty() || password.is_empty() {
                    set_status.set(SubmitStatus::Error(
                        "Email and password are required.".to_string(),
                    ));
                    return;
                }

                // TODO: Hash the password client-side if the API requires it.
                let payload = LoginRequest {
                    email: email.trim(),
                    password: password.as_str(),
                };
                let body = match serde_json::to_string(&payload) {
                    Ok(body) => body,
                    Err(err) => {
                        set_status.set(SubmitStatus::Error(format!(
                            "Failed to serialize request: {err}"
                        )));
                        return;
                    }
                };

                let url = format!("{}/auth/login", base_url.trim_end_matches('/'));
                let request = Request::post(&url).header("Content-Type", "application/json");
                let request = match request.body(body) {
                    Ok(request) => request,
                    Err(err) => {
                        set_status.set(SubmitStatus::Error(format!(
                            "Failed to build request body: {err}"
                        )));
                        return;
                    }
                };
                let response = request.send().await;

                match response {
                    Ok(response) => {
                        let status_code = response.status();
                        let text = response.text().await.unwrap_or_default();
                        if response.ok() {
                            set_status.set(SubmitStatus::Success("Signed in.".to_string()));
                            if !text.is_empty() {
                                set_session_token.set(Some(text));
                            }
                        } else if text.is_empty() {
                            set_status.set(SubmitStatus::Error(format!(
                                "Request failed with status {status_code}."
                            )));
                        } else {
                            set_status.set(SubmitStatus::Error(format!(
                                "Request failed with status {status_code}: {text}"
                            )));
                        }
                    }
                    Err(err) => {
                        set_status.set(SubmitStatus::Error(format!("Network error: {err}")));
                    }
                }
            });
        };

        let status_line = move || match status.get() {
            SubmitStatus::Idle => None,
            SubmitStatus::Working => Some((
                "Signing in...".to_string(),
                "text-sm text-gray-500 mt-4".to_string(),
            )),
            SubmitStatus::Success(message) => {
                Some((message, "text-sm text-green-600 mt-4".to_string()))
            }
            SubmitStatus::Error(message) => {
                Some((message, "text-sm text-red-600 mt-4".to_string()))
            }
        };

        view! {
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
                        autocomplete="email"
                        required=true
                        placeholder="name@inbox.im"
                        class="bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-blue-500 focus:border-blue-500 block w-full p-2.5 dark:bg-gray-700 dark:border-gray-600 dark:placeholder-gray-400 dark:text-white dark:focus:ring-blue-500 dark:focus:border-blue-500"
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
                        autocomplete="current-password"
                        required=true
                        class="bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-blue-500 focus:border-blue-500 block w-full p-2.5 dark:bg-gray-700 dark:border-gray-600 dark:placeholder-gray-400 dark:text-white dark:focus:ring-blue-500 dark:focus:border-blue-500"
                        on:input=move |event| set_password.set(event_target_value(&event))
                    />
                </div>
                <button
                    type="submit"
                    class="text-white bg-blue-700 hover:bg-blue-800 focus:ring-4 focus:outline-none focus:ring-blue-300 font-medium rounded-lg text-sm w-full sm:w-auto px-5 py-2.5 text-center dark:bg-blue-600 dark:hover:bg-blue-700 dark:focus:ring-blue-800"
                    disabled=move || matches!(status.get(), SubmitStatus::Working)
                >
                    "Submit"
                </button>
                {config_error.clone().map(|message| {
                    view! { <p class="text-sm text-red-600 mt-4">{message}</p> }
                })}
                {move || {
                    status_line()
                        .map(|(message, class)| view! { <p class=class>{message}</p> })
                }}
            </form>
        }
    }

    #[component]
    fn NavBar() -> impl IntoView {
        let (open, set_open) = signal(false);
        let toggle = move |_| set_open.update(|value| *value = !*value);
        let menu_class = move || {
            if open.get() {
                "w-full md:block md:w-auto"
            } else {
                "hidden w-full md:block md:w-auto"
            }
        };

        view! {
            <nav class="border-gray-200 dark:bg-gray-900">
                <div class="max-w-screen-xl flex flex-wrap items-center justify-between mx-auto p-4">
                    <a class="flex items-center space-x-3 rtl:space-x-reverse" href="/">
                        <img class="h-8" src="/logo.svg" alt="permesi" />
                        <span class="text-1xl font-semibold whitespace-nowrap dark:text-white">
                            "Permesi"
                        </span>
                    </a>
                    <button
                        type="button"
                        class="inline-flex items-center p-2 w-10 h-10 justify-center text-sm text-gray-500 rounded-lg md:hidden hover:bg-gray-100 focus:outline-none focus:ring-2 focus:ring-gray-200 dark:text-gray-400 dark:hover:bg-gray-700 dark:focus:ring-gray-600"
                        aria-controls="navbar-default"
                        aria-expanded=move || if open.get() { "true" } else { "false" }
                        on:click=toggle
                    >
                        <span class="sr-only">"Open main menu"</span>
                        <svg
                            class="w-5 h-5"
                            aria-hidden="true"
                            xmlns="http://www.w3.org/2000/svg"
                            fill="none"
                            viewBox="0 0 17 14"
                        >
                            <path
                                stroke="currentColor"
                                stroke-linecap="round"
                                stroke-linejoin="round"
                                stroke-width="2"
                                d="M1 1h15M1 7h15M1 13h15"
                            />
                        </svg>
                    </button>
                    <div id="navbar-default" class=menu_class>
                        <ul class="font-medium flex flex-col p-4 md:p-0 mt-4 border border-gray-100 rounded-lg bg-gray-50 md:flex-row md:space-x-8 rtl:space-x-reverse md:mt-0 md:border-0 md:bg-white dark:bg-gray-800 md:dark:bg-gray-900 dark:border-gray-700">
                            <li>
                                <a
                                    class="block py-2 px-3 text-gray-900 rounded hover:bg-gray-100 md:hover:bg-transparent md:border-0 md:hover:text-blue-700 md:p-0 dark:text-white md:dark:hover:text-blue-500 dark:hover:bg-gray-700 dark:hover:text-white md:dark:hover:bg-transparent"
                                    href="/signin"
                                >
                                    "Sign In"
                                </a>
                            </li>
                        </ul>
                    </div>
                </div>
            </nav>
        }
    }

    #[wasm_bindgen(start)]
    pub fn main() {
        mount_to_body(App);
    }
}

#[cfg(target_arch = "wasm32")]
pub use app::main;

#[cfg(not(target_arch = "wasm32"))]
pub fn main() {}
