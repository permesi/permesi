//! Authenticator settings and password proof for removal; the server enforces current session authority.
//!
//! Flow Overview: The section collects browser-local input, completes the existing
//! authentication ceremony and calls its session-authenticated mutation API.

use super::MfaAuthInput;
use crate::{
    app_lib::{AppError, theme::Theme},
    components::{Alert, AlertKind, Spinner},
    features::auth::{client as auth_client, opaque::reauthenticate, state::use_auth},
    routes::paths,
};
use leptos::{ev::SubmitEvent, prelude::*};
use leptos_router::hooks::use_navigate;

/// Owns authenticator settings and rechecks current session authority on removal.
#[component]
pub(super) fn AuthenticatorSection(
    email: StoredValue<String>,
    enabled: bool,
    totp_enabled: bool,
    profile: LocalResource<Result<crate::features::me::types::MeProfile, AppError>>,
) -> impl IntoView {
    let auth = use_auth();
    // Delete MFA signals
    let (show_delete_totp_form, set_show_delete_totp_form) = signal(false);
    let (delete_password, set_delete_password) = signal(String::new());

    // Derived security status from profile
    let disable_totp_action = Action::new_local(move |input: &MfaAuthInput| {
        let input = input.clone();
        async move {
            reauthenticate(&input.email, input.password).await?;

            // 2. Call disable endpoint
            auth_client::mfa_totp_disable().await
        }
    });

    Effect::new(move |_| {
        if let Some(Ok(())) = disable_totp_action.value().get() {
            set_show_delete_totp_form.set(false);
            set_delete_password.set(String::new());
            profile.refetch();
            auth.refresh_session();
        }
    });

    view! {
                                        <Show when=move || enabled>
                                            <div class="px-6 py-4 space-y-2">
                                                <div class="group">
                                                    <div class=Theme::LIST_ITEM_FLAT>
                                                        <div class="flex items-center space-x-3">
                                                            <span class=Theme::ICON_SMALL>
                                                                "smartphone"
                                                            </span>
                                                            <span class="text-sm text-gray-700 dark:text-gray-300 font-medium">
                                                                "Authenticator app"
                                                            </span>
                                                        </div>
                                                        <div class="flex items-center space-x-4">
                                                            <Show when=move || totp_enabled>
                                                                {authenticator_menu(set_show_delete_totp_form)}
                                                            </Show>

                                                            <Show when=move || !totp_enabled>
                                                                {
                                                                    let navigate = use_navigate();
                                                                    view! {
                                                                        <button
                                                                            on:click=move |_| navigate(paths::MFA_SETUP, leptos_router::NavigateOptions::default())
                                                                            class="text-sm font-medium text-gray-700 dark:text-gray-200 bg-white dark:bg-gray-900 border border-gray-300 dark:border-gray-600 rounded-md px-3 py-1.5 hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors cursor-pointer"
                                                                        >
                                                                            "Add"
                                                                        </button>
                                                                    }
                                                                }
                                                            </Show>
                                                        </div>
                                                    </div>
                                                </div>

                                                <Show when=move || show_delete_totp_form.get()>
                                                    <div class="mt-4">
                                                        {removal_form(RemovalForm { email, delete_password, set_delete_password, set_show_delete_totp_form, disable_totp_action })}
                                                    </div>
                                                </Show>
                                            </div>
                                        </Show>

    }
}

#[derive(Clone, Copy)]
struct RemovalForm {
    email: StoredValue<String>,
    delete_password: ReadSignal<String>,
    set_delete_password: WriteSignal<String>,
    set_show_delete_totp_form: WriteSignal<bool>,
    disable_totp_action: Action<MfaAuthInput, Result<(), AppError>>,
}

/// Renders the confirmation form using only its owning section's state.
fn removal_form(state: RemovalForm) -> impl IntoView {
    let RemovalForm {
        email,
        delete_password,
        set_delete_password,
        set_show_delete_totp_form,
        disable_totp_action,
    } = state;
    view! {
    <form
                                                                class="space-y-4 max-w-md bg-red-50 dark:bg-red-900/10 p-4 rounded-lg border border-red-100 dark:border-red-900/30"
                                                                on:submit=move |event: SubmitEvent| {
                                                                    event.prevent_default();
                                                                    let password = delete_password.get_untracked();
                                                                    if password.trim().is_empty() {
                                                                        return;
                                                                    }
                                                                    disable_totp_action.dispatch(MfaAuthInput {
                                                                        email: email.get_value(),
                                                                        password,
                                                                    });
                                                                }
                                                            >
                                                                <div class="flex items-start space-x-3 mb-2">
                                                                    <span class="material-symbols-outlined text-red-600 dark:text-red-400">"warning"</span>
                                                                    <p class="text-sm text-red-800 dark:text-red-200 font-medium">
                                                                        "Confirm removal of Authenticator app"
                                                                    </p>
                                                                </div>
                                                                <p class="text-xs text-red-700 dark:text-red-300 mb-4">
                                                                    "This will disable two-factor authentication for your account. Please enter your password to confirm."
                                                                </p>
                                                                <div>
                                                                    <label class="block mb-1 text-xs font-medium text-red-900 dark:text-red-200" for="delete_password">
                                                                        "Password"
                                                                    </label>
                                                                    <input
                                                                        id="delete_password"
                                                                        type="password"
                                                                        class="bg-white border border-red-200 text-gray-900 text-sm rounded-lg focus:ring-red-500 focus:border-red-500 block w-full p-2 dark:bg-gray-800 dark:border-red-900/50 dark:text-white"
                                                                        required
                                                                        on:input=move |event| set_delete_password.set(event_target_value(&event))
                                                                    />
                                                                </div>
                                                                <div class="pt-2 flex items-center gap-3">
                                                                    <button
                                                                        type="submit"
                                                                        disabled=disable_totp_action.pending()
                                                                        class="px-4 py-2 bg-red-600 hover:bg-red-700 text-white text-sm font-medium rounded-lg transition-colors disabled:opacity-50 shadow-sm cursor-pointer"
                                                                    >
                                                                        "Remove method"
                                                                    </button>
                                                                    <button
                                                                        type="button"
                                                                        on:click=move |_| set_show_delete_totp_form.set(false)
                                                                        class="px-4 py-2 text-gray-700 dark:text-gray-200 text-sm font-medium rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-900 hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors cursor-pointer"
                                                                    >
                                                                        "Cancel"
                                                                    </button>
                                                                    {move || {
                                                                        disable_totp_action
                                                                            .pending()
                                                                            .get()
                                                                            .then_some(view! { <Spinner /> })
                                                                    }}
                                                                </div>
                                                                {move || {
                                                                    disable_totp_action
                                                                        .value()
                                                                        .get()
                                                                        .and_then(std::result::Result::err)
                                                                        .map(|err| {
                                                                            view! { <div class="mt-4"><Alert kind=AlertKind::Error message=err.to_string() /></div> }
                                                                        })
                                                                }}
                                                            </form>
    }
}

/// Opens factor edit/removal controls; mutations still require server-side proof.
fn authenticator_menu(set_show_delete_totp_form: WriteSignal<bool>) -> impl IntoView {
    view! { <div class="relative inline-block text-left">
        {
            let (show_menu, set_show_menu) = signal(false);
            view! {
                    <span
                        class="text-slate-300 hover:text-slate-600 transition-colors cursor-pointer"
                        role="button"
                        tabindex="0"
                        aria-label="Authenticator settings"
                        on:click=move |ev| {
                            ev.stop_propagation();
                            set_show_menu.update(|v| *v = !*v);
                        }
                        on:keydown=move |event| {
                            if event.key() == "Enter" || event.key() == " " {
                                set_show_menu.update(|v| *v = !*v);
                            }
                        }
                    >
                        <span class="material-symbols-outlined text-sm" aria-hidden="true">"settings"</span>
                    </span>

                <Show when=move || show_menu.get()>
                    <div
                        class="absolute right-0 z-20 mt-2 w-48 origin-top-right rounded-md bg-white dark:bg-gray-800 shadow-lg ring-1 ring-black/5 focus:outline-none border border-gray-100 dark:border-gray-700"
                        on:click=move |ev| ev.stop_propagation()
                        on:mouseleave=move |_| set_show_menu.set(false)
                    >
                        <div class="py-1">
                            <leptos_router::components::A
                                href={paths::MFA_SETUP}
                                {..}
                                on:click=move |_| set_show_menu.set(false)
                                class="flex w-full items-center px-4 py-2 text-sm text-gray-700 dark:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-700 cursor-pointer"
                            >
                                <span class="material-symbols-outlined mr-3 text-sm" aria-hidden="true">"edit"</span>
                                "Edit"
                            </leptos_router::components::A>
                            <button
                                type="button"
                                on:click={
                                    move |_| {
                                        set_show_menu.set(false);
                                        set_show_delete_totp_form.set(true);
                                    }
                                }
                                class="flex w-full items-center px-4 py-2 text-sm text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 cursor-pointer text-left"
                            >
                                <span class="material-symbols-outlined mr-3 text-sm" aria-hidden="true">"delete"</span>
                                "Delete"
                            </button>
                        </div>
                    </div>
                </Show>
            }
        }
    </div> }
}
