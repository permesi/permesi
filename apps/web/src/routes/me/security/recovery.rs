//! Recovery-code regeneration after password proof; generated codes stay in this view.
//!
//! Flow Overview: The section collects browser-local input, completes the existing
//! authentication ceremony and calls its session-authenticated mutation API.

use super::MfaAuthInput;
use crate::{
    app_lib::{AppError, theme::Theme},
    components::{Alert, AlertKind, Button, Spinner},
    features::auth::{client as auth_client, opaque::reauthenticate},
};
use leptos::{ev::SubmitEvent, prelude::*};

/// Regenerates recovery codes after password proof and shows them only in this view.
#[component]
pub(super) fn RecoveryCodesSection(email: StoredValue<String>, enabled: bool) -> impl IntoView {
    // Recovery codes signals
    let (show_recovery_codes_form, set_show_recovery_codes_form) = signal(false);
    let (recovery_password, set_recovery_password) = signal(String::new());
    let (regenerated_codes, set_regenerated_codes) = signal::<Option<Vec<String>>>(None);

    let regenerate_codes_action = Action::new_local(move |input: &MfaAuthInput| {
        let input = input.clone();
        async move {
            reauthenticate(&input.email, input.password).await?;

            // 2. Call regeneration endpoint
            let response = auth_client::regenerate_recovery_codes().await?;
            Ok::<Vec<String>, AppError>(response.codes)
        }
    });

    Effect::new(move |_| {
        if let Some(Ok(codes)) = regenerate_codes_action.value().get() {
            set_regenerated_codes.set(Some(codes));
            set_show_recovery_codes_form.set(false);
            set_recovery_password.set(String::new());
        }
    });

    view! {
                                        // Recovery Codes Row
                                        <Show when=move || enabled>
                                            <div class=Theme::ROW>
                                                <div class="flex items-center justify-between">
                                                    <div class="flex items-center space-x-3">
                                                        <span class=Theme::ICON>
                                                            "settings_backup_restore"
                                                        </span>
                                                        <div>
                                                            <p class="text-sm font-medium text-gray-900 dark:text-white">
                                                                "Recovery codes"
                                                            </p>
                                                            <p class="text-xs text-gray-500 dark:text-gray-400">
                                                                "Fallback access via one-time codes."
                                                            </p>
                                                        </div>
                                                    </div>
                                                    <button
                                                        on:click=move |_| {
                                                            set_show_recovery_codes_form.update(|v| *v = !*v);
                                                            set_regenerated_codes.set(None);
                                                        }
                                                        class="text-sm font-medium text-gray-700 dark:text-gray-200 bg-white dark:bg-gray-900 border border-gray-300 dark:border-gray-600 rounded-md px-3 py-1.5 hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors cursor-pointer"
                                                    >
                                                        {move || if show_recovery_codes_form.get() { "Cancel" } else { "Regenerate" }}
                                                    </button>
                                                </div>

                                                <Show when=move || show_recovery_codes_form.get()>
                                                    {recovery_form(email, recovery_password, set_recovery_password, regenerate_codes_action)}
                                                </Show>

                                                <Show when=move || regenerated_codes.get().is_some()>
                                                    <div class="mt-6 space-y-4">
                                                        <Alert kind=AlertKind::Info message="New recovery codes have been generated. Please save them in a safe place.".to_string() />
                                                        <div class="bg-white dark:bg-gray-800 p-4 rounded-lg border border-gray-200 dark:border-gray-700 shadow-inner">
                                                            <div class="grid grid-cols-2 gap-2 font-mono text-sm">
                                                                {move || regenerated_codes.get().unwrap_or_default().into_iter().map(|code| {
                                                                    view! { <div class="p-2 bg-gray-50 dark:bg-gray-900 rounded border border-gray-100 dark:border-gray-700 shadow-sm text-center">{code}</div> }
                                                                }).collect::<Vec<_>>()}
                                                            </div>
                                                        </div>
                                                        <button
                                                            on:click=move |_| set_regenerated_codes.set(None)
                                                            class="px-4 py-2 text-gray-700 dark:text-gray-200 text-sm font-medium rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-900 hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors cursor-pointer"
                                                        >
                                                            "Close"
                                                        </button>
                                                    </div>
                                                </Show>
                                            </div>
                                        </Show>
    }
}

/// Confirms password proof before the owning section regenerates recovery codes.
fn recovery_form(
    email: StoredValue<String>,
    recovery_password: ReadSignal<String>,
    set_recovery_password: WriteSignal<String>,
    regenerate_codes_action: Action<MfaAuthInput, Result<Vec<String>, AppError>>,
) -> impl IntoView {
    view! { <form
        class="mt-6 space-y-4 max-w-md bg-gray-50 dark:bg-gray-900/50 p-4 rounded-lg border border-gray-100 dark:border-gray-700 shadow-sm"
        on:submit=move |event: SubmitEvent| {
            event.prevent_default();
            let password = recovery_password.get_untracked();
            if password.trim().is_empty() {
                return;
            }
            regenerate_codes_action.dispatch(MfaAuthInput {
                email: email.get_value(),
                password,
            });
        }
    >
        <p class="text-xs text-gray-600 dark:text-gray-400 mb-4">
            "Regenerating codes will invalidate your existing set. Enter your password to continue."
        </p>
        <div>
            <label class="block mb-1 text-xs font-medium text-gray-700 dark:text-gray-300" for="recovery_password">
                "Password"
            </label>
            <input
                id="recovery_password"
                type="password"
                class="bg-white border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-blue-500 focus:border-blue-500 block w-full p-2.5 dark:bg-gray-700 dark:border-gray-600 dark:text-white"
                required
                on:input=move |event| set_recovery_password.set(event_target_value(&event))
            />
        </div>
        <div class="pt-2 flex items-center gap-4">
            <Button button_type="submit" disabled=regenerate_codes_action.pending()>
                "Regenerate codes"
            </Button>
            {move || {
                regenerate_codes_action
                    .pending()
                    .get()
                    .then_some(view! { <Spinner /> })
            }}
        </div>
        {move || {
            regenerate_codes_action
                .value()
                .get()
                .and_then(std::result::Result::err)
                .map(|err| {
                    view! { <div class="mt-4"><Alert kind=AlertKind::Error message=err.to_string() /></div> }
                })
        }}
    </form> }
}
