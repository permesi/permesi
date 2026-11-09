//! Authenticated profile view with wrapping account fields and copyable public identity.

use crate::{
    components::{
        Alert, AlertKind, CopyValue, DateTime, EmptyValue, Icon, IconName, MetaItem, Spinner,
        icon_size,
    },
    features::me::client,
};
use leptos::prelude::*;

/// Renders the current user's profile.
#[component]
pub fn MePage() -> impl IntoView {
    let profile = LocalResource::new(move || async move { client::fetch_me().await });

    view! {
        <div class="min-w-0 rounded-lg border border-gray-200 bg-white p-6 dark:border-gray-700 dark:bg-gray-800 space-y-6">
            <div class="flex flex-wrap items-center justify-between gap-3">
                <h1 class="text-2xl font-semibold text-gray-900 dark:text-white">
                    "Me"
                </h1>
                <button type="button" on:click=move |_| profile.refetch()
                    class="inline-flex cursor-pointer items-center gap-2 rounded-lg border border-gray-300 px-3 py-2 text-sm text-gray-700 hover:bg-gray-50 focus-visible:ring-2 focus-visible:ring-blue-500 dark:border-gray-600 dark:text-gray-200 dark:hover:bg-gray-700">
                    <Icon name=IconName::Refresh size=icon_size::INLINE />"Refresh"
                </button>
            </div>
            <Suspense fallback=move || view! { <Spinner /> }>
                {move || match profile.get() {
                    Some(Ok(me)) => {
                        let display_name = me.display_name.clone();
                        let role_list = if me.roles.is_empty() {
                            "user".to_string()
                        } else {
                            me.roles.join(", ")
                        };
                        view! {
                            <div class="min-w-0 space-y-6">
                                <dl class="min-w-0">
                                    <MetaItem icon=IconName::Person label="Display name">{display_name.map_or_else(|| view! { <EmptyValue /> }.into_any(), IntoAny::into_any)}</MetaItem>
                                    <MetaItem icon=IconName::Mail label="Email">{me.email}</MetaItem>
                                    <MetaItem icon=IconName::Globe label="Locale">{me.locale.map_or_else(|| view! { <EmptyValue /> }.into_any(), IntoAny::into_any)}</MetaItem>
                                    <MetaItem icon=IconName::Shield label="Roles">{role_list}</MetaItem>
                                </dl>
                                <dl class="min-w-0 border-t border-gray-100 pt-4 dark:border-gray-700">
                                    <MetaItem icon=IconName::Identifier label="User ID">
                                        <CopyValue value=me.id label="user ID" compact=true />
                                    </MetaItem>
                                    <MetaItem icon=IconName::Calendar label="Joined">
                                        <DateTime value=me.created_at with_time=true />
                                    </MetaItem>
                                    <MetaItem icon=IconName::Clock label="Last Updated">
                                        <DateTime value=me.updated_at with_time=true />
                                    </MetaItem>
                                </dl>
                            </div>
                        }
                        .into_any()
                    }
                    Some(Err(err)) => {
                        view! { <Alert kind=AlertKind::Error message=err.to_string() /> }
                            .into_any()
                    }
                    None => view! { <Spinner /> }.into_any(),
                }}
            </Suspense>
        </div>
    }
}
