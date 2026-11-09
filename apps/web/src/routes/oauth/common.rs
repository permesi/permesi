//! Shared application context and presentation helpers for OAuth configuration.
//!
//! Context is supplied only after the existing applications API resolves ancestry.
//! Error text preserves backend validation while hiding persistence details.

use crate::{
    app_lib::AppError,
    components::{Alert, AlertKind, Icon, IconName, Spinner, icon_size},
    features::{
        oauth::{
            model,
            paths::{ApplicationPaths, EnvironmentPaths},
        },
        orgs::types::ApplicationResponse,
    },
};
use leptos::prelude::*;
use leptos_router::{components::A, hooks::use_location, params::Params};

pub const CARD: &str =
    "min-w-0 rounded-lg border border-gray-200 bg-white p-5 dark:border-gray-700 dark:bg-gray-800";
pub const INPUT: &str = "block w-full rounded-lg border border-gray-300 bg-gray-50 p-2.5 text-sm text-gray-900 focus:border-blue-500 focus:ring-blue-500 disabled:opacity-60 dark:border-gray-600 dark:bg-gray-700 dark:text-white";
pub const LABEL: &str = "mb-2 block text-sm font-medium text-gray-900 dark:text-white";
pub const LINK: &str = "cursor-pointer rounded text-blue-600 hover:text-blue-800 hover:underline focus-visible:ring-2 focus-visible:ring-blue-500 dark:text-blue-400 dark:hover:text-blue-300";
pub const SECONDARY: &str = "inline-flex cursor-pointer items-center justify-center gap-2 rounded-lg border border-gray-300 px-4 py-2 text-sm hover:bg-gray-100 focus-visible:ring-2 focus-visible:ring-blue-500 disabled:cursor-not-allowed disabled:opacity-50 dark:border-gray-600 dark:hover:bg-gray-700";

pub const DESTRUCTIVE: &str = "inline-flex cursor-pointer items-center justify-center gap-2 rounded-lg border border-red-300 px-4 py-2 text-sm font-medium text-red-700 hover:bg-red-50 focus-visible:ring-2 focus-visible:ring-red-500 disabled:cursor-not-allowed disabled:opacity-50 dark:border-red-700 dark:text-red-300 dark:hover:bg-red-900/30";

#[derive(Params, Clone, PartialEq)]
pub struct ResourceParams {
    pub slug: Option<String>,
    pub project_slug: Option<String>,
    pub env_slug: Option<String>,
    pub app_id: Option<String>,
    pub client_id: Option<String>,
}

impl ResourceParams {
    /// Requires all ancestry segments before making a tenant API request.
    pub fn environment(&self) -> Result<EnvironmentPaths, AppError> {
        Ok(EnvironmentPaths {
            org: required(self.slug.as_ref())?,
            project: required(self.project_slug.as_ref())?,
            environment: required(self.env_slug.as_ref())?,
        })
    }
    /// Requires an application identifier without inventing a detail endpoint.
    pub fn application(&self) -> Result<ApplicationPaths, AppError> {
        Ok(self
            .environment()?
            .application(&required(self.app_id.as_ref())?))
    }
}

/// Rejects missing route segments rather than sending requests to an empty ancestor.
fn required(value: Option<&String>) -> Result<String, AppError> {
    value
        .cloned()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::Config("Missing resource path.".to_owned()))
}

/// Resolved application registration used by child routes; contains no role claims.
#[derive(Clone)]
pub struct ApplicationContext {
    pub paths: ApplicationPaths,
    pub application: ApplicationResponse,
}

/// Returns ancestry verified through the applications API. Absence fails closed.
pub fn application_context() -> Option<ApplicationContext> {
    use_context()
}

/// Maps shared network errors to safe administrator feedback without SQL details.
pub fn error_message(error: &AppError) -> String {
    match error {
        AppError::Http {
            status, message, ..
        } => model::http_message(*status, message),
        AppError::Timeout(_) => {
            "Request timed out. Your changes were kept; please try again.".to_owned()
        }
        AppError::Network(_) => {
            "Unable to reach the server. Your changes were kept; please try again.".to_owned()
        }
        _ => "Unable to load this configuration. Check the selected resource and try again."
            .to_owned(),
    }
}

/// Keeps a stable error element for input aria-describedby and live announcements.
#[component]
pub fn FormError(id: &'static str, error: RwSignal<String>) -> impl IntoView {
    view! { <div id=id aria-live="polite">{move || { let value = error.get(); if value.is_empty() { ().into_any() } else { view! { <Alert kind=AlertKind::Error message=value /> }.into_any() } }}</div> }
}

/// Announces resource loading with the existing spinner styling.
#[component]
pub fn Loading(message: &'static str) -> impl IntoView {
    view! { <div class="flex items-center gap-3 py-6" role="status"><Spinner /><span class="text-sm text-gray-500 dark:text-gray-400">{message}</span></div> }
}

/// Presents a quiet, semantic empty state without suggesting a protocol action.
#[component]
pub fn EmptyState(
    title: &'static str,
    message: &'static str,
    #[prop(default = IconName::Clients)] icon: IconName,
) -> impl IntoView {
    view! { <div class="rounded-lg border border-dashed border-gray-300 px-5 py-8 text-center dark:border-gray-700"><Icon name=icon size=icon_size::EMPTY class="mx-auto mb-3 text-gray-400 dark:text-gray-500" /><h3 class="font-medium">{title}</h3><p class="mt-2 text-sm text-gray-500 dark:text-gray-400">{message}</p></div> }
}

/// Renders shared, labelled Lucide icon links with section-aware active styles.
/// Icons are decorative; pathname state affects presentation, never authorization.
#[component]
fn NavigationLink(
    href: String,
    label: &'static str,
    icon: IconName,
    #[prop(default = false)] descendants: bool,
    #[prop(default = false)] secondary: bool,
) -> impl IntoView {
    let location = use_location();
    let href = StoredValue::new(href);
    let active = Signal::derive(move || {
        model::navigation_active(&location.pathname.get(), &href.get_value(), descendants)
    });
    let class = move || match (secondary, active.get()) {
        (false, true) => {
            "inline-flex cursor-pointer items-center gap-2 border-b-2 border-gray-900 px-3 py-3 text-sm font-medium text-gray-900 hover:bg-gray-50 focus-visible:ring-2 focus-visible:ring-blue-500 dark:border-gray-200 dark:text-white dark:hover:bg-gray-800"
        }
        (false, false) => {
            "inline-flex cursor-pointer items-center gap-2 border-b-2 border-transparent px-3 py-3 text-sm font-medium text-gray-600 hover:border-gray-300 hover:bg-gray-50 hover:text-gray-900 focus-visible:ring-2 focus-visible:ring-blue-500 dark:text-gray-400 dark:hover:border-gray-600 dark:hover:bg-gray-800 dark:hover:text-white"
        }
        (true, true) => {
            "inline-flex cursor-pointer items-center gap-1.5 rounded-md bg-white px-3 py-2 text-sm font-medium text-gray-900 shadow-sm hover:bg-gray-50 focus-visible:ring-2 focus-visible:ring-blue-500 dark:bg-gray-700 dark:text-white dark:hover:bg-gray-600"
        }
        (true, false) => {
            "inline-flex cursor-pointer items-center gap-1.5 rounded-md px-3 py-2 text-sm text-gray-600 hover:bg-gray-200 hover:text-gray-900 focus-visible:ring-2 focus-visible:ring-blue-500 dark:text-gray-400 dark:hover:bg-gray-800 dark:hover:text-white"
        }
    };
    view! { <A href=href.get_value() exact=!descendants attr:class=class attr:aria-label=label attr:aria-current=move || active.get().then_some("page")>
        <Icon name=icon size=if secondary { icon_size::INLINE } else { icon_size::NAV } class="text-gray-400 dark:text-gray-500" />
        <span>{label}</span>
    </A> }
}

/// Presents the primary application sections above the nested page outlet.
#[component]
pub fn ApplicationNav(paths: ApplicationPaths) -> impl IntoView {
    let paths = StoredValue::new(paths);
    view! { <nav aria-label="Application" class="flex flex-wrap gap-2 border-b border-gray-200 dark:border-gray-700">
        <NavigationLink href=paths.get_value().console() label="Overview" icon=IconName::Dashboard />
        <NavigationLink href=paths.get_value().oauth() label="OAuth Configuration" icon=IconName::Clients descendants=true />
    </nav> }
}

/// Presents secondary navigation as a compact segmented control inside OAuth.
#[component]
pub fn OAuthNav(paths: ApplicationPaths) -> impl IntoView {
    let paths = StoredValue::new(paths);
    view! { <nav aria-label="OAuth configuration" class="flex w-fit max-w-full flex-wrap gap-1 rounded-lg bg-gray-100 p-1 dark:bg-gray-900">
        <NavigationLink href=paths.get_value().oauth() label="Summary" icon=IconName::Overview secondary=true />
        <NavigationLink href=paths.get_value().clients() label="Clients" icon=IconName::Clients descendants=true secondary=true />
        <NavigationLink href=paths.get_value().scopes() label="Scopes" icon=IconName::Scopes secondary=true />
    </nav> }
}
