//! Single entry point for Lucide SVG icons.
//!
//! Every icon in the console is rendered through [`Icon`] so that concept-to-icon
//! mappings, sizing, and accessibility live in one place. `lucide-leptos`
//! components do not accept `class` or ARIA attributes, so [`Icon`] wraps the SVG
//! in a decorative `<span aria-hidden="true">` that carries Tailwind classes. The
//! SVG uses `currentColor`, so colour comes from the wrapper's text colour.
//!
//! Icons are decorative by default: the adjacent text, or the `aria-label` of an
//! icon-only control, is the accessible name. Colour and caps follow Lucide's defaults
//! (`currentColor`, round); stroke width is normalized to 1.5 by the shared `.lucide`
//! rule in `assets/app.css`, which the custom SVGs below also use.
//!
//! Size scale: [`size::INLINE`] for text actions, [`size::CONTROL`] for buttons and
//! form controls, [`size::NAV`] for sidebar and tab navigation, [`size::CARD`] for
//! cards and section headings, and [`size::EMPTY`] for empty and error states.
//!
//! Lucide has no phone-with-lock glyph, so `PhoneLock` below uses the same grid,
//! stroke and caps. The mobile hamburger also keeps its small inline SVG.

use leptos::prelude::*;
use lucide_leptos::{
    Activity, ArrowLeft, Building, CalendarDays, Check, ChevronDown, ChevronRight, CircleAlert,
    CircleCheck, CircleUser, Clock3, Copy, Database, FingerprintPattern, Globe, GraphStar, House,
    IdCardLanyard, Info, KeyRound, Layers, LayoutDashboard, LayoutPanelLeft, ListChecks, Lock,
    LogIn, LogOut, Mail, Pencil, RectangleEllipsis, RefreshCw, RotateCcw, Settings2, Shield,
    ShieldCheck, ShieldKeyhole, ShieldUser, Smartphone, Tag, Trash, TriangleAlert, Unlink, User,
    UserKey, UserPlus, UserRound, UserX, Users, Workflow, X,
};

/// Icon pixel sizes for the contexts used across the console.
pub mod size {
    /// Inline text actions and menu items.
    pub const INLINE: usize = 16;
    /// Buttons and form controls.
    pub const CONTROL: usize = 18;
    /// Sidebar and tab navigation.
    pub const NAV: usize = 20;
    /// Cards, section headings, and dialog titles.
    pub const CARD: usize = 20;
    /// Empty, loading, and error states.
    pub const EMPTY: usize = 36;
}

/// Semantic icon names. One concept maps to one Lucide icon everywhere.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum IconName {
    Authentication,
    Back,
    Cancel,
    Clients,
    Credentials,
    Dashboard,
    Database,
    Delete,
    Edit,
    Environments,
    Error,
    Expand,
    Health,
    Home,
    Identity,
    Info,
    LockedKey,
    Operator,
    Organizations,
    Overview,
    Profile,
    Projects,
    Recovery,
    Refresh,
    Scopes,
    Security,
    KeyRound,
    Settings,
    SignIn,
    SignOut,
    SignUp,
    Success,
    ConnectedApps,
    Unlink,
    UserDisable,
    Users,
    Warning,
    Device,
    PhoneLock,
    AdminPanel,
    SecurityKey,
    Account,
    Calendar,
    Check,
    Clock,
    Copy,
    Identifier,
    Mail,
    Person,
    Tag,
    Globe,
    Shield,
    ChevronRight,
}

/// Renders a decorative Lucide icon at `size` pixels with optional wrapper classes.
#[component]
pub fn Icon(
    name: IconName,
    #[prop(default = size::INLINE)] size: usize,
    #[prop(optional, into)] class: Signal<String>,
) -> impl IntoView {
    let svg = match name {
        IconName::Authentication => view! { <FingerprintPattern size=size /> }.into_any(),
        IconName::Back => view! { <ArrowLeft size=size /> }.into_any(),
        IconName::Cancel => view! { <X size=size /> }.into_any(),
        IconName::Clients => view! { <KeyRound size=size /> }.into_any(),
        IconName::Credentials => view! { <RectangleEllipsis size=size /> }.into_any(),
        IconName::Dashboard => view! { <LayoutDashboard size=size /> }.into_any(),
        IconName::Database => view! { <Database size=size /> }.into_any(),
        IconName::Delete => view! { <Trash size=size /> }.into_any(),
        IconName::Edit => view! { <Pencil size=size /> }.into_any(),
        IconName::Environments => view! { <Layers size=size /> }.into_any(),
        IconName::Error => view! { <CircleAlert size=size /> }.into_any(),
        IconName::Expand => view! { <ChevronDown size=size /> }.into_any(),
        IconName::Health => view! { <Activity size=size /> }.into_any(),
        IconName::Home => view! { <House size=size /> }.into_any(),
        IconName::Identity => view! { <IdCardLanyard size=size /> }.into_any(),
        IconName::Info => view! { <Info size=size /> }.into_any(),
        IconName::LockedKey => view! { <Lock size=size /> }.into_any(),
        IconName::Operator => view! { <ShieldCheck size=size /> }.into_any(),
        IconName::Organizations => view! { <Building size=size /> }.into_any(),
        IconName::Overview => view! { <LayoutPanelLeft size=size /> }.into_any(),
        IconName::Profile => view! { <User size=size /> }.into_any(),
        IconName::Projects => view! { <Workflow size=size /> }.into_any(),
        IconName::Recovery => view! { <RotateCcw size=size /> }.into_any(),
        IconName::Refresh => view! { <RefreshCw size=size /> }.into_any(),
        IconName::Scopes => view! { <ListChecks size=size /> }.into_any(),
        IconName::Security => view! { <ShieldKeyhole size=size /> }.into_any(),
        IconName::KeyRound => view! { <KeyRound size=size /> }.into_any(),
        IconName::Settings => view! { <Settings2 size=size /> }.into_any(),
        IconName::SignIn => view! { <LogIn size=size /> }.into_any(),
        IconName::SignOut => view! { <LogOut size=size /> }.into_any(),
        IconName::SignUp => view! { <UserPlus size=size /> }.into_any(),
        IconName::Success => view! { <CircleCheck size=size /> }.into_any(),
        IconName::ConnectedApps => view! { <GraphStar size=size /> }.into_any(),
        IconName::Unlink => view! { <Unlink size=size /> }.into_any(),
        IconName::UserDisable => view! { <UserX size=size /> }.into_any(),
        IconName::Users => view! { <Users size=size /> }.into_any(),
        IconName::Warning => view! { <TriangleAlert size=size /> }.into_any(),
        IconName::Device => view! { <Smartphone size=size /> }.into_any(),
        IconName::PhoneLock => view! { <PhoneLock size=size /> }.into_any(),
        IconName::AdminPanel => view! { <ShieldUser size=size /> }.into_any(),
        IconName::SecurityKey => view! { <UserKey size=size /> }.into_any(),
        IconName::Account => view! { <CircleUser size=size /> }.into_any(),
        IconName::Calendar => view! { <CalendarDays size=size /> }.into_any(),
        IconName::Check => view! { <Check size=size /> }.into_any(),
        IconName::Clock => view! { <Clock3 size=size /> }.into_any(),
        IconName::Copy => view! { <Copy size=size /> }.into_any(),
        IconName::Identifier => view! { <FingerprintPattern size=size /> }.into_any(),
        IconName::Mail => view! { <Mail size=size /> }.into_any(),
        IconName::Person => view! { <UserRound size=size /> }.into_any(),
        IconName::Tag => view! { <Tag size=size /> }.into_any(),
        IconName::Globe => view! { <Globe size=size /> }.into_any(),
        IconName::Shield => view! { <Shield size=size /> }.into_any(),
        IconName::ChevronRight => view! { <ChevronRight size=size /> }.into_any(),
    };
    view! { <span class=move || format!("inline-flex shrink-0 items-center justify-center align-middle {}", class.get()) aria-hidden="true">{svg}</span> }
}

/// Smartphone with a padlock beside it, matching Material `phonelink_lock`. Lucide has
/// no phone-with-lock glyph, so the phone outline and lock are drawn on the Lucide grid.
#[component]
fn PhoneLock(size: usize) -> impl IntoView {
    view! {
        <svg class="lucide" xmlns="http://www.w3.org/2000/svg" width=size height=size viewBox="0 0 24 24"
            fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <rect x="3" y="2" width="10" height="20" rx="2" />
            <path d="M8 18h.01" />
            <rect x="15" y="13" width="7" height="7" rx="1" />
            <path d="M16.5 13v-2a2 2 0 0 1 4 0v2" />
        </svg>
    }
}
