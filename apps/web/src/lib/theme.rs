//! Shared UI themes and Tailwind class constants to ensure visual consistency
//! across the application.

pub struct Theme;

impl Theme {
    /// Container for a row that reacts to hover signaling its children (via the `group` class).
    pub const ROW: &'static str = "px-6 py-4 group transition-colors";

    /// Standard icon style that transitions from gray to dark/white on parent hover.
    pub const ICON: &'static str = "inline-flex text-gray-400 dark:text-gray-500 group-hover:text-gray-900 dark:group-hover:text-white transition-colors";

    /// Flat list item variant without drop shadow.
    pub const LIST_ITEM_FLAT: &'static str = "flex items-center justify-between bg-gray-50 dark:bg-gray-900/50 p-3 rounded-lg border border-gray-200 dark:border-gray-700 transition-colors";
}
