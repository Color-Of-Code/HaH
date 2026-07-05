//! Capability functions for the HaH rule engine.
//!
//! Each capability gathers system data (via commands, filesystem scans, etc.)
//! and returns a [`CapValue`] — a simple typed result that the DSL engine
//! converts into its internal pipeline value.
//!
//! Capabilities are split into modules by domain:
//!
//! | Module       | Capabilities                                          |
//! |--------------|-------------------------------------------------------|
//! | [`journal`]  | `journal_usage_mb` — systemd journal disk usage       |
//! | [`files`]    | `old_files`, `broken_symlinks` — filesystem scans     |
//! | [`sysctl`]   | `sysctl_conflicts` — sysctl.d key conflicts           |
//! | [`kernel`]   | `kernel_inventory`, `stale_kernel_headers`             |
//! | [`initramfs`]| `large_initramfs` — oversized initramfs images        |
//! | [`apt`]      | `legacy_apt_sources`, `installed_denylist`             |
//! | [`network`]  | `legacy_network_interfaces` — ifupdown overlap        |

pub mod apt;
pub mod files;
pub mod initramfs;
pub mod journal;
pub mod kernel;
pub mod logs;
pub mod network;
pub mod sysctl;

/// A typed value returned by capability functions.
///
/// Deliberately simple and independent of the DSL's internal `RuleValue`.
/// The DSL engine converts `CapValue` into its own pipeline type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapValue {
    /// A single integer (e.g., megabytes of disk usage).
    Int(i64),
    /// A single string (e.g., a status description).
    Str(String),
    /// A list of strings (e.g., file paths, package names).
    List(Vec<String>),
}
