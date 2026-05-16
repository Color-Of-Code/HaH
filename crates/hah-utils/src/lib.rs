//! Shared utilities and third-party library facades for the HaH workspace.
//!
//! Other crates in this workspace depend on `hah-utils` instead of consuming
//! third-party crate APIs directly.  This keeps the coupling to external
//! libraries localised: changing a library only requires edits inside this
//! crate.
//!
//! # Modules
//!
//! | Module   | Contents |
//! |----------|----------|
//! | [`fs`]   | Filesystem helpers: `sanitize_id`, broken-symlink walk, old-file scan |
//! | [`json`] | JSON serialisation — pretty-print structured data |
//! | [`paths`]| Platform-specific user configuration directory |
//! | [`size`] | Human-readable byte-size parsing |
//! | [`sysctl`] | Pure sysctl conflict-detection algorithm |
//! | [`yaml`] | YAML parsing and serialisation |

pub mod fs;
pub mod json;
pub mod paths;
pub mod size;
pub mod sysctl;
pub mod yaml;
