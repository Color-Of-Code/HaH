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
//! | [`json`] | JSON serialisation — pretty-print structured data |
//! | [`paths`]| Platform-specific user configuration directory |
//! | [`yaml`] | YAML parsing and serialisation |

pub mod json;
pub mod paths;
pub mod yaml;
