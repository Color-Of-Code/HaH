//! Platform-specific directory path helpers.
//!
//! Import from this module rather than from any specific platform-directory
//! library so that the underlying implementation can be swapped without
//! touching callers.

use std::path::PathBuf;

/// Return the platform-appropriate user configuration directory, or `None`
/// if it cannot be determined.
///
/// On Linux this is `$XDG_CONFIG_HOME` when set, otherwise `~/.config`.
pub fn user_config_dir() -> Option<PathBuf> {
    dirs::config_dir()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_config_dir_does_not_panic() {
        // We only verify the function is callable and does not panic.
        let _ = user_config_dir();
    }
}
