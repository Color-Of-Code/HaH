use hah_checks::{
    apt::{LegacySourcesFormatCheck, UserDefinedPackageCheck},
    boot::InitramfsCheck,
    network::{LegacyNetworkInterfacesCheck, NtpConflictCheck},
};
use hah_core::{check::Check, config::Config};
use hah_dsl::rule::RuleSet;
use std::path::PathBuf;

/// Default rules directory shipped alongside the binary.
///
/// At build time this resolves to `rules/` at the workspace root.  When the
/// tool is installed system-wide, rules are expected at `/usr/share/hah/rules/`
/// (override via `rule_dirs` in the config file).
const DEFAULT_RULES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../rules");

/// Rule file search path: default shipped rules, system-wide, user-local, then
/// extra paths from config.
fn rule_search_dirs(config: &Config) -> Vec<PathBuf> {
    let mut dirs = vec![
        PathBuf::from(DEFAULT_RULES_DIR),
        PathBuf::from("/usr/share/hah/rules"),
        PathBuf::from("/etc/hah/rules.d"),
    ];
    if let Some(d) = hah_utils::paths::user_config_dir() {
        dirs.push(d.join("hah/rules.d"));
    }
    dirs.extend(config.rule_dirs.clone());
    dirs
}

pub(crate) fn all_checks(config: &Config) -> Vec<Box<dyn Check>> {
    // Compiled checks for logic too complex for the declarative DSL.
    let mut checks: Vec<Box<dyn Check>> = vec![
        Box::new(InitramfsCheck),
        Box::new(LegacySourcesFormatCheck),
        Box::new(UserDefinedPackageCheck),
        Box::new(NtpConflictCheck),
        Box::new(LegacyNetworkInterfacesCheck),
    ];

    // Load declarative YAML rules from search directories.
    for dir in rule_search_dirs(config) {
        match RuleSet::load_checks_from_dir(&dir) {
            Ok(dsl_checks) => {
                for c in dsl_checks {
                    checks.push(Box::new(c));
                }
            }
            Err(e) => {
                eprintln!(
                    "hah: warning: could not load rules from {}: {e}",
                    dir.display()
                );
            }
        }
    }

    checks
}

#[cfg(test)]
mod tests {
    use super::*;
    use hah_core::config::Config;

    #[test]
    fn all_checks_returns_expected_count() {
        let checks = all_checks(&Config::default());
        // 14 compiled + 10 rules from ./rules/ (legacy-ntp.yaml has 2 rules)
        assert_eq!(checks.len(), 24);
    }

    #[test]
    fn all_checks_ids_are_unique_and_non_empty() {
        let checks = all_checks(&Config::default());
        let mut seen = std::collections::HashSet::new();
        for check in &checks {
            let id = check.id();
            assert!(!id.is_empty(), "check has empty id");
            assert!(seen.insert(id), "duplicate check id: {id}");
        }
    }

    #[test]
    fn all_checks_titles_are_non_empty() {
        for check in all_checks(&Config::default()) {
            assert!(
                !check.title().is_empty(),
                "check '{}' has empty title",
                check.id()
            );
        }
    }
}
