use hah_checks::{
    apt::{
        AptKeyCheck, AutoremovableCheck, DpkgStateCheck, LegacySourcesFormatCheck,
        ResidualConfigCheck, UserDefinedPackageCheck,
    },
    boot::{
        BootSpaceCheck, DkmsStatusCheck, InitramfsCheck, InitramfsCompressionCheck,
        StaleKernelHeadersCheck, UnusedKernelsCheck,
    },
    drift::{BrokenSymlinksCheck, JournalSizeCheck, OldCrashDumpsCheck},
    network::{
        LegacyDhcpClientCheck, LegacyNetworkInterfacesCheck, LegacyNtpCheck, NtpConflictCheck,
        ResolvedConfigCheck,
    },
    snap::{SnapAptDuplicateCheck, SnapHealthCheck},
    sysctl::SysctlOrderingCheck,
};
use hah_core::{check::Check, config::Config};
use hah_dsl::rule::RuleSet;
use std::path::PathBuf;

/// Rule file search path: system-wide, user-local, then extra paths from config.
fn rule_search_dirs(config: &Config) -> Vec<PathBuf> {
    let mut dirs = vec![PathBuf::from("/etc/hah/rules.d")];
    if let Some(d) = hah_utils::paths::user_config_dir() {
        dirs.push(d.join("hah/rules.d"));
    }
    dirs.extend(config.rule_dirs.clone());
    dirs
}

pub(crate) fn all_checks(config: &Config) -> Vec<Box<dyn Check>> {
    let mut checks: Vec<Box<dyn Check>> = vec![
        Box::new(BootSpaceCheck),
        Box::new(UnusedKernelsCheck),
        Box::new(StaleKernelHeadersCheck),
        Box::new(InitramfsCheck),
        Box::new(InitramfsCompressionCheck),
        Box::new(DkmsStatusCheck),
        Box::new(AptKeyCheck),
        Box::new(LegacySourcesFormatCheck),
        Box::new(DpkgStateCheck),
        Box::new(ResidualConfigCheck),
        Box::new(AutoremovableCheck),
        Box::new(UserDefinedPackageCheck),
        Box::new(SnapHealthCheck),
        Box::new(SnapAptDuplicateCheck),
        Box::new(BrokenSymlinksCheck),
        Box::new(OldCrashDumpsCheck),
        Box::new(JournalSizeCheck),
        Box::new(SysctlOrderingCheck),
        Box::new(LegacyNtpCheck),
        Box::new(NtpConflictCheck),
        Box::new(LegacyDhcpClientCheck),
        Box::new(LegacyNetworkInterfacesCheck),
        Box::new(ResolvedConfigCheck),
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
        assert_eq!(checks.len(), 23);
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
