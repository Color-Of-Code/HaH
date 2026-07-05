use std::{collections::HashMap, path::PathBuf};

use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub profile: String,
    #[serde(default)]
    pub allowlist: Allowlist,
    #[serde(default)]
    pub denylist: Denylist,
    #[serde(default)]
    pub enabled_checks: Vec<String>,
    #[serde(default)]
    pub disabled_checks: Vec<String>,
    #[serde(default)]
    pub thresholds: HashMap<String, u64>,
    #[serde(default)]
    pub preferred_snap: Vec<String>,
    /// Extra directories to search for `*.yaml` rule files.
    #[serde(default)]
    pub rule_dirs: Vec<PathBuf>,
    /// Command execution policy (allowlist of programs rules may run).
    #[serde(default)]
    pub commands: CommandPolicy,
}

/// Command execution policy.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CommandPolicy {
    /// Regexes matched against the program name of every command a rule runs.
    /// When empty, the built-in [`DEFAULT_COMMAND_ALLOW`] set is used.
    #[serde(default)]
    pub allow: Vec<String>,
}

/// Programs the shipped rules need.  Used when no allowlist is configured.
pub const DEFAULT_COMMAND_ALLOW: &[&str] = &[
    "^apt-get$",
    "^df$",
    "^dkms$",
    "^dmesg$",
    "^dpkg$",
    "^dpkg-query$",
    "^find$",
    "^grep$",
    "^journalctl$",
    "^ls$",
    "^snap$",
    "^systemctl$",
    "^tail$",
    "^uname$",
];

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Allowlist {
    #[serde(default)]
    pub packages: Vec<String>,
    #[serde(default)]
    pub repositories: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Denylist {
    #[serde(default)]
    pub packages: Vec<DenylistEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DenylistEntry {
    pub name: String,
    pub reason: String,
}

impl Config {
    pub fn load() -> Result<Self> {
        let paths: Vec<PathBuf> = [
            Some(PathBuf::from("/etc/hah/config.yaml")),
            hah_utils::paths::user_config_dir().map(|d| d.join("hah/config.yaml")),
        ]
        .into_iter()
        .flatten()
        .collect();

        Self::load_from_paths(&paths)
    }

    /// Load and merge config from an explicit list of paths, skipping files
    /// that do not exist.  Useful for testing with temporary files.
    pub fn load_from_paths(paths: &[PathBuf]) -> Result<Self> {
        let mut merged = Config::default();
        for path in paths {
            if path.exists() {
                let content = std::fs::read_to_string(path)?;
                let cfg: Config = hah_utils::yaml::parse(&content)?;
                merged.merge(cfg);
            }
        }
        Ok(merged)
    }

    fn merge(&mut self, other: Config) {
        if !other.profile.is_empty() {
            self.profile = other.profile;
        }
        self.allowlist.packages.extend(other.allowlist.packages);
        self.allowlist
            .repositories
            .extend(other.allowlist.repositories);
        self.denylist.packages.extend(other.denylist.packages);
        self.enabled_checks.extend(other.enabled_checks);
        self.disabled_checks.extend(other.disabled_checks);
        self.thresholds.extend(other.thresholds);
        self.preferred_snap.extend(other.preferred_snap);
        self.rule_dirs.extend(other.rule_dirs);
        self.commands.allow.extend(other.commands.allow);
    }

    /// Return the effective command allow patterns: the configured list, or the
    /// built-in [`DEFAULT_COMMAND_ALLOW`] set when none is configured.
    pub fn command_allow(&self) -> Vec<String> {
        if self.commands.allow.is_empty() {
            DEFAULT_COMMAND_ALLOW
                .iter()
                .map(ToString::to_string)
                .collect()
        } else {
            self.commands.allow.clone()
        }
    }

    /// Return a threshold value from config, falling back to `default` if not set.
    pub fn threshold(&self, key: &str, default: u64) -> u64 {
        *self.thresholds.get(key).unwrap_or(&default)
    }

    /// Return true if the check with the given id should run.
    pub fn check_enabled(&self, id: &str) -> bool {
        if !self.disabled_checks.is_empty() && self.disabled_checks.iter().any(|x| x == id) {
            return false;
        }
        if !self.enabled_checks.is_empty() {
            return self.enabled_checks.iter().any(|x| x == id);
        }
        true
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::field_reassign_with_default,
    clippy::cloned_ref_to_slice_refs
)]
mod tests {
    use super::*;

    #[test]
    fn threshold_returns_default_when_not_set() {
        assert_eq!(Config::default().threshold("key", 42), 42);
    }

    #[test]
    fn threshold_returns_configured_value() {
        let mut cfg = Config::default();
        cfg.thresholds.insert("key".into(), 99);
        assert_eq!(cfg.threshold("key", 42), 99);
    }

    #[test]
    fn check_enabled_all_enabled_by_default() {
        assert!(Config::default().check_enabled("any-check"));
    }

    #[test]
    fn check_enabled_disabled_list_blocks_check() {
        let mut cfg = Config::default();
        cfg.disabled_checks = vec!["bad-check".into()];
        assert!(!cfg.check_enabled("bad-check"));
        assert!(cfg.check_enabled("good-check"));
    }

    #[test]
    fn check_enabled_explicit_allowlist() {
        let mut cfg = Config::default();
        cfg.enabled_checks = vec!["allowed".into()];
        assert!(cfg.check_enabled("allowed"));
        assert!(!cfg.check_enabled("not-allowed"));
    }

    #[test]
    fn merge_extends_allowlist_packages() {
        let mut base = Config::default();
        base.allowlist.packages = vec!["pkg-a".into()];
        let mut other = Config::default();
        other.allowlist.packages = vec!["pkg-b".into()];
        base.merge(other);
        assert_eq!(base.allowlist.packages.len(), 2);
    }

    #[test]
    fn merge_overrides_non_empty_profile() {
        let mut base = Config::default();
        let mut other = Config::default();
        other.profile = "production".into();
        base.merge(other);
        assert_eq!(base.profile, "production");
    }

    #[test]
    fn merge_keeps_base_profile_when_other_is_empty() {
        let mut base = Config::default();
        base.profile = "staging".into();
        base.merge(Config::default());
        assert_eq!(base.profile, "staging");
    }

    #[test]
    fn merge_extends_thresholds() {
        let mut base = Config::default();
        base.thresholds.insert("a".into(), 1);
        let mut other = Config::default();
        other.thresholds.insert("b".into(), 2);
        base.merge(other);
        assert_eq!(base.thresholds.len(), 2);
    }

    #[test]
    fn merge_extends_enabled_and_disabled_checks() {
        let mut base = Config::default();
        base.enabled_checks = vec!["check-a".into()];
        base.disabled_checks = vec!["check-x".into()];
        let mut other = Config::default();
        other.enabled_checks = vec!["check-b".into()];
        other.disabled_checks = vec!["check-y".into()];
        base.merge(other);
        assert_eq!(base.enabled_checks.len(), 2);
        assert_eq!(base.disabled_checks.len(), 2);
    }

    #[test]
    fn merge_extends_repositories_and_preferred_snap() {
        let mut base = Config::default();
        base.allowlist.repositories = vec!["repo-a".into()];
        base.preferred_snap = vec!["snap-a".into()];
        let mut other = Config::default();
        other.allowlist.repositories = vec!["repo-b".into()];
        other.preferred_snap = vec!["snap-b".into()];
        base.merge(other);
        assert_eq!(base.allowlist.repositories.len(), 2);
        assert_eq!(base.preferred_snap.len(), 2);
    }

    #[test]
    fn command_allow_defaults_when_unset() {
        assert_eq!(
            Config::default().command_allow(),
            DEFAULT_COMMAND_ALLOW
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn command_allow_uses_configured_patterns() {
        let mut cfg = Config::default();
        cfg.commands.allow = vec!["^find$".into()];
        assert_eq!(cfg.command_allow(), vec!["^find$".to_string()]);
    }

    #[test]
    fn merge_extends_command_allow() {
        let mut base = Config::default();
        base.commands.allow = vec!["^find$".into()];
        let mut other = Config::default();
        other.commands.allow = vec!["^grep$".into()];
        base.merge(other);
        assert_eq!(base.commands.allow.len(), 2);
    }

    #[test]
    fn config_deserializes_commands_allow() {
        let yaml = "commands:\n  allow:\n    - '^find$'\n    - '^grep$'\n";
        let cfg: Config = hah_utils::yaml::parse(yaml).unwrap();
        assert_eq!(cfg.commands.allow, vec!["^find$", "^grep$"]);
    }

    // ── serde deserialization ─────────────────────────────────────────────────

    #[test]
    fn config_deserializes_thresholds_field() {
        let yaml = "thresholds:\n  boot_space_mb: 200\n  journal_size_mb: 1024\n";
        let cfg: Config = hah_utils::yaml::parse(yaml).unwrap();
        assert_eq!(cfg.threshold("boot_space_mb", 0), 200);
        assert_eq!(cfg.threshold("journal_size_mb", 0), 1024);
    }

    #[test]
    fn config_deserializes_preferred_snap_field() {
        let yaml = "preferred_snap:\n  - firefox\n  - vlc\n";
        let cfg: Config = hah_utils::yaml::parse(yaml).unwrap();
        assert_eq!(cfg.preferred_snap, vec!["firefox", "vlc"]);
    }

    #[test]
    fn config_deserializes_all_fields() {
        let yaml = concat!(
            "profile: production\n",
            "thresholds:\n  boot_space_mb: 50\n",
            "preferred_snap:\n  - chromium\n",
            "allowlist:\n  packages:\n    - curl\n",
            "disabled_checks:\n  - apt-key\n",
        );
        let cfg: Config = hah_utils::yaml::parse(yaml).unwrap();
        assert_eq!(cfg.profile, "production");
        assert_eq!(cfg.threshold("boot_space_mb", 0), 50);
        assert_eq!(cfg.preferred_snap, vec!["chromium"]);
        assert!(cfg.allowlist.packages.contains(&"curl".to_string()));
        assert!(cfg.disabled_checks.contains(&"apt-key".to_string()));
    }

    // ── load_from_paths ───────────────────────────────────────────────────────

    #[test]
    fn load_from_paths_skips_nonexistent_files() {
        let cfg =
            Config::load_from_paths(&[PathBuf::from("/nonexistent/path/config.yaml")]).unwrap();
        assert_eq!(cfg.profile, "");
    }

    #[test]
    fn load_from_paths_reads_yaml_file() {
        let path = std::env::temp_dir().join(format!("hah_cfg_test_{}.yaml", std::process::id()));
        std::fs::write(&path, "thresholds:\n  boot_space_mb: 42\n").unwrap();
        let cfg = Config::load_from_paths(&[path.clone()]).unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(cfg.threshold("boot_space_mb", 0), 42);
    }

    #[test]
    fn load_from_paths_merges_multiple_files() {
        let tmp = std::env::temp_dir();
        let p1 = tmp.join(format!("hah_cfg1_{}.yaml", std::process::id()));
        let p2 = tmp.join(format!("hah_cfg2_{}.yaml", std::process::id()));
        std::fs::write(&p1, "allowlist:\n  packages:\n    - vim\n").unwrap();
        std::fs::write(&p2, "allowlist:\n  packages:\n    - git\n").unwrap();
        let cfg = Config::load_from_paths(&[p1.clone(), p2.clone()]).unwrap();
        let _ = std::fs::remove_file(&p1);
        let _ = std::fs::remove_file(&p2);
        assert_eq!(cfg.allowlist.packages.len(), 2);
    }
}
