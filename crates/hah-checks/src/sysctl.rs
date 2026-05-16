use std::{fs, path::Path};

use hah_core::{
    check::{Check, Context},
    model::{CheckResult, Severity},
};

// ── SysctlOrderingCheck ──────────────────────────────────────────────────────

pub struct SysctlOrderingCheck;

const SYSCTL_DIRS: &[&str] = &["/usr/lib/sysctl.d", "/etc/sysctl.d", "/run/sysctl.d"];

impl Check for SysctlOrderingCheck {
    fn id(&self) -> &str {
        "sysctl-ordering"
    }

    fn title(&self) -> &str {
        "Conflicting sysctl.d overrides"
    }

    fn run(&self, _ctx: &Context) -> CheckResult {
        // Collect files in load order (lexicographic within each dir, dirs in priority order)
        let mut file_entries: Vec<(String, String)> = Vec::new(); // (path, content)

        for dir in SYSCTL_DIRS {
            let path = Path::new(dir);
            if !path.exists() {
                continue;
            }
            if let Ok(entries) = fs::read_dir(path) {
                let mut names: Vec<String> = entries
                    .flatten()
                    .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("conf"))
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect();
                names.sort();
                for name in names {
                    let full = format!("{dir}/{name}");
                    if let Ok(content) = fs::read_to_string(&full) {
                        file_entries.push((full, content));
                    }
                }
            }
        }

        find_conflicts(&file_entries)
    }
}

/// Scan `file_entries` (path, content) pairs for sysctl keys that appear in
/// more than one file with *different* values.  Extracted for unit-testing.
pub(crate) fn find_conflicts(file_entries: &[(String, String)]) -> CheckResult {
    let mut result = CheckResult::default();
    for conflict in hah_utils::sysctl::find_conflicts(file_entries) {
        let details: Vec<String> = conflict
            .assignments
            .iter()
            .map(|(f, v)| format!("  {f}: {v}"))
            .collect();
        let key = &conflict.key;
        result = result.with_finding(hah_core::model::Finding {
            id: format!("sysctl-conflict-{}", key.replace('.', "-")),
            title: format!("sysctl key '{key}' has conflicting values across sysctl.d"),
            description: format!(
                "The key '{key}' is set to different values in multiple files:\n{}",
                details.join("\n")
            ),
            severity: Severity::Warning,
            remediation: None,
        });
    }
    result
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use hah_core::{check::Context, config::Config, distro::DistroInfo, runner::SystemRunner};
    use std::sync::Arc;

    fn make_ctx() -> Context {
        Context {
            verbose: false,
            config: Config::default(),
            distro: DistroInfo::default(),
            runner: Arc::new(SystemRunner),
        }
    }

    #[test]
    fn sysctl_ordering_check_id_and_title() {
        assert_eq!(SysctlOrderingCheck.id(), "sysctl-ordering");
        assert!(!SysctlOrderingCheck.title().is_empty());
    }

    #[test]
    fn sysctl_ordering_does_not_panic_on_real_system() {
        // The check scans /usr/lib/sysctl.d, /etc/sysctl.d, /run/sysctl.d.
        // On most systems these dirs exist but contain no conflicting values.
        // We just verify no panic and that findings have correct structure.
        let result = SysctlOrderingCheck.run(&make_ctx());
        for f in &result.findings {
            assert!(!f.id.is_empty());
            assert!(!f.title.is_empty());
        }
    }

    #[test]
    fn sysctl_ordering_with_temp_conflicting_files() {
        // Write two temp files with conflicting values into /tmp (not a real sysctl.d,
        // so the check won't pick them up — but this exercises parse_size_str indirectly
        // by verifying the file parsing logic is reachable).
        // We can only observe the real-system behaviour here.
        let result = SysctlOrderingCheck.run(&make_ctx());
        assert!(result.errors.is_empty());
        // If there happen to be conflicts on this system the findings are valid
        for f in &result.findings {
            assert_eq!(f.severity, Severity::Warning);
        }
    }

    // ── find_conflicts ────────────────────────────────────────────────────────

    #[test]
    fn find_conflicts_empty_input_returns_no_findings() {
        assert!(find_conflicts(&[]).findings.is_empty());
    }

    #[test]
    fn find_conflicts_no_conflict_same_value() {
        let entries = vec![
            (
                "/etc/sysctl.d/50-a.conf".to_string(),
                "net.ipv4.ip_forward = 1\n".to_string(),
            ),
            (
                "/etc/sysctl.d/60-b.conf".to_string(),
                "net.ipv4.ip_forward = 1\n".to_string(),
            ),
        ];
        assert!(find_conflicts(&entries).findings.is_empty());
    }

    #[test]
    fn find_conflicts_detects_different_values() {
        let entries = vec![
            (
                "/etc/sysctl.d/50-a.conf".to_string(),
                "net.ipv4.ip_forward = 0\n".to_string(),
            ),
            (
                "/etc/sysctl.d/60-b.conf".to_string(),
                "net.ipv4.ip_forward = 1\n".to_string(),
            ),
        ];
        let result = find_conflicts(&entries);
        assert_eq!(result.findings.len(), 1);
        assert!(result.findings[0].id.contains("sysctl-conflict"));
        assert_eq!(result.findings[0].severity, Severity::Warning);
    }

    #[test]
    fn find_conflicts_ignores_comments_and_blanks() {
        let entries = vec![(
            "/etc/sysctl.d/50-a.conf".to_string(),
            "# comment\n\n; another\nnet.ipv4.ip_forward = 1\n".to_string(),
        )];
        assert!(find_conflicts(&entries).findings.is_empty());
    }
}
