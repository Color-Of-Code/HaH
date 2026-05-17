use hah_core::{
    check::{Check, Context},
    model::{CheckResult, Finding, Remediation, Severity},
};

use hah_utils::fs::sanitize_id;

// ── OldCrashDumpsCheck ───────────────────────────────────────────────────────

pub struct OldCrashDumpsCheck;

const CRASH_DIRS: &[&str] = &["/var/crash", "/var/lib/systemd/coredump"];
const MAX_AGE_DAYS: u64 = 30;

impl Check for OldCrashDumpsCheck {
    fn id(&self) -> &str {
        "old-crash-dumps"
    }

    fn title(&self) -> &str {
        "Old crash dumps and core files"
    }

    fn run(&self, ctx: &Context) -> CheckResult {
        let max_days = ctx.config.threshold("crash_dump_max_days", MAX_AGE_DAYS);
        scan_crash_dirs(CRASH_DIRS, max_days)
    }
}

/// Scan `dirs` for files older than `max_days` days and build findings.
/// Extracted for deterministic unit-testing with temp directories.
pub(crate) fn scan_crash_dirs(dirs: &[&str], max_days: u64) -> CheckResult {
    let mut result = CheckResult::default();
    for old_file in hah_utils::fs::scan_old_files(dirs, max_days) {
        let name = old_file
            .path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let parent = old_file
            .path
            .parent()
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        result = result.with_finding(Finding {
            id: format!("crash-dump-{}", sanitize_id(&name)),
            title: format!("Old crash dump: {name} ({} KB)", old_file.size_kb),
            description: format!(
                "{parent}/{name} is more than {max_days} days old and occupies {} KB.",
                old_file.size_kb
            ),
            severity: Severity::Info,
            remediation: Some(Remediation {
                description: "Remove old crash dump.".into(),
                commands: vec![format!("sudo rm {parent}/{name}")],
            }),
        });
    }
    result
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::if_same_then_else)]
mod tests {
    use super::*;
    use hah_core::{check::Context, config::Config, distro::DistroInfo, runner::CommandRunner};
    use mockall::mock;
    use std::sync::Arc;
    use std::time::{Duration, SystemTime};

    mock! {
        Runner {}
        impl CommandRunner for Runner {
            fn run<'a>(&self, program: &'a str, args: &'a [&'a str]) -> std::io::Result<hah_core::runner::CommandOutput>;
        }
    }

    fn make_ctx(runner: Arc<dyn CommandRunner>) -> Context {
        Context {
            verbose: false,
            config: Config::default(),
            distro: DistroInfo::default(),
            runner,
        }
    }

    // ── OldCrashDumpsCheck ────────────────────────────────────────────────────

    #[test]
    fn old_crash_dumps_id_and_title() {
        assert_eq!(OldCrashDumpsCheck.id(), "old-crash-dumps");
        assert!(!OldCrashDumpsCheck.title().is_empty());
    }

    #[test]
    fn old_crash_dumps_does_not_panic() {
        let ctx = make_ctx(Arc::new(MockRunner::new()));
        let _ = OldCrashDumpsCheck.run(&ctx);
    }

    #[test]
    fn old_crash_dumps_custom_threshold() {
        let mut config = Config::default();
        config.thresholds.insert("crash_dump_max_days".into(), 7);
        let ctx = Context {
            config,
            ..make_ctx(Arc::new(MockRunner::new()))
        };
        let _ = OldCrashDumpsCheck.run(&ctx);
    }

    #[test]
    fn scan_crash_dirs_empty_returns_no_findings() {
        let tmp = tempfile::tempdir().unwrap();
        let result = scan_crash_dirs(&[tmp.path().to_str().unwrap()], 30);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn scan_crash_dirs_recent_file_not_reported() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("core"), b"data").unwrap();
        // A recently-created file is newer than the 30-day threshold → no finding
        let result = scan_crash_dirs(&[tmp.path().to_str().unwrap()], 30);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn scan_crash_dirs_old_file_produces_finding() {
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("core.old");
        std::fs::write(&f, b"data").unwrap();
        // Set mtime to 60 days ago
        let sixty_days_ago = std::time::UNIX_EPOCH
            + Duration::from_secs(
                SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    - 60 * 86400,
            );
        filetime::set_file_mtime(&f, filetime::FileTime::from_system_time(sixty_days_ago)).unwrap();
        // threshold = 30 days ago → file (60d old) is older → should produce finding
        let result = scan_crash_dirs(&[tmp.path().to_str().unwrap()], 30);
        assert_eq!(result.findings.len(), 1);
        assert!(result.findings[0].id.starts_with("crash-dump-"));
    }
}
