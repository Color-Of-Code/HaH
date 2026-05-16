use hah_core::{
    check::{Check, Context},
    model::{CheckResult, Finding, Remediation, Severity},
};

use hah_utils::fs::sanitize_id;

// ── BrokenSymlinksCheck ──────────────────────────────────────────────────────

pub struct BrokenSymlinksCheck;

const SCAN_DIRS: &[&str] = &["/etc", "/usr/lib", "/var/lib"];

impl Check for BrokenSymlinksCheck {
    fn id(&self) -> &str {
        "broken-symlinks"
    }

    fn title(&self) -> &str {
        "Broken symbolic links"
    }

    fn run(&self, _ctx: &Context) -> CheckResult {
        scan_for_broken_symlinks(SCAN_DIRS)
    }
}

/// Walk `dirs` and collect a finding for every symlink that points to a
/// non-existent target.  Extracted so it can be unit-tested with temp dirs.
pub(crate) fn scan_for_broken_symlinks(dirs: &[&str]) -> CheckResult {
    let mut result = CheckResult::default();
    for path in hah_utils::fs::broken_symlinks(dirs) {
        result = result.with_finding(Finding {
            id: format!("broken-symlink-{}", sanitize_id(&path.to_string_lossy())),
            title: format!("Broken symlink: {}", path.display()),
            description: format!(
                "The symlink {} points to a non-existent target.",
                path.display()
            ),
            severity: Severity::Warning,
            remediation: Some(Remediation {
                description: "Remove the broken symlink.".into(),
                commands: vec![format!("sudo rm {}", path.display())],
                safe: false,
            }),
        });
    }
    result
}

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
                safe: false,
            }),
        });
    }
    result
}

// ── JournalSizeCheck ─────────────────────────────────────────────────────────

pub struct JournalSizeCheck;

impl Check for JournalSizeCheck {
    fn id(&self) -> &str {
        "journal-size"
    }

    fn title(&self) -> &str {
        "systemd journal disk usage"
    }

    fn run(&self, ctx: &Context) -> CheckResult {
        let threshold_mb = ctx.config.threshold("journal_size_mb", 500);

        let out = match ctx.runner.run("journalctl", &["--disk-usage"]) {
            Ok(o) => o,
            Err(_) => return CheckResult::default(),
        };

        let stdout = String::from_utf8_lossy(&out.stdout);
        let size_bytes = hah_utils::size::parse_journal_disk_usage(&stdout).unwrap_or(0);
        let threshold_bytes = threshold_mb * 1_000_000;

        if size_bytes > threshold_bytes {
            let size_mb = size_bytes / 1_000_000;
            CheckResult::default().with_finding(Finding {
                id: "journal-size-large".into(),
                title: format!("systemd journal is {size_mb} MB"),
                description: format!(
                    "The systemd journal occupies {size_mb} MB, \
                     exceeding the {threshold_mb} MB threshold."
                ),
                severity: Severity::Warning,
                remediation: Some(Remediation {
                    description: "Vacuum the journal to reclaim space.".into(),
                    commands: vec![format!("sudo journalctl --vacuum-size={threshold_mb}M")],
                    safe: true,
                }),
            })
        } else {
            CheckResult::default()
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::if_same_then_else)]
mod tests {
    use super::*;
    use hah_core::{
        check::Context,
        config::Config,
        distro::DistroInfo,
        runner::{CommandOutput, CommandRunner},
    };
    use mockall::mock;
    use std::sync::Arc;
    use std::time::{Duration, SystemTime};

    mock! {
        Runner {}
        impl CommandRunner for Runner {
            fn run<'a>(&self, program: &'a str, args: &'a [&'a str]) -> std::io::Result<CommandOutput>;
        }
    }

    fn ok_output(stdout: &str) -> CommandOutput {
        CommandOutput {
            stdout: stdout.as_bytes().to_vec(),
            stderr: vec![],
            success: true,
        }
    }

    fn make_ctx(runner: Arc<dyn CommandRunner>) -> Context {
        Context {
            dry_run: false,
            verbose: false,
            config: Config::default(),
            distro: DistroInfo::default(),
            runner,
        }
    }

    // ── JournalSizeCheck ──────────────────────────────────────────────────────

    #[test]
    fn journal_size_id_and_title() {
        assert_eq!(JournalSizeCheck.id(), "journal-size");
        assert!(!JournalSizeCheck.title().is_empty());
    }

    #[test]
    fn journal_size_below_default_threshold() {
        let mut runner = MockRunner::new();
        runner.expect_run().returning(|_, _| {
            Ok(ok_output(
                "Archived and active journals take up 100M in the file system.\n",
            ))
        });
        assert!(
            JournalSizeCheck
                .run(&make_ctx(Arc::new(runner)))
                .findings
                .is_empty()
        );
    }

    #[test]
    fn journal_size_above_default_threshold() {
        let mut runner = MockRunner::new();
        runner.expect_run().returning(|_, _| {
            Ok(ok_output(
                "Archived and active journals take up 2G in the file system.\n",
            ))
        });
        let result = JournalSizeCheck.run(&make_ctx(Arc::new(runner)));
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].severity, Severity::Warning);
    }

    #[test]
    fn journal_size_runner_error_returns_empty() {
        let mut runner = MockRunner::new();
        runner.expect_run().returning(|_, _| {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "not found",
            ))
        });
        assert!(
            JournalSizeCheck
                .run(&make_ctx(Arc::new(runner)))
                .findings
                .is_empty()
        );
    }

    #[test]
    fn journal_size_custom_threshold_not_exceeded() {
        let mut runner = MockRunner::new();
        runner.expect_run().returning(|_, _| {
            Ok(ok_output(
                "Archived and active journals take up 1G in the file system.\n",
            ))
        });
        let mut config = Config::default();
        config.thresholds.insert("journal_size_mb".into(), 2048); // 2 GB threshold
        let ctx = Context {
            config,
            ..make_ctx(Arc::new(runner))
        };
        assert!(JournalSizeCheck.run(&ctx).findings.is_empty());
    }

    #[test]
    fn journal_size_output_without_size_returns_empty() {
        let mut runner = MockRunner::new();
        runner
            .expect_run()
            .returning(|_, _| Ok(ok_output("No journal files found.\n")));
        assert!(
            JournalSizeCheck
                .run(&make_ctx(Arc::new(runner)))
                .findings
                .is_empty()
        );
    }

    // ── BrokenSymlinksCheck ───────────────────────────────────────────────────

    #[test]
    fn broken_symlinks_id_and_title() {
        assert_eq!(BrokenSymlinksCheck.id(), "broken-symlinks");
        assert!(!BrokenSymlinksCheck.title().is_empty());
    }

    #[test]
    fn broken_symlinks_does_not_panic() {
        let ctx = make_ctx(Arc::new(MockRunner::new()));
        let result = BrokenSymlinksCheck.run(&ctx);
        for f in &result.findings {
            assert!(!f.id.is_empty());
        }
    }

    #[test]
    fn scan_for_broken_symlinks_empty_dir_returns_no_findings() {
        let tmp = tempfile::tempdir().unwrap();
        let result = scan_for_broken_symlinks(&[tmp.path().to_str().unwrap()]);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn scan_for_broken_symlinks_detects_broken_link() {
        let tmp = tempfile::tempdir().unwrap();
        let link = tmp.path().join("broken");
        std::os::unix::fs::symlink("/nonexistent/target_xyz", &link).unwrap();
        let result = scan_for_broken_symlinks(&[tmp.path().to_str().unwrap()]);
        assert_eq!(result.findings.len(), 1);
        assert!(result.findings[0].description.contains("broken"));
    }

    #[test]
    fn scan_for_broken_symlinks_valid_link_is_not_reported() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("real");
        std::fs::write(&target, "data").unwrap();
        let link = tmp.path().join("valid_link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let result = scan_for_broken_symlinks(&[tmp.path().to_str().unwrap()]);
        assert!(result.findings.is_empty());
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
