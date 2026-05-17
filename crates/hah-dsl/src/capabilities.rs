//! Rust-backed capability functions for the declarative rule engine.
//!
//! Each function receives the context it needs (a [`CommandRunner`] for
//! command-based operations, or nothing for pure filesystem operations) and
//! returns a [`RuleValue`] ready for use in a pipeline expression.
//!
//! | Capability              | Returns                                   |
//! |-------------------------|-------------------------------------------|
//! | [`journal_usage_mb`]    | `Int(mb)` — total journal disk usage      |
//! | [`old_files`]           | `List(paths)` — files older than N days   |
//! | [`broken_symlinks`]     | `List(paths)` — broken symlink paths      |
//! | [`sysctl_conflicts`]    | `List(descriptions)` — conflicting keys   |
//! | [`kernel_inventory`]    | `List(pkgs)` — unused kernel packages     |
//! | [`stale_kernel_headers`]| `List(pkgs)` — stale header packages      |

use std::{fs, path::Path};

use anyhow::{Result, anyhow};

use hah_core::runner::CommandRunner;

use crate::pipeline::RuleValue;

// ── Default scan paths ────────────────────────────────────────────────────────

const DEFAULT_CRASH_DIRS: &[&str] = &["/var/crash", "/var/lib/systemd/coredump"];
const DEFAULT_SYMLINK_DIRS: &[&str] = &["/etc", "/usr/lib", "/var/lib"];
const DEFAULT_SYSCTL_DIRS: &[&str] = &["/usr/lib/sysctl.d", "/etc/sysctl.d", "/run/sysctl.d"];

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Resolve `dirs` against `defaults`: if `dirs` is empty the defaults are
/// used, otherwise the caller-supplied list is used verbatim.
fn effective_dirs<'a>(dirs: &'a [String], defaults: &'a [&'a str]) -> Vec<&'a str> {
    if dirs.is_empty() {
        defaults.to_vec()
    } else {
        dirs.iter().map(String::as_str).collect()
    }
}

// ── JournalUsage ─────────────────────────────────────────────────────────────

/// Return the total systemd journal disk usage as `Int(mb)`.
///
/// Returns `Int(0)` when the output cannot be parsed.
pub fn journal_usage_mb(runner: &dyn CommandRunner) -> Result<RuleValue> {
    let out = runner
        .run("journalctl", &["--disk-usage"])
        .map_err(|e| anyhow!("journalctl: {e}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let bytes = hah_utils::size::parse_journal_disk_usage(&stdout).unwrap_or(0);
    Ok(RuleValue::Int((bytes / 1_000_000) as i64))
}

// ── OldFiles ──────────────────────────────────────────────────────────────────

/// Return a `List` of file paths that have not been modified for at least
/// `older_than_days` days.
///
/// Scans [`DEFAULT_CRASH_DIRS`] when `dirs` is empty.
pub fn old_files(dirs: &[String], older_than_days: u64) -> Result<RuleValue> {
    let effective = effective_dirs(dirs, DEFAULT_CRASH_DIRS);
    let files: Vec<RuleValue> = hah_utils::fs::scan_old_files(&effective, older_than_days)
        .into_iter()
        .map(|f| RuleValue::Str(f.path.to_string_lossy().into_owned()))
        .collect();
    Ok(RuleValue::List(files))
}

// ── BrokenSymlinks ────────────────────────────────────────────────────────────

/// Return a `List` of paths that are broken symbolic links.
///
/// Scans [`DEFAULT_SYMLINK_DIRS`] when `dirs` is empty.
pub fn broken_symlinks(dirs: &[String]) -> Result<RuleValue> {
    let effective = effective_dirs(dirs, DEFAULT_SYMLINK_DIRS);
    let broken: Vec<RuleValue> = hah_utils::fs::broken_symlinks(&effective)
        .into_iter()
        .map(|p| RuleValue::Str(p.to_string_lossy().into_owned()))
        .collect();
    Ok(RuleValue::List(broken))
}

// ── SysctlConflicts ───────────────────────────────────────────────────────────

/// Return a `List` of conflict descriptions for sysctl keys that appear with
/// different values across `*.conf` files.
///
/// Each item has the form `"<key>: <file>=<val>, <file>=<val>"`.
/// Scans [`DEFAULT_SYSCTL_DIRS`] when `dirs` is empty.
pub fn sysctl_conflicts(dirs: &[String]) -> Result<RuleValue> {
    let effective = effective_dirs(dirs, DEFAULT_SYSCTL_DIRS);

    let mut file_entries: Vec<(String, String)> = Vec::new();
    for dir in effective {
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

    let conflicts: Vec<RuleValue> = hah_utils::sysctl::find_conflicts(&file_entries)
        .into_iter()
        .map(|c| {
            let detail = c
                .assignments
                .iter()
                .map(|(f, v)| format!("{f}={v}"))
                .collect::<Vec<_>>()
                .join(", ");
            RuleValue::Str(format!("{}: {detail}", c.key))
        })
        .collect();
    Ok(RuleValue::List(conflicts))
}

// ── KernelInventory ───────────────────────────────────────────────────────────

/// Return a `List` of installed `linux-image-*` package names that do **not**
/// contain the currently running kernel version string (i.e., safely removable
/// unused kernels).
pub fn kernel_inventory(runner: &dyn CommandRunner) -> Result<RuleValue> {
    let out = runner
        .run("uname", &["-r"])
        .map_err(|e| anyhow!("uname: {e}"))?;
    let running = String::from_utf8_lossy(&out.stdout).trim().to_string();

    let out = runner
        .run(
            "dpkg-query",
            &["--show", "--showformat=${Package}\n", "linux-image-*"],
        )
        .map_err(|e| anyhow!("dpkg-query (kernels): {e}"))?;

    let unused: Vec<RuleValue> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|pkg| !pkg.is_empty() && !pkg.contains(running.as_str()))
        .map(|pkg| RuleValue::Str(pkg.to_string()))
        .collect();

    Ok(RuleValue::List(unused))
}

// ── StaleKernelHeaders ────────────────────────────────────────────────────────

/// Return a `List` of `linux-headers-*` packages whose version string has no
/// matching `linux-image-*` package installed.
///
/// Meta-packages (e.g., `linux-headers-generic`) that have no numeric version
/// suffix are skipped.
pub fn stale_kernel_headers(runner: &dyn CommandRunner) -> Result<RuleValue> {
    let out_headers = runner
        .run(
            "dpkg-query",
            &["--show", "--showformat=${Package}\n", "linux-headers-*"],
        )
        .map_err(|e| anyhow!("dpkg-query (headers): {e}"))?;

    let out_kernels = runner
        .run(
            "dpkg-query",
            &["--show", "--showformat=${Package}\n", "linux-image-*"],
        )
        .map_err(|e| anyhow!("dpkg-query (kernels): {e}"))?;
    let kernels: Vec<String> = String::from_utf8_lossy(&out_kernels.stdout)
        .lines()
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect();

    let stale: Vec<RuleValue> = String::from_utf8_lossy(&out_headers.stdout)
        .lines()
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .filter(|hdr| {
            let version = hdr.trim_start_matches("linux-headers-");
            version.chars().next().is_some_and(char::is_numeric)
                && !kernels.iter().any(|k| k.contains(version))
        })
        .map(RuleValue::Str)
        .collect();

    Ok(RuleValue::List(stale))
}

// ── NtpActiveServices ─────────────────────────────────────────────────────────

/// Return a `List` of active NTP service labels.
///
/// Checks `ntp`, `chrony`, `openntpd`, and `systemd-timesyncd`.
pub fn ntp_active_services(runner: &dyn CommandRunner) -> Result<RuleValue> {
    let candidates = [
        ("ntp", "ntp (ntpd)"),
        ("chrony", "chrony"),
        ("openntpd", "openntpd"),
        ("systemd-timesyncd", "systemd-timesyncd"),
    ];
    let active: Vec<RuleValue> = candidates
        .iter()
        .filter(|(svc, _)| {
            runner
                .run("systemctl", &["is-active", "--quiet", svc])
                .is_ok_and(|o| o.success)
        })
        .map(|(_, label)| RuleValue::Str((*label).into()))
        .collect();
    Ok(RuleValue::List(active))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use hah_core::runner::{CommandOutput, MockCommandRunner};
    use std::io;
    use std::time::{Duration, SystemTime};
    use tempfile::TempDir;

    fn ok_out(stdout: &str) -> io::Result<CommandOutput> {
        Ok(CommandOutput {
            stdout: stdout.as_bytes().to_vec(),
            stderr: vec![],
            success: true,
        })
    }

    // ── parse_journal_disk_usage (via hah_utils) ──────────────────────────────

    #[test]
    fn parse_journal_gigabytes() {
        let input = "Archived and active journals take up 1.5G in the file system.";
        assert_eq!(
            hah_utils::size::parse_journal_disk_usage(input),
            Some(1_500_000_000)
        );
    }

    #[test]
    fn parse_journal_megabytes() {
        let input = "Archived and active journals take up 512.0M.";
        assert_eq!(
            hah_utils::size::parse_journal_disk_usage(input),
            Some(512_000_000)
        );
    }

    #[test]
    fn parse_journal_kilobytes() {
        let input = "Archived and active journals take up 256K in the file system.";
        assert_eq!(
            hah_utils::size::parse_journal_disk_usage(input),
            Some(256_000)
        );
    }

    #[test]
    fn parse_journal_unrecognized_returns_none() {
        assert_eq!(
            hah_utils::size::parse_journal_disk_usage("no match here"),
            None
        );
        assert_eq!(hah_utils::size::parse_bytes("42XB"), None);
    }

    // ── journal_usage_mb ─────────────────────────────────────────────────────

    #[test]
    fn journal_usage_mb_parses_correctly() {
        let mut mock = MockCommandRunner::new();
        mock.expect_run()
            .returning(|_, _| ok_out("Archived and active journals take up 600.0M.\n"));
        let result = journal_usage_mb(&mock).unwrap();
        assert_eq!(result, RuleValue::Int(600));
    }

    #[test]
    fn journal_usage_mb_returns_zero_on_unparseable_output() {
        let mut mock = MockCommandRunner::new();
        mock.expect_run()
            .returning(|_, _| ok_out("something unexpected\n"));
        let result = journal_usage_mb(&mock).unwrap();
        assert_eq!(result, RuleValue::Int(0));
    }

    #[test]
    fn journal_usage_mb_propagates_command_error() {
        let mut mock = MockCommandRunner::new();
        mock.expect_run()
            .returning(|_, _| Err(io::Error::new(io::ErrorKind::NotFound, "not found")));
        assert!(journal_usage_mb(&mock).is_err());
    }

    // ── old_files ─────────────────────────────────────────────────────────────

    #[test]
    fn old_files_empty_dir_returns_empty_list() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_string_lossy().to_string();
        let result = old_files(&[dir], 30).unwrap();
        assert_eq!(result, RuleValue::List(vec![]));
    }

    #[test]
    fn old_files_nonexistent_dir_returns_empty_list() {
        let result = old_files(&["/nonexistent/path/xyz".to_string()], 30).unwrap();
        assert_eq!(result, RuleValue::List(vec![]));
    }

    #[test]
    fn old_files_recent_file_not_included() {
        let tmp = TempDir::new().unwrap();
        let file = tmp.path().join("recent.log");
        std::fs::write(&file, b"data").unwrap();
        let dir = tmp.path().to_string_lossy().to_string();
        // threshold of 30 days; recently created file should not appear
        let result = old_files(&[dir], 30).unwrap();
        assert_eq!(result, RuleValue::List(vec![]));
    }

    #[test]
    fn old_files_old_file_included() {
        use filetime::{FileTime, set_file_mtime};
        let tmp = TempDir::new().unwrap();
        let file = tmp.path().join("old.log");
        std::fs::write(&file, b"data").unwrap();
        // Set mtime to 60 days ago
        let old_time = SystemTime::now()
            .checked_sub(Duration::from_secs(60 * 86_400))
            .unwrap();
        set_file_mtime(&file, FileTime::from_system_time(old_time)).unwrap();

        let dir = tmp.path().to_string_lossy().to_string();
        let result = old_files(&[dir], 30).unwrap();
        let RuleValue::List(items) = result else {
            panic!("expected list");
        };
        assert_eq!(items.len(), 1);
        assert!(items[0].display().contains("old.log"));
    }

    #[test]
    fn old_files_uses_default_dirs_when_empty() {
        // /var/crash typically doesn't exist in CI; just verify it returns Ok
        let result = old_files(&[], 30);
        assert!(result.is_ok());
    }

    // ── broken_symlinks ───────────────────────────────────────────────────────

    #[test]
    fn broken_symlinks_empty_dir_returns_empty_list() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_string_lossy().to_string();
        let result = broken_symlinks(&[dir]).unwrap();
        assert_eq!(result, RuleValue::List(vec![]));
    }

    #[test]
    fn broken_symlinks_detects_dangling_symlink() {
        let tmp = TempDir::new().unwrap();
        let link = tmp.path().join("dangling");
        std::os::unix::fs::symlink("/nonexistent/target", &link).unwrap();
        let dir = tmp.path().to_string_lossy().to_string();
        let result = broken_symlinks(&[dir]).unwrap();
        let RuleValue::List(items) = result else {
            panic!("expected list");
        };
        assert_eq!(items.len(), 1);
        assert!(items[0].display().contains("dangling"));
    }

    #[test]
    fn broken_symlinks_valid_symlink_not_included() {
        let tmp = TempDir::new().unwrap();
        let target = tmp.path().join("target.txt");
        std::fs::write(&target, b"x").unwrap();
        let link = tmp.path().join("valid_link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let dir = tmp.path().to_string_lossy().to_string();
        let result = broken_symlinks(&[dir]).unwrap();
        assert_eq!(result, RuleValue::List(vec![]));
    }

    #[test]
    fn broken_symlinks_uses_default_dirs_when_empty() {
        let result = broken_symlinks(&[]);
        assert!(result.is_ok());
    }

    // ── sysctl_conflicts ──────────────────────────────────────────────────────

    #[test]
    fn sysctl_conflicts_nonexistent_dir_returns_empty() {
        let result = sysctl_conflicts(&["/nonexistent/sysctl.d".to_string()]).unwrap();
        assert_eq!(result, RuleValue::List(vec![]));
    }

    #[test]
    fn sysctl_conflicts_detects_conflict() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("10-net.conf"), "net.ipv4.ip_forward = 0\n").unwrap();
        std::fs::write(tmp.path().join("20-net.conf"), "net.ipv4.ip_forward = 1\n").unwrap();
        let dir = tmp.path().to_string_lossy().to_string();
        let result = sysctl_conflicts(&[dir]).unwrap();
        let RuleValue::List(items) = result else {
            panic!("expected list");
        };
        assert_eq!(items.len(), 1);
        assert!(items[0].display().contains("net.ipv4.ip_forward"));
    }

    #[test]
    fn sysctl_conflicts_same_value_no_conflict() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("10-a.conf"), "vm.swappiness = 10\n").unwrap();
        std::fs::write(tmp.path().join("20-b.conf"), "vm.swappiness = 10\n").unwrap();
        let dir = tmp.path().to_string_lossy().to_string();
        let result = sysctl_conflicts(&[dir]).unwrap();
        assert_eq!(result, RuleValue::List(vec![]));
    }

    #[test]
    fn sysctl_conflicts_skips_comments_and_empty_lines() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(
            tmp.path().join("10-a.conf"),
            "# comment\n; another comment\n\nnet.ipv4.ip_forward = 1\n",
        )
        .unwrap();
        std::fs::write(tmp.path().join("20-b.conf"), "net.ipv4.ip_forward = 1\n").unwrap();
        let dir = tmp.path().to_string_lossy().to_string();
        let result = sysctl_conflicts(&[dir]).unwrap();
        assert_eq!(result, RuleValue::List(vec![]));
    }

    #[test]
    fn sysctl_conflicts_uses_default_dirs_when_empty() {
        let result = sysctl_conflicts(&[]);
        assert!(result.is_ok());
    }

    // ── kernel_inventory ──────────────────────────────────────────────────────

    #[test]
    fn kernel_inventory_excludes_running_kernel() {
        let mut mock = MockCommandRunner::new();
        mock.expect_run()
            .withf(|prog, _| *prog == *"uname")
            .returning(|_, _| ok_out("6.5.0-35-generic\n"));
        mock.expect_run()
            .withf(|prog, _| *prog == *"dpkg-query")
            .returning(|_, _| {
                ok_out(
                    "linux-image-6.5.0-35-generic\nlinux-image-6.5.0-27-generic\nlinux-image-6.5.0-28-generic\n",
                )
            });
        let result = kernel_inventory(&mock).unwrap();
        let RuleValue::List(items) = result else {
            panic!("expected list");
        };
        assert_eq!(items.len(), 2);
        assert!(!items.iter().any(|i| i.display().contains("35")));
    }

    #[test]
    fn kernel_inventory_all_removed_when_all_match_running() {
        let mut mock = MockCommandRunner::new();
        mock.expect_run()
            .withf(|prog, _| *prog == *"uname")
            .returning(|_, _| ok_out("6.5.0-35-generic\n"));
        mock.expect_run()
            .withf(|prog, _| *prog == *"dpkg-query")
            .returning(|_, _| ok_out("linux-image-6.5.0-35-generic\n"));
        let result = kernel_inventory(&mock).unwrap();
        assert_eq!(result, RuleValue::List(vec![]));
    }

    #[test]
    fn kernel_inventory_propagates_uname_error() {
        let mut mock = MockCommandRunner::new();
        mock.expect_run()
            .returning(|_, _| Err(io::Error::new(io::ErrorKind::NotFound, "not found")));
        assert!(kernel_inventory(&mock).is_err());
    }

    // ── stale_kernel_headers ──────────────────────────────────────────────────

    #[test]
    fn stale_kernel_headers_detects_stale() {
        let mut mock = MockCommandRunner::new();
        // First call: headers
        mock.expect_run()
            .withf(|_, args| args.contains(&"linux-headers-*"))
            .returning(|_, _| ok_out("linux-headers-6.5.0-27-generic\nlinux-headers-generic\n"));
        // Second call: kernels
        mock.expect_run()
            .withf(|_, args| args.contains(&"linux-image-*"))
            .returning(|_, _| ok_out("linux-image-6.5.0-35-generic\n"));
        let result = stale_kernel_headers(&mock).unwrap();
        let RuleValue::List(items) = result else {
            panic!("expected list");
        };
        // 6.5.0-27 has no matching image; generic (non-numeric) is skipped
        assert_eq!(items.len(), 1);
        assert!(items[0].display().contains("6.5.0-27"));
    }

    #[test]
    fn stale_kernel_headers_skips_meta_packages() {
        let mut mock = MockCommandRunner::new();
        mock.expect_run()
            .withf(|_, args| args.contains(&"linux-headers-*"))
            .returning(|_, _| ok_out("linux-headers-generic\n"));
        mock.expect_run()
            .withf(|_, args| args.contains(&"linux-image-*"))
            .returning(|_, _| ok_out("linux-image-6.5.0-35-generic\n"));
        let result = stale_kernel_headers(&mock).unwrap();
        assert_eq!(result, RuleValue::List(vec![]));
    }

    #[test]
    fn stale_kernel_headers_propagates_error() {
        let mut mock = MockCommandRunner::new();
        mock.expect_run()
            .returning(|_, _| Err(io::Error::new(io::ErrorKind::NotFound, "not found")));
        assert!(stale_kernel_headers(&mock).is_err());
    }
}
