//! Filesystem scan capabilities: old files and broken symlinks.

use std::path::Path;

use anyhow::Result;

use crate::CapValue;

const DEFAULT_CRASH_DIRS: &[&str] = &["/var/crash", "/var/lib/systemd/coredump"];
const DEFAULT_SYMLINK_DIRS: &[&str] = &["/etc", "/usr/lib", "/var/lib"];

fn effective_dirs<'a>(dirs: &'a [String], defaults: &'a [&'a str]) -> Vec<&'a str> {
    if dirs.is_empty() {
        defaults.to_vec()
    } else {
        dirs.iter().map(String::as_str).collect()
    }
}

/// Return a list of file paths that have not been modified for at least
/// `older_than_days` days.
///
/// Scans `/var/crash` and `/var/lib/systemd/coredump` when `dirs` is empty.
pub fn old_files(dirs: &[String], older_than_days: u64) -> Result<CapValue> {
    let effective = effective_dirs(dirs, DEFAULT_CRASH_DIRS);
    let files: Vec<String> = hah_utils::fs::scan_old_files(&effective, older_than_days)
        .into_iter()
        .map(|f| f.path.to_string_lossy().into_owned())
        .collect();
    Ok(CapValue::List(files))
}

/// Return a list of paths that are broken symbolic links.
///
/// Scans `/etc`, `/usr/lib`, and `/var/lib` when `dirs` is empty.
pub fn broken_symlinks(dirs: &[String]) -> Result<CapValue> {
    let effective = effective_dirs(dirs, DEFAULT_SYMLINK_DIRS);
    let broken: Vec<String> = hah_utils::fs::broken_symlinks(&effective)
        .into_iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    Ok(CapValue::List(broken))
}

/// Return a list of file paths using the legacy one-line `deb`/`deb-src`
/// APT source format.
///
/// Checks `/etc/apt/sources.list` and all `*.list` files in
/// `/etc/apt/sources.list.d/`.
pub fn legacy_apt_sources() -> Result<CapValue> {
    collect_legacy_sources(
        Path::new("/etc/apt/sources.list"),
        Path::new("/etc/apt/sources.list.d"),
    )
}

pub(crate) fn collect_legacy_sources(sources_list: &Path, sources_d: &Path) -> Result<CapValue> {
    use std::fs;

    let mut legacy: Vec<String> = Vec::new();

    if sources_list.exists()
        && fs::read_to_string(sources_list).is_ok_and(|content| {
            content
                .lines()
                .any(|l| l.starts_with("deb ") || l.starts_with("deb-src "))
        })
    {
        legacy.push(sources_list.to_string_lossy().into_owned());
    }

    if let Ok(entries) = fs::read_dir(sources_d) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("list")
                && fs::read_to_string(&path).is_ok_and(|content| {
                    content
                        .lines()
                        .any(|l| l.starts_with("deb ") || l.starts_with("deb-src "))
                })
            {
                legacy.push(path.to_string_lossy().into_owned());
            }
        }
    }

    Ok(CapValue::List(legacy))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};
    use tempfile::TempDir;

    // ── old_files ─────────────────────────────────────────────────────────────

    #[test]
    fn old_files_empty_dir_returns_empty_list() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_string_lossy().to_string();
        let result = old_files(&[dir], 30).unwrap();
        assert_eq!(result, CapValue::List(vec![]));
    }

    #[test]
    fn old_files_nonexistent_dir_returns_empty_list() {
        let result = old_files(&["/nonexistent/path/xyz".to_string()], 30).unwrap();
        assert_eq!(result, CapValue::List(vec![]));
    }

    #[test]
    fn old_files_recent_file_not_included() {
        let tmp = TempDir::new().unwrap();
        let file = tmp.path().join("recent.log");
        std::fs::write(&file, b"data").unwrap();
        let dir = tmp.path().to_string_lossy().to_string();
        let result = old_files(&[dir], 30).unwrap();
        assert_eq!(result, CapValue::List(vec![]));
    }

    #[test]
    fn old_files_old_file_included() {
        use filetime::{FileTime, set_file_mtime};
        let tmp = TempDir::new().unwrap();
        let file = tmp.path().join("old.log");
        std::fs::write(&file, b"data").unwrap();
        let old_time = SystemTime::now()
            .checked_sub(Duration::from_secs(60 * 86_400))
            .unwrap();
        set_file_mtime(&file, FileTime::from_system_time(old_time)).unwrap();

        let dir = tmp.path().to_string_lossy().to_string();
        let result = old_files(&[dir], 30).unwrap();
        let CapValue::List(items) = result else {
            panic!("expected list");
        };
        assert_eq!(items.len(), 1);
        assert!(items[0].contains("old.log"));
    }

    #[test]
    fn old_files_uses_default_dirs_when_empty() {
        let result = old_files(&[], 30);
        assert!(result.is_ok());
    }

    // ── broken_symlinks ───────────────────────────────────────────────────────

    #[test]
    fn broken_symlinks_empty_dir_returns_empty_list() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_string_lossy().to_string();
        let result = broken_symlinks(&[dir]).unwrap();
        assert_eq!(result, CapValue::List(vec![]));
    }

    #[test]
    fn broken_symlinks_detects_dangling_symlink() {
        let tmp = TempDir::new().unwrap();
        let link = tmp.path().join("dangling");
        std::os::unix::fs::symlink("/nonexistent/target", &link).unwrap();
        let dir = tmp.path().to_string_lossy().to_string();
        let result = broken_symlinks(&[dir]).unwrap();
        let CapValue::List(items) = result else {
            panic!("expected list");
        };
        assert_eq!(items.len(), 1);
        assert!(items[0].contains("dangling"));
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
        assert_eq!(result, CapValue::List(vec![]));
    }

    #[test]
    fn broken_symlinks_uses_default_dirs_when_empty() {
        let result = broken_symlinks(&[]);
        assert!(result.is_ok());
    }

    // ── legacy_apt_sources ────────────────────────────────────────────────────

    #[test]
    fn legacy_apt_sources_returns_ok() {
        let result = legacy_apt_sources();
        assert!(result.is_ok());
    }

    #[test]
    fn collect_legacy_sources_detects_deb_line() {
        let tmp = TempDir::new().unwrap();
        let list = tmp.path().join("sources.list");
        std::fs::write(&list, "deb http://archive.ubuntu.com/ubuntu focal main\n").unwrap();
        let d = tmp.path().join("sources.list.d");
        std::fs::create_dir_all(&d).unwrap();
        let result = collect_legacy_sources(&list, &d).unwrap();
        let CapValue::List(items) = result else {
            panic!("expected list");
        };
        assert_eq!(items.len(), 1);
    }

    #[test]
    fn collect_legacy_sources_detects_list_files_in_dir() {
        let tmp = TempDir::new().unwrap();
        let list = tmp.path().join("sources.list");
        std::fs::write(&list, "# no deb lines\n").unwrap();
        let d = tmp.path().join("sources.list.d");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(
            d.join("extra.list"),
            "deb-src http://example.com/ stable main\n",
        )
        .unwrap();
        std::fs::write(d.join("modern.sources"), "Types: deb\n").unwrap();
        let result = collect_legacy_sources(&list, &d).unwrap();
        let CapValue::List(items) = result else {
            panic!("expected list");
        };
        assert_eq!(items.len(), 1);
        assert!(items[0].contains("extra.list"));
    }

    #[test]
    fn collect_legacy_sources_empty_when_no_deb_lines() {
        let tmp = TempDir::new().unwrap();
        let list = tmp.path().join("sources.list");
        std::fs::write(&list, "# comment only\n").unwrap();
        let d = tmp.path().join("sources.list.d");
        std::fs::create_dir_all(&d).unwrap();
        let result = collect_legacy_sources(&list, &d).unwrap();
        assert_eq!(result, CapValue::List(vec![]));
    }
}
