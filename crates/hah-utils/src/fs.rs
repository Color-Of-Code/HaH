//! Filesystem utilities shared across the HaH workspace.

use std::{
    fs,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use walkdir::WalkDir;

// ── sanitize_id ───────────────────────────────────────────────────────────────

/// Replace every character that is not alphanumeric or `-` with `-`, then
/// trim leading and trailing hyphens.
///
/// Used to turn arbitrary path strings and file names into valid finding IDs.
pub fn sanitize_id(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}

// ── OldFile ───────────────────────────────────────────────────────────────────

/// A file entry returned by [`scan_old_files`].
pub struct OldFile {
    /// Absolute path to the file.
    pub path: PathBuf,
    /// File size in kilobytes (truncated, not rounded).
    pub size_kb: u64,
}

// ── scan_old_files ────────────────────────────────────────────────────────────

/// Walk the top level of each directory in `dirs` and return every file whose
/// last-modified time is older than `older_than_days` days.
///
/// Directories that do not exist are silently skipped.
/// Errors reading individual entries are silently skipped.
pub fn scan_old_files(dirs: &[impl AsRef<str>], older_than_days: u64) -> Vec<OldFile> {
    let threshold = SystemTime::now()
        .checked_sub(Duration::from_secs(older_than_days * 86_400))
        .unwrap_or(SystemTime::UNIX_EPOCH);

    let mut files = Vec::new();
    for dir in dirs {
        let path = Path::new(dir.as_ref());
        if !path.exists() {
            continue;
        }
        let entries = match fs::read_dir(path) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            let modified = match meta.modified() {
                Ok(t) => t,
                Err(_) => continue,
            };
            if modified < threshold {
                files.push(OldFile {
                    path: entry.path(),
                    size_kb: meta.len() / 1024,
                });
            }
        }
    }
    files
}

// ── broken_symlinks ───────────────────────────────────────────────────────────

/// Recursively walk each directory in `dirs` (without following symlinks) and
/// return the path of every symbolic link whose target does not exist.
///
/// Directories that do not exist are silently skipped.
pub fn broken_symlinks(dirs: &[impl AsRef<str>]) -> Vec<PathBuf> {
    let mut result = Vec::new();
    for dir in dirs {
        for entry in WalkDir::new(dir.as_ref())
            .follow_links(false)
            .into_iter()
            .filter_map(Result::ok)
        {
            let path = entry.path();
            if path.is_symlink() && !path.exists() {
                result.push(path.to_path_buf());
            }
        }
    }
    result
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::time::Duration;

    use super::*;

    // ── sanitize_id ───────────────────────────────────────────────────────────

    #[test]
    fn sanitize_id_alphanumeric_unchanged() {
        assert_eq!(sanitize_id("simple"), "simple");
        assert_eq!(sanitize_id("abc-123"), "abc-123");
    }

    #[test]
    fn sanitize_id_replaces_special_chars() {
        assert_eq!(sanitize_id("a.b.c"), "a-b-c");
        assert_eq!(sanitize_id("/var/crash/core"), "var-crash-core");
    }

    #[test]
    fn sanitize_id_trims_leading_trailing_hyphens() {
        assert_eq!(sanitize_id("/foo"), "foo");
    }

    #[test]
    fn sanitize_id_empty_string() {
        assert_eq!(sanitize_id(""), "");
    }

    // ── scan_old_files ────────────────────────────────────────────────────────

    #[test]
    fn scan_old_files_nonexistent_dir_skipped() {
        let result = scan_old_files(&["/nonexistent/path/xyz/abc"], 30);
        assert!(result.is_empty());
    }

    #[test]
    fn scan_old_files_empty_dir_returns_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let result = scan_old_files(&[tmp.path().to_str().unwrap()], 30);
        assert!(result.is_empty());
    }

    #[test]
    fn scan_old_files_recent_file_not_returned() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("recent.log"), b"data").unwrap();
        let result = scan_old_files(&[tmp.path().to_str().unwrap()], 30);
        assert!(result.is_empty());
    }

    #[test]
    fn scan_old_files_old_file_returned() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("old.log");
        std::fs::write(&file, b"data").unwrap();
        // Set mtime to 60 days ago
        let old_time = SystemTime::now()
            .checked_sub(Duration::from_secs(60 * 86_400))
            .unwrap();
        filetime::set_file_mtime(&file, filetime::FileTime::from_system_time(old_time)).unwrap();

        let result = scan_old_files(&[tmp.path().to_str().unwrap()], 30);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].path, file);
    }

    #[test]
    fn scan_old_files_size_kb_populated() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("sized.log");
        std::fs::write(&file, vec![0u8; 2048]).unwrap();
        let old_time = SystemTime::now()
            .checked_sub(Duration::from_secs(60 * 86_400))
            .unwrap();
        filetime::set_file_mtime(&file, filetime::FileTime::from_system_time(old_time)).unwrap();

        let result = scan_old_files(&[tmp.path().to_str().unwrap()], 30);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].size_kb, 2); // 2048 bytes / 1024 = 2 KB
    }

    // ── broken_symlinks ───────────────────────────────────────────────────────

    #[test]
    fn broken_symlinks_empty_dir_returns_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let result = broken_symlinks(&[tmp.path().to_str().unwrap()]);
        assert!(result.is_empty());
    }

    #[test]
    fn broken_symlinks_valid_symlink_not_returned() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("target");
        let link = tmp.path().join("link");
        std::fs::write(&target, b"data").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let result = broken_symlinks(&[tmp.path().to_str().unwrap()]);
        assert!(result.is_empty());
    }

    #[test]
    fn broken_symlinks_dangling_symlink_returned() {
        let tmp = tempfile::tempdir().unwrap();
        let link = tmp.path().join("dangling");
        std::os::unix::fs::symlink("/nonexistent/target/xyz", &link).unwrap();
        let result = broken_symlinks(&[tmp.path().to_str().unwrap()]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], link);
    }

    #[test]
    fn broken_symlinks_nonexistent_dir_skipped() {
        let result = broken_symlinks(&["/nonexistent/path/xyz"]);
        assert!(result.is_empty());
    }
}
