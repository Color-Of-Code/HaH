//! Pure sysctl conflict-detection algorithm.
//!
//! This module contains no I/O.  Callers are responsible for reading the
//! `sysctl.d` files and passing `(file_path, file_content)` pairs to
//! [`find_conflicts`].

use std::collections::HashMap;

// ── SysctlConflict ────────────────────────────────────────────────────────────

/// A sysctl key that is assigned different values by at least two files.
pub struct SysctlConflict {
    /// The sysctl key, e.g. `"net.ipv4.tcp_syncookies"`.
    pub key: String,
    /// All `(filename, value)` assignments seen for this key.
    ///
    /// Contains at least two entries with differing values.
    pub assignments: Vec<(String, String)>,
}

// ── find_conflicts ────────────────────────────────────────────────────────────

/// Scan `(file_path, file_content)` pairs for sysctl keys that are assigned
/// **different** values across multiple files.
///
/// Lines that are empty, or whose first non-whitespace character is `#` or
/// `;`, are treated as comments and ignored.
///
/// Returns one [`SysctlConflict`] per conflicting key.  The order is
/// non-deterministic (based on `HashMap` iteration order).
pub fn find_conflicts(entries: &[(impl AsRef<str>, impl AsRef<str>)]) -> Vec<SysctlConflict> {
    let mut seen: HashMap<String, Vec<(String, String)>> = HashMap::new();

    for (file, content) in entries {
        for line in content.as_ref().lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            if let Some((key, value)) = line.split_once('=') {
                seen.entry(key.trim().to_string())
                    .or_default()
                    .push((file.as_ref().to_string(), value.trim().to_string()));
            }
        }
    }

    let mut conflicts = Vec::new();
    for (key, occurrences) in &seen {
        if occurrences.len() < 2 {
            continue;
        }
        let first = &occurrences[0].1;
        if occurrences.iter().any(|(_, v)| v != first) {
            conflicts.push(SysctlConflict {
                key: key.clone(),
                assignments: occurrences.clone(),
            });
        }
    }
    conflicts
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn find_conflicts_empty_input_returns_nothing() {
        let entries: &[(&str, &str)] = &[];
        assert!(find_conflicts(entries).is_empty());
    }

    #[test]
    fn find_conflicts_no_conflict_same_value() {
        let entries = vec![
            ("file_a", "net.ipv4.ip_forward = 1\n"),
            ("file_b", "net.ipv4.ip_forward = 1\n"),
        ];
        assert!(find_conflicts(&entries).is_empty());
    }

    #[test]
    fn find_conflicts_detects_different_values() {
        let entries = vec![
            ("file_a", "net.ipv4.ip_forward = 0\n"),
            ("file_b", "net.ipv4.ip_forward = 1\n"),
        ];
        let result = find_conflicts(&entries);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].key, "net.ipv4.ip_forward");
        assert_eq!(result[0].assignments.len(), 2);
    }

    #[test]
    fn find_conflicts_ignores_comments_and_blanks() {
        let entries = vec![(
            "file_a",
            "# comment\n\n; another\nnet.ipv4.ip_forward = 1\n",
        )];
        assert!(find_conflicts(&entries).is_empty());
    }

    #[test]
    fn find_conflicts_single_key_single_file_no_conflict() {
        let entries = vec![("file_a", "vm.swappiness = 10\n")];
        assert!(find_conflicts(&entries).is_empty());
    }

    #[test]
    fn find_conflicts_works_with_string_slices() {
        // Verify the generic impl accepts &str and &str without String
        let entries = [
            ("/etc/sysctl.d/50-a.conf", "kernel.panic = 10\n"),
            ("/etc/sysctl.d/60-b.conf", "kernel.panic = 5\n"),
        ];
        assert_eq!(find_conflicts(&entries).len(), 1);
    }
}
