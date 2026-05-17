//! Sysctl conflict detection capability.

use std::{fs, path::Path};

use anyhow::Result;

use crate::CapValue;

const DEFAULT_SYSCTL_DIRS: &[&str] = &["/usr/lib/sysctl.d", "/etc/sysctl.d", "/run/sysctl.d"];

/// Return a list of conflict descriptions for sysctl keys that appear with
/// different values across `*.conf` files.
///
/// Each item has the form `"<key>: <file>=<val>, <file>=<val>"`.
/// Scans default sysctl directories when `dirs` is empty.
pub fn sysctl_conflicts(dirs: &[String]) -> Result<CapValue> {
    let effective: Vec<&str> = if dirs.is_empty() {
        DEFAULT_SYSCTL_DIRS.to_vec()
    } else {
        dirs.iter().map(String::as_str).collect()
    };

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

    let conflicts: Vec<String> = hah_utils::sysctl::find_conflicts(&file_entries)
        .into_iter()
        .map(|c| {
            let detail = c
                .assignments
                .iter()
                .map(|(f, v)| format!("{f}={v}"))
                .collect::<Vec<_>>()
                .join(", ");
            format!("{}: {detail}", c.key)
        })
        .collect();
    Ok(CapValue::List(conflicts))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn nonexistent_dir_returns_empty() {
        let result = sysctl_conflicts(&["/nonexistent/sysctl.d".to_string()]).unwrap();
        assert_eq!(result, CapValue::List(vec![]));
    }

    #[test]
    fn detects_conflict() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("10-net.conf"), "net.ipv4.ip_forward = 0\n").unwrap();
        std::fs::write(tmp.path().join("20-net.conf"), "net.ipv4.ip_forward = 1\n").unwrap();
        let dir = tmp.path().to_string_lossy().to_string();
        let result = sysctl_conflicts(&[dir]).unwrap();
        let CapValue::List(items) = result else {
            panic!("expected list");
        };
        assert_eq!(items.len(), 1);
        assert!(items[0].contains("net.ipv4.ip_forward"));
    }

    #[test]
    fn same_value_no_conflict() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("10-a.conf"), "vm.swappiness = 10\n").unwrap();
        std::fs::write(tmp.path().join("20-b.conf"), "vm.swappiness = 10\n").unwrap();
        let dir = tmp.path().to_string_lossy().to_string();
        let result = sysctl_conflicts(&[dir]).unwrap();
        assert_eq!(result, CapValue::List(vec![]));
    }

    #[test]
    fn skips_comments_and_empty_lines() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(
            tmp.path().join("10-a.conf"),
            "# comment\n; another comment\n\nnet.ipv4.ip_forward = 1\n",
        )
        .unwrap();
        std::fs::write(tmp.path().join("20-b.conf"), "net.ipv4.ip_forward = 1\n").unwrap();
        let dir = tmp.path().to_string_lossy().to_string();
        let result = sysctl_conflicts(&[dir]).unwrap();
        assert_eq!(result, CapValue::List(vec![]));
    }

    #[test]
    fn uses_default_dirs_when_empty() {
        let result = sysctl_conflicts(&[]);
        assert!(result.is_ok());
    }
}
