//! APT package capabilities: installed denylist.

use std::collections::HashSet;

use anyhow::{Result, anyhow};
use hah_core::{config::DenylistEntry, runner::CommandRunner};

use crate::CapValue;

/// Return a list of `"name|reason"` strings for denylist packages that are
/// currently installed.
pub fn installed_denylist(
    runner: &dyn CommandRunner,
    packages: &[DenylistEntry],
) -> Result<CapValue> {
    if packages.is_empty() {
        return Ok(CapValue::List(vec![]));
    }
    let out = runner
        .run("dpkg-query", &["-W", "-f=${Package}\n"])
        .map_err(|e| anyhow!("dpkg-query: {e}"))?;

    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let installed: HashSet<&str> = stdout.lines().collect();

    let matches: Vec<String> = packages
        .iter()
        .filter(|p| installed.contains(p.name.as_str()))
        .map(|p| format!("{}|{}", p.name, p.reason))
        .collect();

    Ok(CapValue::List(matches))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use hah_core::runner::{CommandOutput, MockCommandRunner};
    use std::io;

    fn ok_out(stdout: &str) -> io::Result<CommandOutput> {
        Ok(CommandOutput {
            stdout: stdout.as_bytes().to_vec(),
            stderr: vec![],
            success: true,
        })
    }

    #[test]
    fn empty_packages_returns_empty() {
        let mock = MockCommandRunner::new();
        let result = installed_denylist(&mock, &[]).unwrap();
        assert_eq!(result, CapValue::List(vec![]));
    }

    #[test]
    fn finds_matching_package() {
        let mut mock = MockCommandRunner::new();
        mock.expect_run()
            .returning(|_, _| ok_out("bash\nbad-pkg\nvim\n"));
        let packages = vec![DenylistEntry {
            name: "bad-pkg".into(),
            reason: "insecure".into(),
        }];
        let result = installed_denylist(&mock, &packages).unwrap();
        let CapValue::List(items) = result else {
            panic!("expected list");
        };
        assert_eq!(items.len(), 1);
        assert!(items[0].contains("bad-pkg"));
        assert!(items[0].contains("insecure"));
    }

    #[test]
    fn no_match_returns_empty() {
        let mut mock = MockCommandRunner::new();
        mock.expect_run().returning(|_, _| ok_out("bash\nvim\n"));
        let packages = vec![DenylistEntry {
            name: "bad-pkg".into(),
            reason: "insecure".into(),
        }];
        let result = installed_denylist(&mock, &packages).unwrap();
        assert_eq!(result, CapValue::List(vec![]));
    }

    #[test]
    fn propagates_error() {
        let mut mock = MockCommandRunner::new();
        mock.expect_run()
            .returning(|_, _| Err(io::Error::new(io::ErrorKind::NotFound, "not found")));
        let packages = vec![DenylistEntry {
            name: "x".into(),
            reason: "y".into(),
        }];
        assert!(installed_denylist(&mock, &packages).is_err());
    }
}
