//! Kernel package capabilities: unused kernels and stale headers.

use anyhow::{Result, anyhow};
use hah_core::runner::CommandRunner;

use crate::CapValue;

/// Return a list of installed `linux-image-*` package names that do **not**
/// contain the currently running kernel version string.
pub fn kernel_inventory(runner: &dyn CommandRunner) -> Result<CapValue> {
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

    let unused: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|pkg| !pkg.is_empty() && !pkg.contains(running.as_str()))
        .map(str::to_string)
        .collect();

    Ok(CapValue::List(unused))
}

/// Return a list of `linux-headers-*` packages whose version string has no
/// matching `linux-image-*` package installed.
///
/// Meta-packages (e.g., `linux-headers-generic`) that have no numeric version
/// suffix are skipped.
pub fn stale_kernel_headers(runner: &dyn CommandRunner) -> Result<CapValue> {
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

    let stale: Vec<String> = String::from_utf8_lossy(&out_headers.stdout)
        .lines()
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .filter(|hdr| {
            let version = hdr.trim_start_matches("linux-headers-");
            version.chars().next().is_some_and(char::is_numeric)
                && !kernels.iter().any(|k| k.contains(version))
        })
        .collect();

    Ok(CapValue::List(stale))
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
    fn kernel_inventory_excludes_running_kernel() {
        let mut mock = MockCommandRunner::new();
        mock.expect_run()
            .withf(|prog, _| *prog == *"uname")
            .returning(|_, _| ok_out("6.5.0-35-generic\n"));
        mock.expect_run()
            .withf(|prog, _| *prog == *"dpkg-query")
            .returning(|_, _| {
                ok_out("linux-image-6.5.0-35-generic\nlinux-image-6.5.0-27-generic\nlinux-image-6.5.0-28-generic\n")
            });
        let result = kernel_inventory(&mock).unwrap();
        let CapValue::List(items) = result else {
            panic!("expected list");
        };
        assert_eq!(items.len(), 2);
        assert!(!items.iter().any(|i| i.contains("35")));
    }

    #[test]
    fn kernel_inventory_all_match_running() {
        let mut mock = MockCommandRunner::new();
        mock.expect_run()
            .withf(|prog, _| *prog == *"uname")
            .returning(|_, _| ok_out("6.5.0-35-generic\n"));
        mock.expect_run()
            .withf(|prog, _| *prog == *"dpkg-query")
            .returning(|_, _| ok_out("linux-image-6.5.0-35-generic\n"));
        let result = kernel_inventory(&mock).unwrap();
        assert_eq!(result, CapValue::List(vec![]));
    }

    #[test]
    fn kernel_inventory_propagates_uname_error() {
        let mut mock = MockCommandRunner::new();
        mock.expect_run()
            .returning(|_, _| Err(io::Error::new(io::ErrorKind::NotFound, "not found")));
        assert!(kernel_inventory(&mock).is_err());
    }

    #[test]
    fn stale_kernel_headers_detects_stale() {
        let mut mock = MockCommandRunner::new();
        mock.expect_run()
            .withf(|_, args| args.contains(&"linux-headers-*"))
            .returning(|_, _| ok_out("linux-headers-6.5.0-27-generic\nlinux-headers-generic\n"));
        mock.expect_run()
            .withf(|_, args| args.contains(&"linux-image-*"))
            .returning(|_, _| ok_out("linux-image-6.5.0-35-generic\n"));
        let result = stale_kernel_headers(&mock).unwrap();
        let CapValue::List(items) = result else {
            panic!("expected list");
        };
        assert_eq!(items.len(), 1);
        assert!(items[0].contains("6.5.0-27"));
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
        assert_eq!(result, CapValue::List(vec![]));
    }

    #[test]
    fn stale_kernel_headers_propagates_error() {
        let mut mock = MockCommandRunner::new();
        mock.expect_run()
            .returning(|_, _| Err(io::Error::new(io::ErrorKind::NotFound, "not found")));
        assert!(stale_kernel_headers(&mock).is_err());
    }
}
