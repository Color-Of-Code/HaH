//! Journal disk usage capability.

use anyhow::{Result, anyhow};
use hah_core::runner::CommandRunner;

use crate::CapValue;

/// Return the total systemd journal disk usage in megabytes.
///
/// Returns `Int(0)` when the output cannot be parsed.
pub fn journal_usage_mb(runner: &dyn CommandRunner) -> Result<CapValue> {
    let out = runner
        .run("journalctl", &["--disk-usage"])
        .map_err(|e| anyhow!("journalctl: {e}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let bytes = hah_utils::size::parse_journal_disk_usage(&stdout).unwrap_or(0);
    Ok(CapValue::Int((bytes / 1_000_000) as i64))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
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
    fn parses_correctly() {
        let mut mock = MockCommandRunner::new();
        mock.expect_run()
            .returning(|_, _| ok_out("Archived and active journals take up 600.0M.\n"));
        let result = journal_usage_mb(&mock).unwrap();
        assert_eq!(result, CapValue::Int(600));
    }

    #[test]
    fn returns_zero_on_unparseable_output() {
        let mut mock = MockCommandRunner::new();
        mock.expect_run()
            .returning(|_, _| ok_out("something unexpected\n"));
        let result = journal_usage_mb(&mock).unwrap();
        assert_eq!(result, CapValue::Int(0));
    }

    #[test]
    fn propagates_command_error() {
        let mut mock = MockCommandRunner::new();
        mock.expect_run()
            .returning(|_, _| Err(io::Error::new(io::ErrorKind::NotFound, "not found")));
        assert!(journal_usage_mb(&mock).is_err());
    }

    #[test]
    fn parse_journal_gigabytes() {
        assert_eq!(
            hah_utils::size::parse_journal_disk_usage(
                "Archived and active journals take up 1.5G in the file system."
            ),
            Some(1_500_000_000)
        );
    }

    #[test]
    fn parse_journal_megabytes() {
        assert_eq!(
            hah_utils::size::parse_journal_disk_usage(
                "Archived and active journals take up 512.0M."
            ),
            Some(512_000_000)
        );
    }

    #[test]
    fn parse_journal_kilobytes() {
        assert_eq!(
            hah_utils::size::parse_journal_disk_usage(
                "Archived and active journals take up 256K in the file system."
            ),
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
}
