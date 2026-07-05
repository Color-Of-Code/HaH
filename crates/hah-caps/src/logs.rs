//! Log scanning capability: read lines from a file or command and filter by
//! regex patterns.
//!
//! All policy (which source, which patterns, how much to read) lives in YAML.
//! This module only provides the generic mechanism.

use anyhow::{Result, anyhow};
use regex::Regex;
use serde::{Deserialize, Serialize};

use hah_core::runner::CommandRunner;

use crate::CapValue;

// ── Source ────────────────────────────────────────────────────────────────────

/// Where to read log lines from.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum LogSource {
    /// Read from a file on disk.
    File {
        /// Absolute path to the log file.
        file: String,
        /// If set, only read the last `last_bytes` bytes of the file (tail).
        /// Any partial first line created by the seek is automatically skipped.
        #[serde(default)]
        last_bytes: Option<u64>,
    },
    /// Run a command and scan its stdout.
    Command {
        /// Full argv for the command (must be non-empty).
        command: Vec<String>,
    },
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Scan log lines from `source`, keeping only lines that match any pattern in
/// `patterns`.
///
/// - Empty `patterns` → all lines are returned.
/// - `File { last_bytes: Some(n) }` → only the last `n` bytes are scanned.
pub fn log_scan(
    source: &LogSource,
    patterns: &[String],
    runner: &dyn CommandRunner,
) -> Result<CapValue> {
    let regexes = compile_patterns(patterns)?;
    let lines = collect_lines(source, runner)?;
    let matches = lines
        .into_iter()
        .filter(|line| any_matches(&regexes, line))
        .collect();
    Ok(CapValue::List(matches))
}

// ── Internals ─────────────────────────────────────────────────────────────────

fn compile_patterns(patterns: &[String]) -> Result<Vec<Regex>> {
    patterns
        .iter()
        .map(|p| Regex::new(p).map_err(|e| anyhow!("log_scan: invalid regex {:?}: {}", p, e)))
        .collect()
}

/// Return `true` when `line` matches any compiled regex (or no patterns given).
fn any_matches(regexes: &[Regex], line: &str) -> bool {
    regexes.is_empty() || regexes.iter().any(|re| re.is_match(line))
}

fn collect_lines(source: &LogSource, runner: &dyn CommandRunner) -> Result<Vec<String>> {
    match source {
        LogSource::File { file, last_bytes } => read_file_lines(file, *last_bytes),
        LogSource::Command { command } => run_command_lines(command, runner),
    }
}

fn read_file_lines(path: &str, last_bytes: Option<u64>) -> Result<Vec<String>> {
    use std::fs::File;
    use std::io::{BufRead, BufReader, Seek, SeekFrom};

    let file = File::open(path).map_err(|e| anyhow!("log_scan: cannot open {:?}: {}", path, e))?;

    if let Some(tail) = last_bytes {
        let size = file
            .metadata()
            .map_err(|e| anyhow!("log_scan: stat {:?}: {}", path, e))?
            .len();
        if size > tail {
            let mut reader = BufReader::new(file);
            reader
                .seek(SeekFrom::Start(size - tail))
                .map_err(|e| anyhow!("log_scan: seek {:?}: {}", path, e))?;
            // Discard the partial first line we may have landed in the middle of.
            let mut discard = String::new();
            reader.read_line(&mut discard)?;
            return Ok(reader.lines().map_while(Result::ok).collect());
        }
    }

    Ok(BufReader::new(file).lines().map_while(Result::ok).collect())
}

fn run_command_lines(argv: &[String], runner: &dyn CommandRunner) -> Result<Vec<String>> {
    if argv.is_empty() {
        return Err(anyhow!("log_scan: command argv must not be empty"));
    }
    let args: Vec<&str> = argv[1..].iter().map(String::as_str).collect();
    let output = runner
        .run(&argv[0], &args)
        .map_err(|e| anyhow!("log_scan: command {:?} failed: {}", argv[0], e))?;
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::to_owned)
        .collect())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::io::Write;

    use hah_core::runner::{CommandOutput, MockCommandRunner};
    use tempfile::NamedTempFile;

    use super::*;

    fn mock_with_stdout(stdout: &[u8]) -> MockCommandRunner {
        let out = CommandOutput {
            stdout: stdout.to_vec(),
            stderr: vec![],
            success: true,
        };
        let mut mock = MockCommandRunner::new();
        mock.expect_run().return_once(move |_, _| Ok(out));
        mock
    }

    // ── command source ────────────────────────────────────────────────────────

    #[test]
    fn command_source_keeps_matching_lines() {
        let mock = mock_with_stdout(b"info: all good\nerror: disk full\nwarn: memory high\n");
        let source = LogSource::Command {
            command: vec!["dmesg".into()],
        };
        let result = log_scan(&source, &["(?i)error".into(), "(?i)warn".into()], &mock).unwrap();
        assert_eq!(
            result,
            CapValue::List(vec!["error: disk full".into(), "warn: memory high".into()])
        );
    }

    #[test]
    fn command_source_empty_patterns_returns_all() {
        let mock = mock_with_stdout(b"line1\nline2\n");
        let source = LogSource::Command {
            command: vec!["dmesg".into()],
        };
        let result = log_scan(&source, &[], &mock).unwrap();
        assert_eq!(result, CapValue::List(vec!["line1".into(), "line2".into()]));
    }

    #[test]
    fn command_source_no_matches_returns_empty_list() {
        let mock = mock_with_stdout(b"info: fine\ninfo: also fine\n");
        let source = LogSource::Command {
            command: vec!["dmesg".into()],
        };
        let result = log_scan(&source, &["(?i)error".into()], &mock).unwrap();
        assert_eq!(result, CapValue::List(vec![]));
    }

    #[test]
    fn empty_argv_returns_error() {
        let mock = MockCommandRunner::new();
        let source = LogSource::Command { command: vec![] };
        assert!(log_scan(&source, &[], &mock).is_err());
    }

    // ── file source ───────────────────────────────────────────────────────────

    #[test]
    fn file_source_filters_matching_lines() {
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(tmp, "info: ok").unwrap();
        writeln!(tmp, "error: bad").unwrap();
        writeln!(tmp, "warning: check").unwrap();
        let source = LogSource::File {
            file: tmp.path().to_str().unwrap().to_owned(),
            last_bytes: None,
        };
        let mock = MockCommandRunner::new();
        let result = log_scan(&source, &["(?i)(error|warning)".into()], &mock).unwrap();
        assert_eq!(
            result,
            CapValue::List(vec!["error: bad".into(), "warning: check".into()])
        );
    }

    #[test]
    fn file_source_last_bytes_tails_file() {
        let mut tmp = NamedTempFile::new().unwrap();
        // Write "old" content that should be excluded.
        let old_line = "not-relevant\n";
        for _ in 0..10 {
            write!(tmp, "{old_line}").unwrap();
        }
        let marker = "error: recent problem\n";
        write!(tmp, "{marker}").unwrap();
        // Tail just enough bytes to include only the last line (plus a few chars
        // so we land in the middle of the preceding line, triggering the skip).
        let tail_size = (marker.len() + old_line.len() / 2) as u64;
        let source = LogSource::File {
            file: tmp.path().to_str().unwrap().to_owned(),
            last_bytes: Some(tail_size),
        };
        let mock = MockCommandRunner::new();
        let result = log_scan(&source, &["error".into()], &mock).unwrap();
        assert_eq!(result, CapValue::List(vec!["error: recent problem".into()]));
    }

    #[test]
    fn file_source_no_tail_when_file_smaller_than_last_bytes() {
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(tmp, "error: only line").unwrap();
        let source = LogSource::File {
            file: tmp.path().to_str().unwrap().to_owned(),
            last_bytes: Some(999_999),
        };
        let mock = MockCommandRunner::new();
        let result = log_scan(&source, &["error".into()], &mock).unwrap();
        assert_eq!(result, CapValue::List(vec!["error: only line".into()]));
    }

    #[test]
    fn invalid_pattern_returns_error() {
        let mock = MockCommandRunner::new();
        let source = LogSource::Command {
            command: vec!["dmesg".into()],
        };
        assert!(log_scan(&source, &["[invalid".into()], &mock).is_err());
    }
}
