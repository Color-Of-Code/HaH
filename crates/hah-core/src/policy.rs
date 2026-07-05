//! Command execution policy: allowlist enforcement and interactive approval.
//!
//! A [`PolicyRunner`] wraps an inner [`CommandRunner`] and only lets a command
//! run when its program name matches one of the configured allow regexes.  In
//! [`ExecMode::Ask`] mode, a program that is not allowlisted triggers an
//! interactive approval prompt instead of being rejected outright.
//!
//! Blocked commands surface as an [`io::ErrorKind::PermissionDenied`] error so
//! that callers can treat the affected check as *skipped* rather than failed.

use std::io::{self, BufRead, Write};
use std::sync::Arc;

use regex::Regex;

use crate::runner::{CommandOutput, CommandRunner};

/// How the [`PolicyRunner`] treats commands that are not allowlisted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecMode {
    /// Reject non-allowlisted commands (default).
    Enforce,
    /// Prompt the user to approve each non-allowlisted command.
    Ask,
}

/// Callback that decides whether a non-allowlisted command may run.
pub type Approver = Arc<dyn Fn(&str, &[&str]) -> bool + Send + Sync>;

/// A [`CommandRunner`] decorator that enforces a command allowlist.
pub struct PolicyRunner {
    inner: Arc<dyn CommandRunner>,
    allow: Vec<Regex>,
    mode: ExecMode,
    approver: Approver,
}

impl PolicyRunner {
    /// Create a policy runner from compiled allow regexes.
    pub fn new(
        inner: Arc<dyn CommandRunner>,
        allow: Vec<Regex>,
        mode: ExecMode,
        approver: Approver,
    ) -> Self {
        Self {
            inner,
            allow,
            mode,
            approver,
        }
    }

    /// Whether `program` matches any allow regex.
    fn is_allowed(&self, program: &str) -> bool {
        self.allow.iter().any(|re| re.is_match(program))
    }

    /// Decide whether the command may run given the current mode.
    fn permit(&self, program: &str, args: &[&str]) -> bool {
        if self.is_allowed(program) {
            return true;
        }
        match self.mode {
            ExecMode::Enforce => false,
            ExecMode::Ask => (self.approver)(program, args),
        }
    }

    fn blocked(program: &str) -> io::Error {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("command not allowed: {program}"),
        )
    }
}

impl CommandRunner for PolicyRunner {
    fn run<'a>(&self, program: &'a str, args: &'a [&'a str]) -> io::Result<CommandOutput> {
        if self.permit(program, args) {
            self.inner.run(program, args)
        } else {
            Err(Self::blocked(program))
        }
    }

    fn run_stdin<'a>(
        &self,
        program: &'a str,
        args: &'a [&'a str],
        stdin: &'a [u8],
    ) -> io::Result<CommandOutput> {
        if self.permit(program, args) {
            self.inner.run_stdin(program, args, stdin)
        } else {
            Err(Self::blocked(program))
        }
    }
}

/// Compile a list of allow-pattern strings into anchored-as-written regexes.
///
/// Invalid patterns are reported with their source string.
pub fn compile_allow(patterns: &[String]) -> Result<Vec<Regex>, String> {
    patterns
        .iter()
        .map(|p| Regex::new(p).map_err(|e| format!("invalid allow pattern {p:?}: {e}")))
        .collect()
}

/// Interactive yes/no confirmation, reading from `reader` and prompting on
/// `writer`.  Returns `true` only when the first input line starts with `y`
/// or `Y`.
pub fn confirm(reader: &mut impl BufRead, writer: &mut impl Write, prompt: &str) -> bool {
    let _ = write!(writer, "{prompt} [y/N] ");
    let _ = writer.flush();
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim().chars().next(), Some('y' | 'Y'))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::runner::MockCommandRunner;

    fn ok_output(stdout: &[u8]) -> io::Result<CommandOutput> {
        Ok(CommandOutput {
            stdout: stdout.to_vec(),
            stderr: vec![],
            success: true,
        })
    }

    fn allow(patterns: &[&str]) -> Vec<Regex> {
        compile_allow(&patterns.iter().map(ToString::to_string).collect::<Vec<_>>()).unwrap()
    }

    fn deny_approver() -> Approver {
        Arc::new(|_, _| false)
    }

    #[test]
    fn allowed_command_runs() {
        let mut inner = MockCommandRunner::new();
        inner.expect_run().returning(|_, _| ok_output(b"out"));
        let policy = PolicyRunner::new(
            Arc::new(inner),
            allow(&["^find$"]),
            ExecMode::Enforce,
            deny_approver(),
        );
        let out = policy.run("find", &["/tmp"]).unwrap();
        assert_eq!(out.stdout, b"out");
    }

    #[test]
    fn denied_command_is_blocked_in_enforce_mode() {
        let inner = MockCommandRunner::new();
        let policy = PolicyRunner::new(
            Arc::new(inner),
            allow(&["^find$"]),
            ExecMode::Enforce,
            deny_approver(),
        );
        let err = policy.run("rm", &["-rf", "/"]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn denied_run_stdin_is_blocked() {
        let inner = MockCommandRunner::new();
        let policy = PolicyRunner::new(
            Arc::new(inner),
            allow(&["^grep$"]),
            ExecMode::Enforce,
            deny_approver(),
        );
        let err = policy.run_stdin("curl", &["http://x"], b"").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn allowed_run_stdin_pipes_through() {
        let mut inner = MockCommandRunner::new();
        inner
            .expect_run_stdin()
            .returning(|_, _, _| ok_output(b"piped"));
        let policy = PolicyRunner::new(
            Arc::new(inner),
            allow(&["^grep$"]),
            ExecMode::Enforce,
            deny_approver(),
        );
        let out = policy.run_stdin("grep", &["x"], b"in").unwrap();
        assert_eq!(out.stdout, b"piped");
    }

    #[test]
    fn ask_mode_runs_when_approved() {
        let mut inner = MockCommandRunner::new();
        inner.expect_run().returning(|_, _| ok_output(b"approved"));
        let approver: Approver = Arc::new(|_, _| true);
        let policy =
            PolicyRunner::new(Arc::new(inner), allow(&["^find$"]), ExecMode::Ask, approver);
        let out = policy.run("dmesg", &[]).unwrap();
        assert_eq!(out.stdout, b"approved");
    }

    #[test]
    fn ask_mode_blocks_when_declined() {
        let inner = MockCommandRunner::new();
        let policy = PolicyRunner::new(
            Arc::new(inner),
            allow(&["^find$"]),
            ExecMode::Ask,
            deny_approver(),
        );
        let err = policy.run("dmesg", &[]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn compile_allow_reports_invalid_pattern() {
        let err = compile_allow(&["[".to_string()]).unwrap_err();
        assert!(err.contains("invalid allow pattern"));
    }

    #[test]
    fn confirm_accepts_yes() {
        let mut input = io::Cursor::new(b"y\n");
        let mut out = Vec::new();
        assert!(confirm(&mut input, &mut out, "Run?"));
        assert!(String::from_utf8_lossy(&out).contains("Run?"));
    }

    #[test]
    fn confirm_rejects_other_input() {
        let mut input = io::Cursor::new(b"no\n");
        let mut out = Vec::new();
        assert!(!confirm(&mut input, &mut out, "Run?"));
    }

    #[test]
    fn confirm_rejects_empty_input() {
        let mut input = io::Cursor::new(b"");
        let mut out = Vec::new();
        assert!(!confirm(&mut input, &mut out, "Run?"));
    }
}
