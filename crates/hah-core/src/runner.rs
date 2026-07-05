use std::{
    io::{self, Write},
    process::{Command, Stdio},
};

/// Output captured from a [`CommandRunner::run`] call.
#[derive(Clone)]
pub struct CommandOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// `true` when the process exited with status 0.
    pub success: bool,
}

/// Abstraction over external process execution.
///
/// The production implementation delegates to [`std::process::Command`].
/// Test implementations can return pre-baked responses without spawning
/// any real process.
#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
pub trait CommandRunner: Send + Sync {
    /// Run `program` with `args`, capturing its output.
    fn run<'a>(&self, program: &'a str, args: &'a [&'a str]) -> io::Result<CommandOutput>;

    /// Run `program` with `args`, feeding `stdin` to the process' standard
    /// input.  Used to chain declarative command pipelines.
    fn run_stdin<'a>(
        &self,
        program: &'a str,
        args: &'a [&'a str],
        stdin: &'a [u8],
    ) -> io::Result<CommandOutput>;
}

/// Production [`CommandRunner`] that spawns real child processes.
pub struct SystemRunner;

impl CommandRunner for SystemRunner {
    fn run<'a>(&self, program: &'a str, args: &'a [&'a str]) -> io::Result<CommandOutput> {
        self.run_stdin(program, args, &[])
    }

    fn run_stdin<'a>(
        &self,
        program: &'a str,
        args: &'a [&'a str],
        stdin: &'a [u8],
    ) -> io::Result<CommandOutput> {
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        // Write stdin from a dedicated thread to avoid deadlocking when both
        // the input and the output exceed the OS pipe buffer.
        if let Some(mut sink) = child.stdin.take() {
            let data = stdin.to_vec();
            std::thread::spawn(move || {
                let _ = sink.write_all(&data);
            });
        }
        let out = child.wait_with_output()?;
        Ok(CommandOutput {
            stdout: out.stdout,
            stderr: out.stderr,
            success: out.status.success(),
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn command_output_clone_preserves_fields() {
        let out = CommandOutput {
            stdout: b"hello".to_vec(),
            stderr: b"warn".to_vec(),
            success: true,
        };
        let cloned = out.clone();
        assert_eq!(cloned.stdout, b"hello");
        assert_eq!(cloned.stderr, b"warn");
        assert!(cloned.success);
    }

    #[test]
    fn mock_runner_returns_preset_output() {
        let mut mock = MockCommandRunner::new();
        mock.expect_run().returning(|_, _| {
            Ok(CommandOutput {
                stdout: b"hi".to_vec(),
                stderr: vec![],
                success: true,
            })
        });
        let result = mock.run("echo", &["hi"]).unwrap();
        assert!(result.success);
        assert_eq!(result.stdout, b"hi");
    }

    #[test]
    fn mock_runner_propagates_error() {
        let mut mock = MockCommandRunner::new();
        mock.expect_run()
            .returning(|_, _| Err(io::Error::new(io::ErrorKind::NotFound, "not found")));
        assert!(mock.run("nonexistent", &[]).is_err());
    }

    #[test]
    fn system_runner_executes_real_command() {
        let runner = SystemRunner;
        let result = runner.run("true", &[]).unwrap();
        assert!(result.success);
        assert!(result.stderr.is_empty());
    }

    #[test]
    fn system_runner_captures_stdout() {
        let runner = SystemRunner;
        let result = runner.run("echo", &["hello"]).unwrap();
        assert!(result.success);
        let out = String::from_utf8_lossy(&result.stdout);
        assert!(out.contains("hello"));
    }

    #[test]
    fn system_runner_reports_non_zero_exit() {
        let runner = SystemRunner;
        // `false` always exits with status 1
        let result = runner.run("false", &[]).unwrap();
        assert!(!result.success);
    }

    #[test]
    fn system_runner_feeds_stdin_to_child() {
        let runner = SystemRunner;
        // `cat` echoes its stdin back to stdout.
        let result = runner.run_stdin("cat", &[], b"piped input\n").unwrap();
        assert!(result.success);
        assert_eq!(result.stdout, b"piped input\n");
    }

    #[test]
    fn system_runner_run_stdin_missing_program_errors() {
        let runner = SystemRunner;
        assert!(
            runner
                .run_stdin("__no_such_program__", &[], b"")
                .is_err()
        );
    }

    #[test]
    fn mock_runner_run_stdin_returns_preset_output() {
        let mut mock = MockCommandRunner::new();
        mock.expect_run_stdin().returning(|_, _, _| {
            Ok(CommandOutput {
                stdout: b"ok".to_vec(),
                stderr: vec![],
                success: true,
            })
        });
        let result = mock.run_stdin("grep", &["x"], b"input").unwrap();
        assert_eq!(result.stdout, b"ok");
    }
}
