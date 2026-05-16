use std::{io, process::Command};

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
    fn run<'a>(&self, program: &'a str, args: &'a [&'a str]) -> io::Result<CommandOutput>;
}

/// Production [`CommandRunner`] that spawns real child processes.
pub struct SystemRunner;

impl CommandRunner for SystemRunner {
    fn run<'a>(&self, program: &'a str, args: &'a [&'a str]) -> io::Result<CommandOutput> {
        let out = Command::new(program).args(args).output()?;
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
}
