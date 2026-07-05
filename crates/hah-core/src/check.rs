use std::sync::Arc;

use crate::{
    config::Config,
    distro::DistroInfo,
    model::CheckResult,
    runner::{CommandRunner, SystemRunner},
};

pub struct Context {
    pub verbose: bool,
    pub config: Config,
    pub distro: DistroInfo,
    pub runner: Arc<dyn CommandRunner>,
}

impl Context {
    pub fn new(verbose: bool, config: Config, distro: DistroInfo) -> Self {
        Self {
            verbose,
            config,
            distro,
            runner: Arc::new(SystemRunner),
        }
    }

    /// Create a context with a custom [`CommandRunner`], primarily for testing.
    pub fn new_with_runner(
        verbose: bool,
        config: Config,
        distro: DistroInfo,
        runner: Arc<dyn CommandRunner>,
    ) -> Self {
        Self {
            verbose,
            config,
            distro,
            runner,
        }
    }
}

pub trait Check: Send + Sync {
    fn id(&self) -> &str;
    fn title(&self) -> &str;
    fn run(&self, ctx: &Context) -> CheckResult;

    /// The external commands this check may run, as `argv` vectors.  Used by
    /// `--dry-run` to preview what would execute.  Default: none.
    fn planned_commands(&self) -> Vec<Vec<String>> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_new_defaults_to_system_runner() {
        let ctx = Context::new(true, Config::default(), DistroInfo::default());
        assert!(ctx.verbose);
    }

    #[test]
    fn context_new_verbose_flag() {
        let ctx = Context::new(false, Config::default(), DistroInfo::default());
        assert!(!ctx.verbose);
    }
}
