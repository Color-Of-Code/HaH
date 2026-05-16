use std::sync::Arc;

use crate::{
    config::Config,
    distro::DistroInfo,
    model::CheckResult,
    runner::{CommandRunner, SystemRunner},
};

pub struct Context {
    pub dry_run: bool,
    pub verbose: bool,
    pub config: Config,
    pub distro: DistroInfo,
    pub runner: Arc<dyn CommandRunner>,
}

impl Context {
    pub fn new(dry_run: bool, verbose: bool, config: Config, distro: DistroInfo) -> Self {
        Self {
            dry_run,
            verbose,
            config,
            distro,
            runner: Arc::new(SystemRunner),
        }
    }

    /// Create a context with a custom [`CommandRunner`], primarily for testing.
    pub fn new_with_runner(
        dry_run: bool,
        verbose: bool,
        config: Config,
        distro: DistroInfo,
        runner: Arc<dyn CommandRunner>,
    ) -> Self {
        Self {
            dry_run,
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_new_defaults_to_system_runner() {
        let ctx = Context::new(false, true, Config::default(), DistroInfo::default());
        assert!(!ctx.dry_run);
        assert!(ctx.verbose);
    }

    #[test]
    fn context_new_dry_run_flag() {
        let ctx = Context::new(true, false, Config::default(), DistroInfo::default());
        assert!(ctx.dry_run);
        assert!(!ctx.verbose);
    }
}
