mod cli;
mod registry;

use clap::Parser;

use cli::{Cli, Command, OutputFormat};
use hah_core::{
    check::Context,
    config::Config,
    distro::DistroInfo,
    model::Severity,
    output::{self, OutputFormat as CoreOutputFormat},
    policy::{self, Approver, ExecMode, PolicyRunner},
    runner::SystemRunner,
};
use std::sync::Arc;

/// Run a parsed CLI command. Returns an exit code reflecting the maximum
/// severity of findings: 0 (none), 1 (Info), 2 (Warning), 3 (Critical).
pub(crate) fn run_with_config(cli: Cli, config: Config, distro: DistroInfo) -> u32 {
    match cli.command {
        Command::Scan {
            output,
            check,
            dry_run,
            ask,
        } => run_scan(&output, check.as_deref(), dry_run, ask, config, distro),

        Command::List => {
            let checks = registry::all_checks(&config);
            println!("{:<30} TITLE", "ID");
            println!("{}", "-".repeat(70));
            for check in &checks {
                println!("{:<30} {}", check.id(), check.title());
            }
            0
        }

        Command::Validate { paths } => run_lint(&paths, &config),
    }
}

/// Handle the `scan` subcommand. Returns exit code: 0 (no findings), 1 (Info),
/// 2 (Warning), 3 (Critical), or 0 (error/dry-run).
fn run_scan(
    output: &OutputFormat,
    check: Option<&str>,
    dry_run: bool,
    ask: bool,
    config: Config,
    distro: DistroInfo,
) -> u32 {
    let all = registry::all_checks(&config);
    let checks: Vec<_> = match check {
        Some(id) => all.into_iter().filter(|c| c.id() == id).collect(),
        None => all,
    };
    // Respect enabled/disabled_checks from config
    let checks: Vec<_> = checks
        .into_iter()
        .filter(|c| config.check_enabled(c.id()))
        .collect();

    if dry_run {
        print_dry_run(&checks);
        return 0;
    }

    let runner = match build_runner(&config, ask) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("hah: {e}");
            return 0;
        }
    };
    let ctx = Context::new_with_runner(false, config, distro, runner);

    let results: Vec<_> = checks
        .iter()
        .map(|c| (c.id().to_string(), c.run(&ctx)))
        .collect();

    let fmt = match output {
        OutputFormat::Terminal => CoreOutputFormat::Terminal,
        OutputFormat::Json => CoreOutputFormat::Json,
        OutputFormat::Yaml => CoreOutputFormat::Yaml,
    };

    output::render(&results, &fmt);

    results_to_exit_code(&results)
}

/// Calculate exit code from results: 0 (none), 1 (Info), 2 (Warning), 3 (Critical).
fn results_to_exit_code(results: &[(String, hah_core::model::CheckResult)]) -> u32 {
    let max_severity = results
        .iter()
        .flat_map(|(_, r)| r.findings.iter().map(|f| &f.severity))
        .max_by_key(|s| match s {
            Severity::Info => 1,
            Severity::Warning => 2,
            Severity::Critical => 3,
        });

    match max_severity {
        None => 0,
        Some(Severity::Info) => 1,
        Some(Severity::Warning) => 2,
        Some(Severity::Critical) => 3,
    }
}

/// Build a policy-enforcing command runner from the config allowlist.
fn build_runner(
    config: &Config,
    ask: bool,
) -> Result<Arc<dyn hah_core::runner::CommandRunner>, String> {
    let allow = policy::compile_allow(&config.command_allow())?;
    let mode = if ask {
        ExecMode::Ask
    } else {
        ExecMode::Enforce
    };
    let approver: Approver = Arc::new(|program: &str, args: &[&str]| {
        let joined = args.join(" ");
        policy::confirm(
            &mut std::io::stdin().lock(),
            &mut std::io::stderr(),
            &format!("Run `{program} {joined}`?"),
        )
    });
    Ok(Arc::new(PolicyRunner::new(
        Arc::new(SystemRunner),
        allow,
        mode,
        approver,
    )))
}

/// Print each check and the commands it would run, without executing anything.
fn print_dry_run(checks: &[Box<dyn hah_core::check::Check>]) {
    for check in checks {
        println!("{} — {}", check.id(), check.title());
        for argv in check.planned_commands() {
            println!("    $ {}", argv.join(" "));
        }
    }
}

fn run_lint(paths: &[std::path::PathBuf], config: &Config) -> u32 {
    let dirs: Vec<std::path::PathBuf> = if paths.is_empty() {
        registry::rule_search_dirs(config)
    } else {
        paths.to_vec()
    };

    let mut has_errors = false;
    for path in &dirs {
        let files = collect_yaml_files(path);
        for file in files {
            let errors = hah_dsl::validate_rule_file(&file);
            for err in errors {
                eprintln!("{}: {err}", file.display());
                has_errors = true;
            }
        }
    }
    if !has_errors {
        println!("All rule files are valid.");
    }
    if has_errors { 1 } else { 0 }
}

fn collect_yaml_files(path: &std::path::Path) -> Vec<std::path::PathBuf> {
    if path.is_file() {
        return vec![path.to_path_buf()];
    }
    let Ok(entries) = std::fs::read_dir(path) else {
        return vec![];
    };
    entries
        .flatten()
        .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("yaml"))
        .map(|e| e.path())
        .collect()
}

/// Load config + distro from the real system, then delegate to [`run_with_config`].
pub(crate) fn run(cli: Cli) -> u32 {
    run_with_config(
        cli,
        Config::load().unwrap_or_default(),
        DistroInfo::detect().unwrap_or_default(),
    )
}

fn main() {
    let exit_code = run(Cli::parse());
    if exit_code != 0 {
        // Skip the actual exit when building for coverage measurement so that
        // integration-test drivers are not killed by the instrumented binary.
        #[cfg(not(coverage))]
        std::process::exit(exit_code as i32);
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::field_reassign_with_default
)]
mod tests {
    use super::*;
    use clap::Parser;
    use hah_core::{config::Config, distro::DistroInfo};

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(args).expect("failed to parse CLI args")
    }

    #[test]
    fn list_checks_returns_zero() {
        assert_eq!(
            run_with_config(
                parse(&["hah", "list"]),
                Config::default(),
                DistroInfo::default(),
            ),
            0
        );
    }

    #[test]
    fn scan_with_check_filter_no_match_returns_zero() {
        assert_eq!(
            run_with_config(
                parse(&["hah", "scan", "--check", "__no_such_check__"]),
                Config::default(),
                DistroInfo::default(),
            ),
            0
        );
    }

    #[test]
    fn scan_json_output_does_not_panic() {
        run_with_config(
            parse(&[
                "hah",
                "scan",
                "--check",
                "__no_such_check__",
                "--output",
                "json",
            ]),
            Config::default(),
            DistroInfo::default(),
        );
    }

    #[test]
    fn scan_yaml_output_does_not_panic() {
        run_with_config(
            parse(&[
                "hah",
                "scan",
                "--check",
                "__no_such_check__",
                "--output",
                "yaml",
            ]),
            Config::default(),
            DistroInfo::default(),
        );
    }

    #[test]
    fn scan_without_check_filter_exercises_none_branch() {
        // The `None` branch of the `match &check` expression.
        // Use `enabled_checks` to allow only a non-existent ID so nothing
        // actually runs and the test remains fast.
        let mut config = Config::default();
        config.enabled_checks = vec!["__force_empty__".into()];
        assert_eq!(
            run_with_config(parse(&["hah", "scan"]), config, DistroInfo::default(),),
            0
        );
    }

    #[test]
    fn scan_boot_space_with_impossible_threshold_returns_critical() {
        // /boot cannot have 999 PB free, so BootSpaceCheck will always fire
        // a Critical finding → run_with_config returns 3.
        let mut config = Config::default();
        config
            .thresholds
            .insert("boot_space_mb".into(), 999_999_999);
        assert_eq!(
            run_with_config(
                parse(&["hah", "scan", "--check", "boot-space"]),
                config,
                DistroInfo::default(),
            ),
            3,
            "/boot should be \"critically low\" against a 999 PB threshold"
        );
    }

    #[test]
    fn run_does_not_panic_with_real_system() {
        // Exercises the Config::load() / DistroInfo::detect() code paths.
        run(parse(&["hah", "scan", "--check", "__no_such_check__"]));
    }

    #[test]
    fn scan_dry_run_lists_without_executing() {
        // Dry-run prints planned commands and never returns Critical (exit code 0).
        assert_eq!(
            run_with_config(
                parse(&["hah", "scan", "--check", "boot-space", "--dry-run"]),
                Config::default(),
                DistroInfo::default(),
            ),
            0
        );
    }

    #[test]
    fn scan_with_invalid_allow_pattern_returns_zero() {
        // A bad allow regex makes build_runner fail; scan reports and returns 0 (error).
        let mut config = Config::default();
        config.commands.allow = vec!["[".into()];
        assert_eq!(
            run_with_config(
                parse(&["hah", "scan", "--check", "boot-space"]),
                config,
                DistroInfo::default(),
            ),
            0
        );
    }

    #[test]
    fn validate_shipped_rules_returns_zero() {
        assert_eq!(
            run_with_config(
                parse(&["hah", "validate"]),
                Config::default(),
                DistroInfo::default(),
            ),
            0
        );
    }

    #[test]
    fn validate_explicit_rules_dir_returns_zero() {
        assert_eq!(
            run_with_config(
                parse(&["hah", "validate", "rules/"]),
                Config::default(),
                DistroInfo::default(),
            ),
            0
        );
    }

    #[test]
    fn validate_bad_file_returns_one() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("bad.yaml");
        std::fs::write(&path, "not: [valid: {{").expect("write");
        let result = run_with_config(
            parse(&["hah", "validate", path.to_str().expect("utf8")]),
            Config::default(),
            DistroInfo::default(),
        );
        assert_eq!(result, 1);
    }
}
