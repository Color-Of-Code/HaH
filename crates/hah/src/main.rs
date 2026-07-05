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
};

/// Run a parsed CLI command.  Returns `true` when at least one Critical finding
/// was produced (the binary should exit with code 1 in that case).
pub(crate) fn run_with_config(cli: Cli, config: Config, distro: DistroInfo) -> bool {
    match cli.command {
        Command::Scan { output, check } => {
            let all = registry::all_checks(&config);
            let ctx = Context::new(false, config, distro);
            let checks: Vec<_> = match &check {
                Some(id) => all.into_iter().filter(|c| c.id() == id).collect(),
                None => all,
            };

            // Respect enabled/disabled_checks from config
            let checks: Vec<_> = checks
                .into_iter()
                .filter(|c| ctx.config.check_enabled(c.id()))
                .collect();

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

            results
                .iter()
                .any(|(_, r)| r.findings.iter().any(|f| f.severity == Severity::Critical))
        }

        Command::List => {
            let checks = registry::all_checks(&config);
            println!("{:<30} TITLE", "ID");
            println!("{}", "-".repeat(70));
            for check in &checks {
                println!("{:<30} {}", check.id(), check.title());
            }
            false
        }

        Command::Validate { paths } => run_lint(&paths, &config),
    }
}

fn run_lint(paths: &[std::path::PathBuf], config: &Config) -> bool {
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
    has_errors
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
pub(crate) fn run(cli: Cli) -> bool {
    run_with_config(
        cli,
        Config::load().unwrap_or_default(),
        DistroInfo::detect().unwrap_or_default(),
    )
}

fn main() {
    if run(Cli::parse()) {
        // Skip the actual exit when building for coverage measurement so that
        // integration-test drivers are not killed by the instrumented binary.
        #[cfg(not(coverage))]
        std::process::exit(1);
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
    fn list_checks_returns_false() {
        assert!(!run_with_config(
            parse(&["hah", "list"]),
            Config::default(),
            DistroInfo::default(),
        ));
    }

    #[test]
    fn scan_with_check_filter_no_match_returns_false() {
        assert!(!run_with_config(
            parse(&["hah", "scan", "--check", "__no_such_check__"]),
            Config::default(),
            DistroInfo::default(),
        ));
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
        assert!(!run_with_config(
            parse(&["hah", "scan"]),
            config,
            DistroInfo::default(),
        ));
    }

    #[test]
    fn scan_boot_space_with_impossible_threshold_returns_critical() {
        // /boot cannot have 999 PB free, so BootSpaceCheck will always fire
        // a Critical finding → run_with_config returns true.
        let mut config = Config::default();
        config
            .thresholds
            .insert("boot_space_mb".into(), 999_999_999);
        assert!(
            run_with_config(
                parse(&["hah", "scan", "--check", "boot-space"]),
                config,
                DistroInfo::default(),
            ),
            "/boot should be \"critically low\" against a 999 PB threshold"
        );
    }

    #[test]
    fn run_does_not_panic_with_real_system() {
        // Exercises the Config::load() / DistroInfo::detect() code paths.
        run(parse(&["hah", "scan", "--check", "__no_such_check__"]));
    }

    #[test]
    fn validate_shipped_rules_returns_false() {
        assert!(!run_with_config(
            parse(&["hah", "validate"]),
            Config::default(),
            DistroInfo::default(),
        ));
    }

    #[test]
    fn validate_explicit_rules_dir_returns_false() {
        assert!(!run_with_config(
            parse(&["hah", "validate", "rules/"]),
            Config::default(),
            DistroInfo::default(),
        ));
    }

    #[test]
    fn validate_bad_file_returns_true() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("bad.yaml");
        std::fs::write(&path, "not: [valid: {{").expect("write");
        let result = run_with_config(
            parse(&["hah", "validate", path.to_str().expect("utf8")]),
            Config::default(),
            DistroInfo::default(),
        );
        assert!(result);
    }
}
