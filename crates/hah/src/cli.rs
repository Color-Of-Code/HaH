use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(
    name = "hah",
    about = "Hunt and Heal — Linux system maintenance checker",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run all enabled checks and report findings
    Scan {
        /// Output format
        #[arg(long, value_enum, default_value_t = OutputFormat::Terminal)]
        output: OutputFormat,

        /// Run only the check with this ID
        #[arg(long)]
        check: Option<String>,

        /// List the checks and the commands they would run, without executing
        #[arg(long)]
        dry_run: bool,

        /// Prompt for approval before running any non-allowlisted command
        #[arg(long)]
        ask: bool,
    },

    /// List all registered checks with their IDs
    List,

    /// Validate rule file syntax and structure
    Validate {
        /// Files or directories to check (default: standard rule dirs)
        #[arg(value_name = "PATH")]
        paths: Vec<PathBuf>,
    },
}

#[derive(Debug, Clone, ValueEnum)]
pub enum OutputFormat {
    Terminal,
    Json,
    Yaml,
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

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(args).expect("parse failed")
    }

    #[test]
    fn parse_list_checks_command() {
        let cli = parse(&["hah", "list"]);
        assert!(matches!(cli.command, Command::List));
    }

    #[test]
    fn parse_scan_defaults() {
        if let Command::Scan {
            output,
            check,
            dry_run,
            ask,
        } = parse(&["hah", "scan"]).command
        {
            assert!(matches!(output, OutputFormat::Terminal));
            assert!(check.is_none());
            assert!(!dry_run);
            assert!(!ask);
        } else {
            panic!("expected Scan");
        }
    }

    #[test]
    fn parse_scan_dry_run_and_ask() {
        if let Command::Scan { dry_run, ask, .. } =
            parse(&["hah", "scan", "--dry-run", "--ask"]).command
        {
            assert!(dry_run);
            assert!(ask);
        } else {
            panic!("expected Scan");
        }
    }

    #[test]
    fn parse_scan_json_output() {
        if let Command::Scan { output, .. } = parse(&["hah", "scan", "--output", "json"]).command {
            assert!(matches!(output, OutputFormat::Json));
        } else {
            panic!("expected Scan");
        }
    }

    #[test]
    fn parse_scan_yaml_output() {
        if let Command::Scan { output, .. } = parse(&["hah", "scan", "--output", "yaml"]).command {
            assert!(matches!(output, OutputFormat::Yaml));
        } else {
            panic!("expected Scan");
        }
    }

    #[test]
    fn parse_scan_with_check_filter() {
        if let Command::Scan { check, .. } =
            parse(&["hah", "scan", "--check", "boot-space"]).command
        {
            assert_eq!(check.as_deref(), Some("boot-space"));
        } else {
            panic!("expected Scan");
        }
    }

    #[test]
    fn parse_invalid_subcommand_returns_error() {
        assert!(Cli::try_parse_from(["hah", "invalid-subcommand"]).is_err());
    }

    #[test]
    fn parse_validate_no_paths() {
        if let Command::Validate { paths } = parse(&["hah", "validate"]).command {
            assert!(paths.is_empty());
        } else {
            panic!("expected Validate");
        }
    }

    #[test]
    fn parse_validate_with_paths() {
        if let Command::Validate { paths } =
            parse(&["hah", "validate", "rules/", "/etc/hah"]).command
        {
            assert_eq!(paths.len(), 2);
        } else {
            panic!("expected Validate");
        }
    }
}
