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
    },

    /// List all registered checks with their IDs
    ListChecks,
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
        let cli = parse(&["hah", "list-checks"]);
        assert!(matches!(cli.command, Command::ListChecks));
    }

    #[test]
    fn parse_scan_defaults() {
        if let Command::Scan { output, check } = parse(&["hah", "scan"]).command {
            assert!(matches!(output, OutputFormat::Terminal));
            assert!(check.is_none());
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
}
