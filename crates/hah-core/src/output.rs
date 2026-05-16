use std::collections::HashMap;

use colored::Colorize;

use crate::model::{CheckResult, Finding, Severity};

pub enum OutputFormat {
    Terminal,
    Json,
    Yaml,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "terminal" | "term" => Ok(Self::Terminal),
            "json" => Ok(Self::Json),
            "yaml" | "yml" => Ok(Self::Yaml),
            other => Err(format!("unknown output format: {other}")),
        }
    }
}

pub fn render(results: &[(String, CheckResult)], format: &OutputFormat) {
    match format {
        OutputFormat::Terminal => render_terminal(results),
        OutputFormat::Json => render_json(results),
        OutputFormat::Yaml => render_yaml(results),
    }
}

fn severity_label(s: &Severity) -> colored::ColoredString {
    match s {
        Severity::Info => "INFO    ".cyan(),
        Severity::Warning => "WARNING ".yellow(),
        Severity::Critical => "CRITICAL".red().bold(),
    }
}

fn render_terminal(results: &[(String, CheckResult)]) {
    let total_findings: usize = results.iter().map(|(_, r)| r.findings.len()).sum();
    let total_errors: usize = results.iter().map(|(_, r)| r.errors.len()).sum();

    if total_findings == 0 && total_errors == 0 {
        println!("{}", "No issues found.".green().bold());
        return;
    }

    for (check_id, result) in results {
        if result.findings.is_empty() && result.errors.is_empty() {
            continue;
        }
        println!("\n{}", format!("── {check_id} ──").bold());
        for finding in &result.findings {
            render_finding(finding);
        }
        for error in &result.errors {
            eprintln!("  {} {}", "ERROR".red(), error);
        }
    }

    println!("\n{} finding(s), {} error(s)", total_findings, total_errors);
}

fn render_finding(f: &Finding) {
    println!("  [{}] {}", severity_label(&f.severity), f.title.bold());
    println!("         {}", f.description);
    if let Some(rem) = &f.remediation {
        println!("         {}: {}", "Fix".green(), rem.description);
        for cmd in &rem.commands {
            println!("           {}", format!("$ {cmd}").dimmed());
        }
    }
}

fn render_json(results: &[(String, CheckResult)]) {
    let map: HashMap<&str, &CheckResult> = results.iter().map(|(id, r)| (id.as_str(), r)).collect();
    println!("{}", hah_utils::json::serialize_pretty(&map));
}

fn render_yaml(results: &[(String, CheckResult)]) {
    let map: HashMap<&str, &CheckResult> = results.iter().map(|(id, r)| (id.as_str(), r)).collect();
    print!("{}", hah_utils::yaml::serialize(&map).unwrap_or_default());
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::model::{Finding, Remediation, Severity};

    fn sample_finding(severity: Severity, with_remediation: bool) -> Finding {
        Finding {
            id: "test-id".into(),
            title: "Test finding".into(),
            description: "Test description".into(),
            severity,
            remediation: with_remediation.then(|| Remediation {
                description: "Fix it".into(),
                commands: vec!["sudo fix".into()],
            }),
        }
    }

    #[test]
    fn output_format_from_str_terminal() {
        assert!(matches!(
            "terminal".parse::<OutputFormat>().unwrap(),
            OutputFormat::Terminal
        ));
        assert!(matches!(
            "term".parse::<OutputFormat>().unwrap(),
            OutputFormat::Terminal
        ));
        assert!(matches!(
            "TERMINAL".parse::<OutputFormat>().unwrap(),
            OutputFormat::Terminal
        ));
    }

    #[test]
    fn output_format_from_str_json() {
        assert!(matches!(
            "json".parse::<OutputFormat>().unwrap(),
            OutputFormat::Json
        ));
        assert!(matches!(
            "JSON".parse::<OutputFormat>().unwrap(),
            OutputFormat::Json
        ));
    }

    #[test]
    fn output_format_from_str_yaml() {
        assert!(matches!(
            "yaml".parse::<OutputFormat>().unwrap(),
            OutputFormat::Yaml
        ));
        assert!(matches!(
            "yml".parse::<OutputFormat>().unwrap(),
            OutputFormat::Yaml
        ));
    }

    #[test]
    fn output_format_from_str_unknown_returns_error() {
        assert!("csv".parse::<OutputFormat>().is_err());
    }

    #[test]
    fn render_terminal_empty_results() {
        render(&[], &OutputFormat::Terminal);
    }

    #[test]
    fn render_terminal_no_findings() {
        let results = vec![("check-a".into(), CheckResult::default())];
        render(&results, &OutputFormat::Terminal);
    }

    #[test]
    fn render_terminal_info_finding_with_remediation() {
        let f = sample_finding(Severity::Info, true);
        let results = vec![("check-a".into(), CheckResult::default().with_finding(f))];
        render(&results, &OutputFormat::Terminal);
    }

    #[test]
    fn render_terminal_warning_finding_no_remediation() {
        let f = sample_finding(Severity::Warning, false);
        let results = vec![("check-a".into(), CheckResult::default().with_finding(f))];
        render(&results, &OutputFormat::Terminal);
    }

    #[test]
    fn render_terminal_critical_finding() {
        let f = sample_finding(Severity::Critical, true);
        let results = vec![("check-a".into(), CheckResult::default().with_finding(f))];
        render(&results, &OutputFormat::Terminal);
    }

    #[test]
    fn render_terminal_with_errors() {
        let result = CheckResult::default().with_error("something went wrong");
        let results = vec![("check-a".into(), result)];
        render(&results, &OutputFormat::Terminal);
    }

    #[test]
    fn render_terminal_multiple_checks() {
        let results = vec![
            (
                "check-a".into(),
                CheckResult::default().with_finding(sample_finding(Severity::Info, false)),
            ),
            ("check-b".into(), CheckResult::default()),
            ("check-c".into(), CheckResult::default().with_error("err")),
        ];
        render(&results, &OutputFormat::Terminal);
    }

    #[test]
    fn render_json_does_not_panic() {
        let results = vec![(
            "check-a".into(),
            CheckResult::default().with_finding(sample_finding(Severity::Warning, true)),
        )];
        render(&results, &OutputFormat::Json);
    }

    #[test]
    fn render_yaml_does_not_panic() {
        let results = vec![(
            "check-a".into(),
            CheckResult::default().with_finding(sample_finding(Severity::Critical, false)),
        )];
        render(&results, &OutputFormat::Yaml);
    }
}
