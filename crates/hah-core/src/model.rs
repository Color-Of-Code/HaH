use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Remediation {
    pub description: String,
    pub commands: Vec<String>,
    /// Whether this remediation is considered safe to apply automatically.
    pub safe: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub remediation: Option<Remediation>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct CheckResult {
    pub findings: Vec<Finding>,
    pub errors: Vec<String>,
}

impl Remediation {
    /// Create a new remediation with an empty command list, marked unsafe by default.
    pub fn new(description: impl Into<String>) -> Self {
        Self {
            description: description.into(),
            commands: Vec::new(),
            safe: false,
        }
    }

    /// Append a remediation command.
    pub fn command(mut self, cmd: impl Into<String>) -> Self {
        self.commands.push(cmd.into());
        self
    }

    /// Mark this remediation as safe to apply automatically.
    pub fn mark_safe(self) -> Self {
        Self { safe: true, ..self }
    }
}

impl Finding {
    /// Create a new finding without a remediation.
    pub fn new(
        id: impl Into<String>,
        title: impl Into<String>,
        description: impl Into<String>,
        severity: Severity,
    ) -> Self {
        Self {
            id: id.into(),
            title: title.into(),
            description: description.into(),
            severity,
            remediation: None,
        }
    }

    /// Attach a remediation to this finding.
    pub fn with_remediation(mut self, remediation: Remediation) -> Self {
        self.remediation = Some(remediation);
        self
    }
}

impl CheckResult {
    pub fn with_finding(mut self, finding: Finding) -> Self {
        self.findings.push(finding);
        self
    }

    pub fn with_error(mut self, error: impl Into<String>) -> Self {
        self.errors.push(error.into());
        self
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn severity_ordering() {
        assert!(Severity::Info < Severity::Warning);
        assert!(Severity::Warning < Severity::Critical);
    }

    #[test]
    fn remediation_new_has_empty_commands_and_is_unsafe() {
        let r = Remediation::new("Fix it");
        assert_eq!(r.description, "Fix it");
        assert!(r.commands.is_empty());
        assert!(!r.safe);
    }

    #[test]
    fn remediation_command_appends() {
        let r = Remediation::new("Fix").command("sudo apt remove foo");
        assert_eq!(r.commands, vec!["sudo apt remove foo"]);
    }

    #[test]
    fn remediation_multiple_commands() {
        let r = Remediation::new("Fix").command("step1").command("step2");
        assert_eq!(r.commands, vec!["step1", "step2"]);
    }

    #[test]
    fn remediation_mark_safe_sets_flag() {
        let r = Remediation::new("Safe fix").mark_safe();
        assert!(r.safe);
    }

    #[test]
    fn finding_new_has_no_remediation() {
        let f = Finding::new("id-1", "Title", "Description", Severity::Warning);
        assert_eq!(f.id, "id-1");
        assert_eq!(f.title, "Title");
        assert_eq!(f.description, "Description");
        assert_eq!(f.severity, Severity::Warning);
        assert!(f.remediation.is_none());
    }

    #[test]
    fn finding_with_remediation_attaches_it() {
        let r = Remediation::new("Fix it");
        let f = Finding::new("x", "X", "Desc", Severity::Info).with_remediation(r);
        let rem = f.remediation.unwrap();
        assert_eq!(rem.description, "Fix it");
    }

    #[test]
    fn check_result_with_finding_appends() {
        let f = Finding::new("id", "title", "desc", Severity::Info);
        let result = CheckResult::default().with_finding(f);
        assert_eq!(result.findings.len(), 1);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn check_result_with_error_appends() {
        let result = CheckResult::default().with_error("oops");
        assert_eq!(result.errors, vec!["oops"]);
        assert!(result.findings.is_empty());
    }
}
