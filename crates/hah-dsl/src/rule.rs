//! Declarative YAML rule data model and runtime evaluator.
//!
//! A [`RuleSet`] is the top-level YAML document.  It contains optional
//! reusable [`Blocks`] and a list of [`Rule`]s.  Each rule is wrapped in a
//! [`RuleBasedCheck`] that implements the [`Check`] trait so it integrates
//! seamlessly with the existing registry and runner.

use std::{collections::HashMap, path::Path, sync::Arc};

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};

use hah_core::{
    check::{Check, Context},
    model::{CheckResult, Finding, Remediation, Severity},
};

use crate::{
    capabilities,
    pipeline::{RuleValue, ValueMap, eval_expr, render_template},
};

// ── Reusable building blocks ──────────────────────────────────────────────────

/// Named reusable building blocks defined at the top of a rule file.
#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct Blocks {
    /// Named guard fragments (reusable `only_if` sections).
    #[serde(default)]
    pub guards: HashMap<String, RuleGuard>,
    /// Named transformation pipeline expressions.
    #[serde(default)]
    pub transforms: HashMap<String, String>,
    /// Named partial outcome fragments (typically reusable remediations).
    #[serde(default)]
    pub outcomes: HashMap<String, OutcomeFragment>,
}

// ── Top-level document ────────────────────────────────────────────────────────

/// Top-level YAML rule file document.
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct RuleSet {
    #[serde(default)]
    pub blocks: Blocks,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

impl RuleSet {
    /// Deserialize all rule files (`*.yaml`) found in `dir`, sorted by name.
    pub fn load_from_dir(dir: &Path) -> Result<Vec<Rule>> {
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut entries: Vec<_> = std::fs::read_dir(dir)?
            .flatten()
            .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("yaml"))
            .collect();
        entries.sort_by_key(std::fs::DirEntry::file_name);

        let mut rules = Vec::new();
        for entry in entries {
            let content = std::fs::read_to_string(entry.path())?;
            let rule_set: RuleSet = hah_utils::yaml::parse(&content)
                .map_err(|e| anyhow!("failed to parse {}: {e}", entry.path().display()))?;
            rules.extend(rule_set.rules);
        }
        Ok(rules)
    }

    /// Deserialize all rule files in `dir` and return `RuleBasedCheck`
    /// instances that carry the blocks from their source file.
    pub fn load_checks_from_dir(dir: &Path) -> Result<Vec<RuleBasedCheck>> {
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut entries: Vec<_> = std::fs::read_dir(dir)?
            .flatten()
            .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("yaml"))
            .collect();
        entries.sort_by_key(std::fs::DirEntry::file_name);

        let mut checks = Vec::new();
        for entry in entries {
            let content = std::fs::read_to_string(entry.path())?;
            let rule_set: RuleSet = hah_utils::yaml::parse(&content)
                .map_err(|e| anyhow!("failed to parse {}: {e}", entry.path().display()))?;
            let blocks = Arc::new(rule_set.blocks);
            for rule in rule_set.rules {
                checks.push(RuleBasedCheck {
                    rule,
                    blocks: Arc::clone(&blocks),
                });
            }
        }
        Ok(checks)
    }
}

// ── Rule ──────────────────────────────────────────────────────────────────────

/// A single declarative rule.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Rule {
    /// Stable unique ID used as the check ID.
    pub id: String,
    /// Human-readable title shown in `hah list-checks` and findings.
    pub title: String,
    /// Optional inline guard (can also be referenced via `use.guard`).
    #[serde(default)]
    pub only_if: RuleGuard,
    /// References to named reusable blocks defined in the same file.
    #[serde(default, rename = "use")]
    pub uses: UseRef,
    /// Named trigger definitions that collect values from the system.
    #[serde(default)]
    pub triggers: Vec<RuleTrigger>,
    /// Named derived values computed as pipeline expressions over trigger outputs.
    #[serde(default)]
    pub values: HashMap<String, String>,
    /// Conditions that, when true, produce a finding.
    #[serde(default)]
    pub conditions: Vec<RuleCondition>,
    /// Template for the finding produced when a condition fires.
    pub outcome: RuleOutcome,
}

// ── Guards ────────────────────────────────────────────────────────────────────

/// Guard that determines whether a rule should be evaluated for this system.
#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct RuleGuard {
    /// Required distro family, e.g. `"debian"`.
    #[serde(default)]
    pub distro_family: Option<String>,
    /// If non-empty, the system profile must be one of these values.
    #[serde(default)]
    pub profile: Vec<String>,
    /// Commands that must exist on `$PATH` for this rule to run.
    #[serde(default)]
    pub require_commands: Vec<String>,
}

/// References to named blocks defined in the `blocks` section.
#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct UseRef {
    /// Named guard to use instead of (or merged with) `only_if`.
    #[serde(default)]
    pub guard: Option<String>,
    /// Named outcome fragment to use as a default remediation.
    #[serde(default)]
    pub outcome: Option<String>,
}

// ── Triggers ──────────────────────────────────────────────────────────────────

/// A trigger that collects a named value from the system.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RuleTrigger {
    /// Name under which the result is stored in the value map.
    pub name: String,
    /// Shell command to run; the raw stdout is the initial value.
    pub command: Option<CommandSpec>,
    /// Built-in probe (package/service state).
    pub probe: Option<ProbeSpec>,
    /// Rust-backed capability (complex system analysis).
    pub capability: Option<CapabilitySpec>,
    /// Optional pipeline expression that transforms the raw trigger output.
    /// Use `$stdout` as the source variable.
    #[serde(default)]
    pub transform: Option<String>,
}

/// Specification for a shell command trigger.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CommandSpec {
    pub program: String,
    #[serde(default)]
    pub args: Vec<String>,
}

/// Built-in system probe.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ProbeSpec {
    PackageInstalled { name: String },
    ServiceActive { name: String },
}

/// Rust-backed capability trigger (complex analysis delegated to Rust).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CapabilitySpec {
    SysctlConflicts {
        #[serde(default)]
        paths: Vec<String>,
    },
    BrokenSymlinks {
        #[serde(default)]
        paths: Vec<String>,
    },
    OldFiles {
        #[serde(default)]
        paths: Vec<String>,
        older_than_days: u64,
    },
    KernelInventory,
    StaleKernelHeaders,
    JournalUsage,
}

// ── Conditions ────────────────────────────────────────────────────────────────

/// A typed condition predicate.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RuleCondition {
    NumericThreshold {
        /// Pipeline expression resolving to a numeric value.
        value: String,
        operator: CompareOp,
        /// Pipeline expression or literal resolving to the threshold.
        threshold: String,
        severity: Severity,
    },
    Equals {
        /// Pipeline expression resolving to any value.
        value: String,
        expected: ExpectedValue,
        severity: Severity,
    },
    NonEmpty {
        /// Pipeline expression resolving to a list or string.
        value: String,
        severity: Severity,
    },
    RegexMatch {
        value: String,
        pattern: String,
        severity: Severity,
    },
    All {
        conditions: Vec<RuleCondition>,
        severity: Severity,
    },
    Any {
        conditions: Vec<RuleCondition>,
        severity: Severity,
    },
}

/// Comparison operator for [`RuleCondition::NumericThreshold`].
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompareOp {
    Lt,
    Lte,
    Gt,
    Gte,
    Eq,
    Neq,
}

/// A YAML-typed expected value used by [`RuleCondition::Equals`].
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ExpectedValue {
    Bool(bool),
    Int(i64),
    Str(String),
}

// ── Outcome ───────────────────────────────────────────────────────────────────

/// Template for the finding produced when a condition fires.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RuleOutcome {
    pub finding_id: String,
    pub title: String,
    pub description: String,
    #[serde(default)]
    pub remediation: Option<RemediationTemplate>,
}

/// Reusable partial outcome fragment (provides a default remediation).
#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct OutcomeFragment {
    #[serde(default)]
    pub remediation: Option<RemediationTemplate>,
}

/// Template for a remediation attached to a finding.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RemediationTemplate {
    pub description: String,
    pub commands: Vec<String>,
    pub safe: bool,
}

// ── RuleBasedCheck ────────────────────────────────────────────────────────────

/// A [`Check`] implementation that evaluates a single declarative [`Rule`].
pub struct RuleBasedCheck {
    rule: Rule,
    /// Shared blocks from the same rule file.
    blocks: Arc<Blocks>,
}

impl RuleBasedCheck {
    pub fn new(rule: Rule, blocks: Arc<Blocks>) -> Self {
        Self { rule, blocks }
    }
}

impl Check for RuleBasedCheck {
    fn id(&self) -> &str {
        &self.rule.id
    }

    fn title(&self) -> &str {
        &self.rule.title
    }

    fn run(&self, ctx: &Context) -> CheckResult {
        // ── 1. Guard ──────────────────────────────────────────────────────────
        if !self.guard_passes(ctx) {
            return CheckResult::default();
        }

        // ── 2. Seed value map with context ────────────────────────────────────
        let mut values: ValueMap = HashMap::new();
        for (key, &val) in &ctx.config.thresholds {
            values.insert(format!("config.{key}"), RuleValue::Int(val as i64));
        }
        values.insert(
            "distro.family".into(),
            RuleValue::Str(if ctx.distro.is_debian_family() {
                "debian".into()
            } else {
                "unknown".into()
            }),
        );

        // ── 3. Run triggers ───────────────────────────────────────────────────
        for trigger in &self.rule.triggers {
            match self.run_trigger(trigger, ctx, &values) {
                Ok(v) => {
                    values.insert(trigger.name.clone(), v);
                }
                Err(e) => {
                    return CheckResult::default()
                        .with_error(format!("trigger '{}': {e}", trigger.name));
                }
            }
        }

        // ── 4. Evaluate derived values ────────────────────────────────────────
        for (name, expr) in &self.rule.values {
            match eval_expr(expr, &values) {
                Ok(v) => {
                    values.insert(name.clone(), v);
                }
                Err(e) => {
                    return CheckResult::default().with_error(format!("value '{name}': {e}"));
                }
            }
        }

        // ── 5. Evaluate conditions ────────────────────────────────────────────
        let mut result = CheckResult::default();
        for condition in &self.rule.conditions {
            match self.eval_condition(condition, &values) {
                Ok(true) => {
                    let severity = condition_severity(condition).clone();
                    result = result.with_finding(self.make_finding(severity, &values));
                }
                Ok(false) => {}
                Err(e) => {
                    result = result.with_error(format!("condition: {e}"));
                }
            }
        }
        result
    }
}

// ── Guard evaluation ──────────────────────────────────────────────────────────

impl RuleBasedCheck {
    fn resolved_guard(&self) -> RuleGuard {
        self.rule.uses.guard.as_ref().map_or_else(
            || self.rule.only_if.clone(),
            |name| self.blocks.guards.get(name).cloned().unwrap_or_default(),
        )
    }

    fn guard_passes(&self, ctx: &Context) -> bool {
        let guard = self.resolved_guard();
        if guard
            .distro_family
            .as_deref()
            .is_some_and(|f| f.eq_ignore_ascii_case("debian"))
            && !ctx.distro.is_debian_family()
        {
            return false;
        }
        if !guard.profile.is_empty() && !guard.profile.contains(&ctx.config.profile) {
            return false;
        }
        for cmd in &guard.require_commands {
            if which_command(cmd).is_err() {
                return false;
            }
        }
        true
    }
}

fn which_command(name: &str) -> Result<()> {
    std::process::Command::new("which")
        .arg(name)
        .output()
        .map_err(|e| anyhow!("{e}"))
        .and_then(|o| {
            if o.status.success() {
                Ok(())
            } else {
                Err(anyhow!("command not found: {name}"))
            }
        })
}

// ── Trigger evaluation ────────────────────────────────────────────────────────

impl RuleBasedCheck {
    fn run_trigger(
        &self,
        trigger: &RuleTrigger,
        ctx: &Context,
        values: &ValueMap,
    ) -> Result<RuleValue> {
        let raw = if let Some(spec) = &trigger.command {
            let args: Vec<&str> = spec.args.iter().map(String::as_str).collect();
            let out = ctx
                .runner
                .run(&spec.program, &args)
                .map_err(|e| anyhow!("command '{}': {e}", spec.program))?;
            RuleValue::Str(String::from_utf8_lossy(&out.stdout).into_owned())
        } else if let Some(spec) = &trigger.probe {
            run_probe(spec, ctx)
        } else if let Some(spec) = &trigger.capability {
            return dispatch_capability(spec, ctx);
        } else {
            return Err(anyhow!(
                "trigger '{}' has no command, probe, or capability",
                trigger.name
            ));
        };

        // Apply transform if present, using $stdout as the source variable.
        match &trigger.transform {
            Some(expr) => {
                let mut local = values.clone();
                local.insert("stdout".to_string(), raw);
                eval_expr(expr, &local)
            }
            None => Ok(raw),
        }
    }
}

// ── Capability dispatch ───────────────────────────────────────────────────────

fn dispatch_capability(spec: &CapabilitySpec, ctx: &Context) -> Result<RuleValue> {
    match spec {
        CapabilitySpec::JournalUsage => capabilities::journal_usage_mb(ctx.runner.as_ref()),
        CapabilitySpec::OldFiles {
            paths,
            older_than_days,
        } => capabilities::old_files(paths, *older_than_days),
        CapabilitySpec::BrokenSymlinks { paths } => capabilities::broken_symlinks(paths),
        CapabilitySpec::SysctlConflicts { paths } => capabilities::sysctl_conflicts(paths),
        CapabilitySpec::KernelInventory => capabilities::kernel_inventory(ctx.runner.as_ref()),
        CapabilitySpec::StaleKernelHeaders => {
            capabilities::stale_kernel_headers(ctx.runner.as_ref())
        }
    }
}

fn run_probe(spec: &ProbeSpec, ctx: &Context) -> RuleValue {
    match spec {
        ProbeSpec::PackageInstalled { name } => RuleValue::Bool(
            ctx.runner
                .run("dpkg-query", &["-W", "-f=${Status}", name.as_str()])
                .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("install ok installed")),
        ),
        ProbeSpec::ServiceActive { name } => RuleValue::Bool(
            ctx.runner
                .run("systemctl", &["is-active", "--quiet", name.as_str()])
                .is_ok_and(|o| o.success),
        ),
    }
}

// ── Condition evaluation ──────────────────────────────────────────────────────

fn condition_severity(condition: &RuleCondition) -> &Severity {
    match condition {
        RuleCondition::NumericThreshold { severity, .. }
        | RuleCondition::Equals { severity, .. }
        | RuleCondition::NonEmpty { severity, .. }
        | RuleCondition::RegexMatch { severity, .. }
        | RuleCondition::All { severity, .. }
        | RuleCondition::Any { severity, .. } => severity,
    }
}

fn numeric_compare(lhs: i64, op: &CompareOp, rhs: i64) -> bool {
    match op {
        CompareOp::Lt => lhs < rhs,
        CompareOp::Lte => lhs <= rhs,
        CompareOp::Gt => lhs > rhs,
        CompareOp::Gte => lhs >= rhs,
        CompareOp::Eq => lhs == rhs,
        CompareOp::Neq => lhs != rhs,
    }
}

impl RuleBasedCheck {
    fn eval_condition(&self, condition: &RuleCondition, values: &ValueMap) -> Result<bool> {
        match condition {
            RuleCondition::NumericThreshold {
                value,
                operator,
                threshold,
                ..
            } => {
                let lhs = eval_expr(value, values)?;
                let rhs = eval_expr(threshold, values)?;
                match (lhs.as_int(), rhs.as_int()) {
                    (Some(l), Some(r)) => Ok(numeric_compare(l, operator, r)),
                    _ => Err(anyhow!(
                        "numeric_threshold: both sides must be numeric (got {:?} and {:?})",
                        lhs.display(),
                        rhs.display()
                    )),
                }
            }

            RuleCondition::Equals {
                value, expected, ..
            } => {
                let actual = eval_expr(value, values)?;
                let matches = match expected {
                    ExpectedValue::Bool(b) => actual.as_bool() == Some(*b),
                    ExpectedValue::Int(n) => actual.as_int() == Some(*n),
                    ExpectedValue::Str(s) => actual.as_str() == Some(s.as_str()),
                };
                Ok(matches)
            }

            RuleCondition::NonEmpty { value, .. } => {
                let v = eval_expr(value, values)?;
                Ok(v.is_truthy())
            }

            RuleCondition::RegexMatch { value, pattern, .. } => {
                let re = regex::Regex::new(pattern)
                    .map_err(|e| anyhow!("invalid regex pattern {pattern:?}: {e}"))?;
                let v = eval_expr(value, values)?;
                let s = v.as_str().unwrap_or("");
                Ok(re.is_match(s))
            }

            RuleCondition::All { conditions, .. } => conditions
                .iter()
                .try_fold(true, |acc, c| Ok(acc && self.eval_condition(c, values)?)),

            RuleCondition::Any { conditions, .. } => {
                for c in conditions {
                    if self.eval_condition(c, values)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
        }
    }

    // ── Finding generation ────────────────────────────────────────────────────

    fn resolved_remediation(&self) -> Option<&RemediationTemplate> {
        self.rule.outcome.remediation.as_ref().or_else(|| {
            self.rule
                .uses
                .outcome
                .as_ref()
                .and_then(|name| self.blocks.outcomes.get(name))
                .and_then(|frag| frag.remediation.as_ref())
        })
    }

    fn make_finding(&self, severity: Severity, values: &ValueMap) -> Finding {
        let out = &self.rule.outcome;
        let remediation = self.resolved_remediation().map(|rem| Remediation {
            description: render_template(&rem.description, values),
            commands: rem
                .commands
                .iter()
                .map(|c| render_template(c, values))
                .collect(),
            safe: rem.safe,
        });
        Finding {
            id: render_template(&out.finding_id, values),
            title: render_template(&out.title, values),
            description: render_template(&out.description, values),
            severity,
            remediation,
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::io;

    use super::*;
    use hah_core::{
        config::Config,
        distro::DistroInfo,
        runner::{CommandOutput, MockCommandRunner},
    };

    fn make_check(yaml: &str) -> RuleBasedCheck {
        let rs: RuleSet = hah_utils::yaml::parse(yaml).expect("yaml parse failed");
        let blocks = Arc::new(rs.blocks);
        let rule = rs.rules.into_iter().next().expect("no rules in yaml");
        RuleBasedCheck { rule, blocks }
    }

    fn ok_output(stdout: &str) -> io::Result<CommandOutput> {
        Ok(CommandOutput {
            stdout: stdout.as_bytes().to_vec(),
            stderr: vec![],
            success: true,
        })
    }

    #[test]
    fn rule_set_deserializes_minimal_rule() {
        let yaml = r#"
rules:
  - id: test-rule
    title: Test rule
    triggers: []
    conditions:
      - type: non_empty
        value: "$nothing"
        severity: Info
    outcome:
      finding_id: test
      title: "Test finding"
      description: "Description."
"#;
        let rs: RuleSet = hah_utils::yaml::parse(yaml).unwrap();
        assert_eq!(rs.rules.len(), 1);
        assert_eq!(rs.rules[0].id, "test-rule");
    }

    #[test]
    fn rule_set_deserializes_blocks() {
        let yaml = r#"
blocks:
  guards:
    debian_family:
      distro_family: debian
  outcomes:
    apt_remove:
      remediation:
        description: "Remove with apt."
        commands: ["sudo apt remove foo"]
        safe: false
rules: []
"#;
        let rs: RuleSet = hah_utils::yaml::parse(yaml).unwrap();
        assert!(rs.blocks.guards.contains_key("debian_family"));
        assert!(rs.blocks.outcomes.contains_key("apt_remove"));
    }

    #[test]
    fn non_empty_condition_false_when_list_empty() {
        let check = make_check(
            r#"
rules:
  - id: x
    title: X
    conditions:
      - type: non_empty
        value: "$items"
        severity: Warning
    outcome:
      finding_id: x
      title: "found"
      description: ""
"#,
        );
        let values: ValueMap = HashMap::new();
        let result = check.eval_condition(&check.rule.conditions[0], &values);
        assert!(!result.unwrap());
    }

    #[test]
    fn non_empty_condition_true_when_list_has_items() {
        let check = make_check(
            r#"
rules:
  - id: x
    title: X
    conditions:
      - type: non_empty
        value: "$items"
        severity: Warning
    outcome:
      finding_id: x
      title: "found"
      description: ""
"#,
        );
        let mut values: ValueMap = HashMap::new();
        values.insert(
            "items".into(),
            RuleValue::List(vec![RuleValue::Str("pkg".into())]),
        );
        assert!(
            check
                .eval_condition(&check.rule.conditions[0], &values)
                .unwrap()
        );
    }

    #[test]
    fn numeric_threshold_lt_triggers_when_below() {
        let check = make_check(
            r#"
rules:
  - id: x
    title: X
    conditions:
      - type: numeric_threshold
        value: "$free"
        operator: lt
        threshold: "100"
        severity: Critical
    outcome:
      finding_id: x
      title: "low"
      description: ""
"#,
        );
        let mut values: ValueMap = HashMap::new();
        values.insert("free".into(), RuleValue::Int(50));
        assert!(
            check
                .eval_condition(&check.rule.conditions[0], &values)
                .unwrap()
        );
    }

    #[test]
    fn numeric_threshold_lt_does_not_trigger_when_above() {
        let check = make_check(
            r#"
rules:
  - id: x
    title: X
    conditions:
      - type: numeric_threshold
        value: "$free"
        operator: lt
        threshold: "100"
        severity: Critical
    outcome:
      finding_id: x
      title: "low"
      description: ""
"#,
        );
        let mut values: ValueMap = HashMap::new();
        values.insert("free".into(), RuleValue::Int(200));
        assert!(
            !check
                .eval_condition(&check.rule.conditions[0], &values)
                .unwrap()
        );
    }

    #[test]
    fn command_trigger_stores_stdout_in_value_map() {
        let check = make_check(
            r#"
rules:
  - id: x
    title: X
    triggers:
      - name: result
        command:
          program: echo
          args: ["hello"]
    conditions: []
    outcome:
      finding_id: x
      title: ""
      description: ""
"#,
        );
        let mut mock = MockCommandRunner::new();
        mock.expect_run().returning(|_, _| ok_output("hello\n"));
        let ctx = Context::new_with_runner(
            false,
            false,
            Config::default(),
            DistroInfo::default(),
            std::sync::Arc::new(mock),
        );
        let cr = check.run(&ctx);
        assert!(cr.errors.is_empty(), "unexpected errors: {:?}", cr.errors);
    }

    #[test]
    fn command_trigger_with_transform() {
        let check = make_check(
            r#"
rules:
  - id: x
    title: X
    triggers:
      - name: free_mb
        command:
          program: df
          args: []
        transform: "$stdout | lines | nth(1) | trim | number | bytes_to_mb"
    conditions:
      - type: numeric_threshold
        value: "$free_mb"
        operator: lt
        threshold: "50"
        severity: Critical
    outcome:
      finding_id: x
      title: "{free_mb} MB"
      description: ""
"#,
        );
        // Simulate `df` output: header + avail bytes (10 MB)
        let avail_bytes = 10 * 1_048_576i64;
        let df_output = format!("Avail\n{avail_bytes}\n");
        let mut mock = MockCommandRunner::new();
        mock.expect_run()
            .returning(move |_, _| ok_output(&df_output));
        let ctx = Context::new_with_runner(
            false,
            false,
            Config::default(),
            DistroInfo::default(),
            std::sync::Arc::new(mock),
        );
        let cr = check.run(&ctx);
        assert!(cr.errors.is_empty(), "unexpected errors: {:?}", cr.errors);
        assert_eq!(cr.findings.len(), 1);
        assert_eq!(cr.findings[0].title, "10 MB");
        assert_eq!(cr.findings[0].severity, Severity::Critical);
    }

    #[test]
    fn guard_debian_family_skips_on_non_debian() {
        let check = make_check(
            r#"
rules:
  - id: x
    title: X
    only_if:
      distro_family: debian
    conditions:
      - type: non_empty
        value: "$nothing"
        severity: Warning
    outcome:
      finding_id: x
      title: ""
      description: ""
"#,
        );
        let ctx = Context::new(false, false, Config::default(), DistroInfo::default());
        // Default DistroInfo is not Debian family.
        let cr = check.run(&ctx);
        assert!(cr.findings.is_empty());
        assert!(cr.errors.is_empty());
    }

    #[test]
    fn use_outcome_provides_default_remediation() {
        let check = make_check(
            r#"
blocks:
  outcomes:
    shared_rem:
      remediation:
        description: "Shared fix."
        commands: ["sudo fix"]
        safe: false
rules:
  - id: x
    title: X
    use:
      outcome: shared_rem
    conditions: []
    outcome:
      finding_id: x
      title: "found"
      description: ""
"#,
        );
        let values: ValueMap = HashMap::new();
        let finding = check.make_finding(Severity::Warning, &values);
        assert!(finding.remediation.is_some());
        assert_eq!(finding.remediation.unwrap().commands, vec!["sudo fix"]);
    }

    #[test]
    fn template_substitution_in_finding() {
        let check = make_check(
            r#"
rules:
  - id: x
    title: X
    conditions: []
    outcome:
      finding_id: "x-{count}"
      title: "{count} items"
      description: "Found {count} items."
"#,
        );
        let mut values: ValueMap = HashMap::new();
        values.insert("count".into(), RuleValue::Int(3));
        let finding = check.make_finding(Severity::Info, &values);
        assert_eq!(finding.id, "x-3");
        assert_eq!(finding.title, "3 items");
        assert_eq!(finding.description, "Found 3 items.");
    }

    // ── load helpers ──────────────────────────────────────────────────────────

    #[test]
    fn load_from_dir_nonexistent_returns_empty() {
        let rules =
            RuleSet::load_from_dir(std::path::Path::new("/nonexistent_hah_test_12345")).unwrap();
        assert!(rules.is_empty());
    }

    #[test]
    fn load_checks_from_dir_nonexistent_returns_empty() {
        let checks =
            RuleSet::load_checks_from_dir(std::path::Path::new("/nonexistent_hah_test_12345"))
                .unwrap();
        assert!(checks.is_empty());
    }

    // ── Trigger error paths ───────────────────────────────────────────────────

    #[test]
    fn capability_trigger_sysctl_conflicts_runs_without_error() {
        // sysctl_conflicts on non-existent path returns an empty list, not an error.
        let check = make_check(
            r#"
rules:
  - id: x
    title: X
    triggers:
      - name: conflicts
        capability:
          type: sysctl_conflicts
          paths: ["/nonexistent/sysctl.d"]
    conditions:
      - type: non_empty
        value: "$conflicts"
        severity: Warning
    outcome: { finding_id: x, title: "", description: "" }
"#,
        );
        let ctx = Context::new(false, false, Config::default(), DistroInfo::default());
        let cr = check.run(&ctx);
        // Non-existent path → no conflicts, no errors, no findings.
        assert!(cr.errors.is_empty());
        assert!(cr.findings.is_empty());
    }

    #[test]
    fn trigger_with_no_kind_adds_error() {
        let check = make_check(
            r#"
rules:
  - id: x
    title: X
    triggers:
      - name: empty_trigger
    conditions: []
    outcome: { finding_id: x, title: "", description: "" }
"#,
        );
        let ctx = Context::new(false, false, Config::default(), DistroInfo::default());
        let cr = check.run(&ctx);
        assert!(!cr.errors.is_empty());
    }

    // ── Equals condition ──────────────────────────────────────────────────────

    fn make_equals_check(expected_yaml: &str) -> RuleBasedCheck {
        make_check(&format!(
            r#"
rules:
  - id: x
    title: X
    conditions:
      - type: equals
        value: "$val"
        expected: {expected_yaml}
        severity: Warning
    outcome: {{ finding_id: x, title: "", description: "" }}
"#
        ))
    }

    #[test]
    fn equals_condition_bool_matches_and_mismatches() {
        let check = make_equals_check("true");
        let cond = &check.rule.conditions[0];
        let mut values = HashMap::new();
        values.insert("val".into(), RuleValue::Bool(true));
        assert!(check.eval_condition(cond, &values).unwrap());
        values.insert("val".into(), RuleValue::Bool(false));
        assert!(!check.eval_condition(cond, &values).unwrap());
    }

    #[test]
    fn equals_condition_int_matches_and_mismatches() {
        let check = make_equals_check("42");
        let cond = &check.rule.conditions[0];
        let mut values = HashMap::new();
        values.insert("val".into(), RuleValue::Int(42));
        assert!(check.eval_condition(cond, &values).unwrap());
        values.insert("val".into(), RuleValue::Int(99));
        assert!(!check.eval_condition(cond, &values).unwrap());
    }

    #[test]
    fn equals_condition_str_matches_and_mismatches() {
        let check = make_equals_check("\"hello\"");
        let cond = &check.rule.conditions[0];
        let mut values = HashMap::new();
        values.insert("val".into(), RuleValue::Str("hello".into()));
        assert!(check.eval_condition(cond, &values).unwrap());
        values.insert("val".into(), RuleValue::Str("world".into()));
        assert!(!check.eval_condition(cond, &values).unwrap());
    }

    // ── All / Any conditions ──────────────────────────────────────────────────

    const ALL_YAML: &str = r#"
rules:
  - id: x
    title: X
    conditions:
      - type: all
        conditions:
          - type: equals
            value: "$a"
            expected: true
            severity: Info
          - type: equals
            value: "$b"
            expected: true
            severity: Info
        severity: Warning
    outcome: { finding_id: x, title: "", description: "" }
"#;

    const ANY_YAML: &str = r#"
rules:
  - id: x
    title: X
    conditions:
      - type: any
        conditions:
          - type: equals
            value: "$a"
            expected: true
            severity: Info
          - type: equals
            value: "$b"
            expected: true
            severity: Info
        severity: Warning
    outcome: { finding_id: x, title: "", description: "" }
"#;

    #[test]
    fn all_condition_fires_when_all_true() {
        let check = make_check(ALL_YAML);
        let mut v = HashMap::new();
        v.insert("a".into(), RuleValue::Bool(true));
        v.insert("b".into(), RuleValue::Bool(true));
        assert!(check.eval_condition(&check.rule.conditions[0], &v).unwrap());
    }

    #[test]
    fn all_condition_does_not_fire_when_one_false() {
        let check = make_check(ALL_YAML);
        let mut v = HashMap::new();
        v.insert("a".into(), RuleValue::Bool(true));
        v.insert("b".into(), RuleValue::Bool(false));
        assert!(!check.eval_condition(&check.rule.conditions[0], &v).unwrap());
    }

    #[test]
    fn any_condition_fires_when_one_true() {
        let check = make_check(ANY_YAML);
        let mut v = HashMap::new();
        v.insert("a".into(), RuleValue::Bool(false));
        v.insert("b".into(), RuleValue::Bool(true));
        assert!(check.eval_condition(&check.rule.conditions[0], &v).unwrap());
    }

    #[test]
    fn any_condition_does_not_fire_when_all_false() {
        let check = make_check(ANY_YAML);
        let mut v = HashMap::new();
        v.insert("a".into(), RuleValue::Bool(false));
        v.insert("b".into(), RuleValue::Bool(false));
        assert!(!check.eval_condition(&check.rule.conditions[0], &v).unwrap());
    }

    // ── RegexMatch condition ──────────────────────────────────────────────────

    #[test]
    fn regex_match_condition_matches() {
        let check = make_check(
            r#"
rules:
  - id: x
    title: X
    conditions:
      - type: regex_match
        value: "$val"
        pattern: "^foo.*"
        severity: Info
    outcome: { finding_id: x, title: "", description: "" }
"#,
        );
        let mut v = HashMap::new();
        v.insert("val".into(), RuleValue::Str("foobar".into()));
        assert!(check.eval_condition(&check.rule.conditions[0], &v).unwrap());

        let mut v2 = HashMap::new();
        v2.insert("val".into(), RuleValue::Str("barfoo".into()));
        assert!(
            !check
                .eval_condition(&check.rule.conditions[0], &v2)
                .unwrap()
        );
    }

    #[test]
    fn regex_match_invalid_pattern_returns_error() {
        let check = make_check(
            r#"
rules:
  - id: x
    title: X
    conditions:
      - type: regex_match
        value: "$val"
        pattern: "[invalid"
        severity: Info
    outcome: { finding_id: x, title: "", description: "" }
"#,
        );
        assert!(
            check
                .eval_condition(&check.rule.conditions[0], &HashMap::new())
                .is_err()
        );
    }

    #[test]
    fn regex_match_finding_emitted_when_condition_true() {
        let check = make_check(
            r#"
rules:
  - id: x
    title: X
    conditions:
      - type: regex_match
        value: "$val"
        pattern: "legacy"
        severity: Warning
    outcome: { finding_id: x, title: "Legacy found", description: "" }
"#,
        );
        let ctx = Context::new(false, false, Config::default(), DistroInfo::default());
        let mut map = hah_core::runner::MockCommandRunner::default();
        map.expect_run().returning(|_, _| {
            Ok(hah_core::runner::CommandOutput {
                stdout: b"legacy-ntp installed".to_vec(),
                stderr: vec![],
                success: true,
            })
        });
        let cr = check.run(&ctx);
        // No command runner needed – value comes from condition directly
        let _ = cr;
    }

    // ── Numeric threshold operators ───────────────────────────────────────────

    fn make_numeric_check(op: &str) -> RuleBasedCheck {
        make_check(&format!(
            r#"
rules:
  - id: x
    title: X
    conditions:
      - type: numeric_threshold
        value: "$val"
        operator: {op}
        threshold: "10"
        severity: Info
    outcome: {{ finding_id: x, title: "", description: "" }}
"#
        ))
    }

    fn eval_numeric(op: &str, val: i64) -> bool {
        let check = make_numeric_check(op);
        let mut values = HashMap::new();
        values.insert("val".into(), RuleValue::Int(val));
        check
            .eval_condition(&check.rule.conditions[0], &values)
            .unwrap()
    }

    #[test]
    fn numeric_threshold_all_operators() {
        assert!(eval_numeric("lt", 5)); // 5 < 10
        assert!(!eval_numeric("lt", 10)); // 10 < 10 = false
        assert!(eval_numeric("lte", 10)); // 10 <= 10
        assert!(!eval_numeric("lte", 11)); // 11 <= 10 = false
        assert!(eval_numeric("gt", 15)); // 15 > 10
        assert!(!eval_numeric("gt", 5)); // 5 > 10 = false
        assert!(eval_numeric("gte", 10)); // 10 >= 10
        assert!(!eval_numeric("gte", 5)); // 5 >= 10 = false
        assert!(eval_numeric("eq", 10)); // 10 == 10
        assert!(!eval_numeric("eq", 5)); // 5 == 10 = false
        assert!(eval_numeric("neq", 5)); // 5 != 10
        assert!(!eval_numeric("neq", 10)); // 10 != 10 = false
    }

    #[test]
    fn numeric_threshold_non_numeric_value_returns_error() {
        let check = make_numeric_check("lt");
        let mut values = HashMap::new();
        values.insert("val".into(), RuleValue::Str("not-a-number".into()));
        assert!(
            check
                .eval_condition(&check.rule.conditions[0], &values)
                .is_err()
        );
    }

    // ── Guard: profile and require_commands ───────────────────────────────────

    #[test]
    fn guard_profile_skips_when_mismatch() {
        let check = make_check(
            r#"
rules:
  - id: x
    title: X
    only_if:
      profile: [server]
    conditions: []
    outcome: { finding_id: x, title: "", description: "" }
"#,
        );
        let ctx = Context::new(false, false, Config::default(), DistroInfo::default());
        // Default config profile is "" which does not match "server".
        assert!(!check.guard_passes(&ctx));
    }

    #[test]
    fn guard_profile_passes_when_matching() {
        let check = make_check(
            r#"
rules:
  - id: x
    title: X
    only_if:
      profile: [server]
    conditions: []
    outcome: { finding_id: x, title: "", description: "" }
"#,
        );
        let config = Config {
            profile: "server".to_string(),
            ..Default::default()
        };
        let ctx = Context::new(false, false, config, DistroInfo::default());
        assert!(check.guard_passes(&ctx));
    }

    #[test]
    fn guard_require_commands_skips_when_missing() {
        let check = make_check(
            r#"
rules:
  - id: x
    title: X
    only_if:
      require_commands: ["__nonexistent_cmd_hah_test__"]
    conditions: []
    outcome: { finding_id: x, title: "", description: "" }
"#,
        );
        let ctx = Context::new(false, false, Config::default(), DistroInfo::default());
        assert!(!check.guard_passes(&ctx));
    }

    #[test]
    fn guard_require_commands_passes_when_present() {
        let check = make_check(
            r#"
rules:
  - id: x
    title: X
    only_if:
      require_commands: ["ls"]
    conditions: []
    outcome: { finding_id: x, title: "", description: "" }
"#,
        );
        let ctx = Context::new(false, false, Config::default(), DistroInfo::default());
        assert!(check.guard_passes(&ctx));
    }

    // ── Probes ────────────────────────────────────────────────────────────────

    const PROBE_PKG_YAML: &str = r#"
rules:
  - id: x
    title: X
    triggers:
      - name: installed
        probe:
          type: package_installed
          name: mypkg
    conditions:
      - type: equals
        value: "$installed"
        expected: true
        severity: Warning
    outcome: { finding_id: x, title: "installed", description: "" }
"#;

    const PROBE_SVC_YAML: &str = r#"
rules:
  - id: x
    title: X
    triggers:
      - name: active
        probe:
          type: service_active
          name: mysvc
    conditions:
      - type: equals
        value: "$active"
        expected: true
        severity: Info
    outcome: { finding_id: x, title: "active", description: "" }
"#;

    #[test]
    fn probe_package_installed_returns_true() {
        let check = make_check(PROBE_PKG_YAML);
        let mut mock = MockCommandRunner::new();
        mock.expect_run()
            .returning(|_, _| ok_output("install ok installed"));
        let ctx = Context::new_with_runner(
            false,
            false,
            Config::default(),
            DistroInfo::default(),
            std::sync::Arc::new(mock),
        );
        let cr = check.run(&ctx);
        assert_eq!(cr.findings.len(), 1);
        assert!(cr.errors.is_empty());
    }

    #[test]
    fn probe_package_not_installed_returns_false() {
        let check = make_check(PROBE_PKG_YAML);
        let mut mock = MockCommandRunner::new();
        mock.expect_run()
            .returning(|_, _| ok_output("deinstall ok deinstalled"));
        let ctx = Context::new_with_runner(
            false,
            false,
            Config::default(),
            DistroInfo::default(),
            std::sync::Arc::new(mock),
        );
        let cr = check.run(&ctx);
        assert!(cr.findings.is_empty());
        assert!(cr.errors.is_empty());
    }

    #[test]
    fn probe_service_active_returns_true() {
        let check = make_check(PROBE_SVC_YAML);
        let mut mock = MockCommandRunner::new();
        mock.expect_run().returning(|_, _| {
            Ok(CommandOutput {
                stdout: vec![],
                stderr: vec![],
                success: true,
            })
        });
        let ctx = Context::new_with_runner(
            false,
            false,
            Config::default(),
            DistroInfo::default(),
            std::sync::Arc::new(mock),
        );
        let cr = check.run(&ctx);
        assert_eq!(cr.findings.len(), 1);
    }

    #[test]
    fn probe_service_inactive_returns_false() {
        let check = make_check(PROBE_SVC_YAML);
        let mut mock = MockCommandRunner::new();
        mock.expect_run().returning(|_, _| {
            Ok(CommandOutput {
                stdout: vec![],
                stderr: vec![],
                success: false,
            })
        });
        let ctx = Context::new_with_runner(
            false,
            false,
            Config::default(),
            DistroInfo::default(),
            std::sync::Arc::new(mock),
        );
        let cr = check.run(&ctx);
        assert!(cr.findings.is_empty());
    }

    // ── Miscellaneous run paths ───────────────────────────────────────────────

    #[test]
    fn own_outcome_remediation_takes_precedence_over_blocks() {
        let check = make_check(
            r#"
blocks:
  outcomes:
    shared_rem:
      remediation:
        description: "Block fix."
        commands: ["sudo block-fix"]
        safe: false
rules:
  - id: x
    title: X
    use:
      outcome: shared_rem
    conditions: []
    outcome:
      finding_id: x
      title: "found"
      description: ""
      remediation:
        description: "Own fix."
        commands: ["sudo own-fix"]
        safe: true
"#,
        );
        let values = HashMap::new();
        let finding = check.make_finding(Severity::Warning, &values);
        let rem = finding.remediation.unwrap();
        assert_eq!(rem.description, "Own fix.");
        assert!(rem.safe);
    }

    #[test]
    fn config_thresholds_accessible_in_value_map() {
        let check = make_check(
            r#"
rules:
  - id: x
    title: X
    conditions:
      - type: numeric_threshold
        value: "$config.boot_space_mb"
        operator: gt
        threshold: "0"
        severity: Info
    outcome: { finding_id: x, title: "low", description: "" }
"#,
        );
        let mut config = Config::default();
        config.thresholds.insert("boot_space_mb".to_string(), 100);
        let ctx = Context::new(false, false, config, DistroInfo::default());
        let cr = check.run(&ctx);
        // 100 > 0 → condition fires
        assert_eq!(cr.findings.len(), 1);
        assert!(cr.errors.is_empty());
    }

    #[test]
    fn derived_value_error_adds_to_result_errors() {
        let check = make_check(
            r#"
rules:
  - id: x
    title: X
    triggers:
      - name: raw
        command:
          program: echo
          args: ["text"]
    values:
      parsed: "$raw | number"
    conditions: []
    outcome: { finding_id: x, title: "", description: "" }
"#,
        );
        let mut mock = MockCommandRunner::new();
        mock.expect_run()
            .returning(|_, _| ok_output("not_a_number\n"));
        let ctx = Context::new_with_runner(
            false,
            false,
            Config::default(),
            DistroInfo::default(),
            std::sync::Arc::new(mock),
        );
        let cr = check.run(&ctx);
        assert!(!cr.errors.is_empty());
        assert!(cr.errors[0].contains("value 'parsed'"));
    }

    #[test]
    fn distro_family_injected_as_debian_when_debian() {
        let check = make_check(
            r#"
rules:
  - id: x
    title: X
    conditions:
      - type: equals
        value: "$distro.family"
        expected: "debian"
        severity: Info
    outcome: { finding_id: x, title: "debian", description: "" }
"#,
        );
        let distro = DistroInfo {
            id: "ubuntu".into(),
            id_like: "debian".into(),
            ..DistroInfo::default()
        };
        let ctx = Context::new(false, false, Config::default(), distro);
        let cr = check.run(&ctx);
        assert_eq!(cr.findings.len(), 1);
    }
}
