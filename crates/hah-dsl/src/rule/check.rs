//! [`RuleBasedCheck`]: the [`Check`] implementation that evaluates a declarative rule.

use std::collections::HashMap;
use std::io;
use std::sync::Arc;

use anyhow::{Result, anyhow};

use hah_core::{
    check::{Check, Context},
    model::{CheckResult, Finding, Remediation, Severity},
};

use crate::pipeline::{RuleValue, ValueMap, eval_expr, render_template};

use super::eval;
use super::model::{
    Blocks, ProbeSpec, RemediationTemplate, Rule, RuleCondition, RuleGuard, RuleTrigger,
};

// ── Blocked command signalling ────────────────────────────────────────────────

/// Error marker meaning a command was refused by the execution policy.  When a
/// trigger fails with this, the whole check is reported as *skipped* rather
/// than errored.
#[derive(Debug)]
pub(crate) struct BlockedCommand(pub String);

impl std::fmt::Display for BlockedCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "command not allowed: {}", self.0)
    }
}

impl std::error::Error for BlockedCommand {}

// ── RuleBasedCheck ────────────────────────────────────────────────────────────

/// A [`Check`] implementation that evaluates a single declarative [`Rule`].
pub struct RuleBasedCheck {
    pub(crate) rule: Rule,
    /// Shared blocks from the same rule file.
    pub(crate) blocks: Arc<Blocks>,
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
        let mut values = self.seed_context_values(ctx);

        // ── 3. Run triggers ───────────────────────────────────────────────────
        for trigger in &self.rule.triggers {
            match self.run_trigger(trigger, ctx, &values) {
                Ok(v) => {
                    values.insert(trigger.name.clone(), v);
                }
                Err(e) => {
                    if let Some(blocked) = e.downcast_ref::<BlockedCommand>() {
                        return CheckResult::skipped(blocked.0.clone());
                    }
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
        self.eval_conditions(&values)
    }

    fn planned_commands(&self) -> Vec<Vec<String>> {
        let mut cmds = Vec::new();
        for trigger in &self.rule.triggers {
            if let Some(spec) = &trigger.command {
                let mut argv = vec![spec.program.clone()];
                argv.extend(spec.args.iter().cloned());
                cmds.push(argv);
            }
            if let Some(stages) = &trigger.pipeline {
                cmds.extend(stages.iter().cloned());
            }
            if let Some(probe) = &trigger.probe {
                if let Some(argv) = probe_command(probe) {
                    cmds.push(argv);
                }
            }
        }
        cmds
    }
}

// ── Condition loop ────────────────────────────────────────────────────────────

impl RuleBasedCheck {
    fn eval_conditions(&self, values: &ValueMap) -> CheckResult {
        let mut result = CheckResult::default();
        for condition in &self.rule.conditions {
            match self.eval_condition(condition, values) {
                Ok(true) => {
                    let severity = condition.severity();
                    match self.emit_findings(severity, values) {
                        Ok(findings) => {
                            for f in findings {
                                result = result.with_finding(f);
                            }
                        }
                        Err(e) => {
                            result = result.with_error(format!("outcome for_each: {e}"));
                        }
                    }
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

// ── Context seeding ───────────────────────────────────────────────────────────

impl RuleBasedCheck {
    fn seed_context_values(&self, ctx: &Context) -> ValueMap {
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
        values.insert(
            "config.allowlist.packages".into(),
            RuleValue::List(
                ctx.config
                    .allowlist
                    .packages
                    .iter()
                    .map(|s| RuleValue::Str(s.clone()))
                    .collect(),
            ),
        );
        values.insert(
            "config.denylist.packages".into(),
            RuleValue::List(
                ctx.config
                    .denylist
                    .packages
                    .iter()
                    .map(|e| RuleValue::Str(e.name.clone()))
                    .collect(),
            ),
        );
        values
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

    pub(crate) fn guard_passes(&self, ctx: &Context) -> bool {
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
        for file_path in &guard.require_files {
            if !std::path::Path::new(file_path).exists() {
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
            let out = run_checked(ctx, &spec.program, &args, &[])?;
            RuleValue::Str(String::from_utf8_lossy(&out.stdout).into_owned())
        } else if let Some(stages) = &trigger.pipeline {
            run_pipeline(ctx, stages)?
        } else if let Some(spec) = &trigger.file {
            // Return Null (not an error) when the file does not exist so that
            // `require_files` guards and `default('')` pipelines can handle it.
            std::fs::read_to_string(&spec.path).map_or(RuleValue::Null, RuleValue::Str)
        } else if let Some(spec) = &trigger.probe {
            run_probe(spec, ctx)
        } else {
            return Err(anyhow!(
                "trigger '{}' has no command, pipeline, file, or probe",
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

// ── Command execution helpers ─────────────────────────────────────────────────

/// Run one command through the context runner, converting a policy rejection
/// into a [`BlockedCommand`] error.
fn run_checked(
    ctx: &Context,
    program: &str,
    args: &[&str],
    stdin: &[u8],
) -> Result<hah_core::runner::CommandOutput> {
    match ctx.runner.run_stdin(program, args, stdin) {
        Ok(out) => Ok(out),
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            Err(anyhow::Error::new(BlockedCommand(program.to_string())))
        }
        Err(e) => Err(anyhow!("command '{program}': {e}")),
    }
}

/// Execute a declarative command pipeline, feeding each stage's stdout into the
/// next stage's stdin.  The final stage's stdout is returned as a `Str`.
fn run_pipeline(ctx: &Context, stages: &[Vec<String>]) -> Result<RuleValue> {
    if stages.is_empty() {
        return Err(anyhow!("pipeline has no stages"));
    }
    let mut input: Vec<u8> = Vec::new();
    for stage in stages {
        let Some((program, rest)) = stage.split_first() else {
            return Err(anyhow!("pipeline stage is empty"));
        };
        let args: Vec<&str> = rest.iter().map(String::as_str).collect();
        let out = run_checked(ctx, program, &args, &input)?;
        input = out.stdout;
    }
    Ok(RuleValue::Str(String::from_utf8_lossy(&input).into_owned()))
}

pub(crate) fn run_probe(spec: &ProbeSpec, ctx: &Context) -> RuleValue {
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
        ProbeSpec::FileSize { path } => std::fs::metadata(path)
            .map_or(RuleValue::Null, |meta| RuleValue::Int(meta.len() as i64)),
        ProbeSpec::SymlinkTarget { path } => std::fs::read_link(path)
            .map_or(RuleValue::Null, |target| {
                RuleValue::Str(target.to_string_lossy().into_owned())
            }),
    }
}

/// The external command a probe runs, for `--dry-run` previews.  Filesystem
/// probes (`file_size`, `symlink_target`) run no external command.
fn probe_command(spec: &ProbeSpec) -> Option<Vec<String>> {
    match spec {
        ProbeSpec::PackageInstalled { name } => Some(vec![
            "dpkg-query".into(),
            "-W".into(),
            "-f=${Status}".into(),
            name.clone(),
        ]),
        ProbeSpec::ServiceActive { name } => Some(vec![
            "systemctl".into(),
            "is-active".into(),
            "--quiet".into(),
            name.clone(),
        ]),
        ProbeSpec::FileSize { .. } | ProbeSpec::SymlinkTarget { .. } => None,
    }
}

// ── Condition evaluation ──────────────────────────────────────────────────────

impl RuleBasedCheck {
    pub(crate) fn eval_condition(
        &self,
        condition: &RuleCondition,
        values: &ValueMap,
    ) -> Result<bool> {
        eval::eval_condition(condition, values, &|c, v| self.eval_condition(c, v))
    }

    /// Produce findings for a fired condition. If the outcome has `for_each`,
    /// iterate over the list and emit one finding per item; otherwise emit one.
    pub(crate) fn emit_findings(
        &self,
        severity: Severity,
        values: &ValueMap,
    ) -> Result<Vec<Finding>> {
        if let Some(fe) = &self.rule.outcome.for_each {
            let list = eval_expr(&fe.list, values)?;
            let items = list
                .as_list()
                .ok_or_else(|| anyhow!("for_each list must resolve to a list"))?;
            let mut findings = Vec::new();
            for item in items {
                let mut local = values.clone();
                local.insert(fe.item_var.clone(), item.clone());
                findings.push(self.make_finding(severity.clone(), &local));
            }
            Ok(findings)
        } else {
            Ok(vec![self.make_finding(severity, values)])
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

    pub(crate) fn make_finding(&self, severity: Severity, values: &ValueMap) -> Finding {
        let out = &self.rule.outcome;
        let remediation = self.resolved_remediation().map(|rem| Remediation {
            description: render_template(&rem.description, values),
            commands: rem
                .commands
                .iter()
                .map(|c| render_template(c, values))
                .collect(),
        });
        Finding {
            id: render_template(&out.id, values),
            title: render_template(&out.title, values),
            description: render_template(&out.description, values),
            severity,
            remediation,
        }
    }
}
