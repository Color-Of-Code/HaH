//! Data model types for the declarative rule DSL.
//!
//! These types map directly to the YAML structure of rule files.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use hah_core::model::Severity;

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
    /// Files that must exist for this rule to run.
    #[serde(default)]
    pub require_files: Vec<String>,
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
    /// Read a file from the filesystem; the file content is the initial value.
    /// Returns `Null` if the file does not exist (rule continues without error).
    pub file: Option<FileSpec>,
    /// Built-in probe (package/service state).
    pub probe: Option<ProbeSpec>,
    /// Rust-backed capability (complex system analysis).
    pub capability: Option<CapabilitySpec>,
    /// Optional pipeline expression that transforms the raw trigger output.
    /// Use `$stdout` as the source variable.
    #[serde(default)]
    pub transform: Option<String>,
}

/// Specification for reading a file as a trigger.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FileSpec {
    pub path: String,
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
    PackageInstalled {
        name: String,
    },
    ServiceActive {
        name: String,
    },
    /// Returns the file size in bytes as an `Int`, or `Null` if the file
    /// does not exist.
    FileSize {
        path: String,
    },
    /// Returns the symlink target as a `Str`, or `Null` if the path is not
    /// a symlink or does not exist.
    SymlinkTarget {
        path: String,
    },
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
    LargeInitramfs {
        #[serde(default = "default_initramfs_threshold")]
        threshold_mb: u64,
    },
    LegacyAptSources,
    LegacyNetworkInterfaces,
    InstalledDenylist,
}

fn default_initramfs_threshold() -> u64 {
    100
}

// ── Conditions ────────────────────────────────────────────────────────────────

/// A typed condition predicate.
#[derive(Debug, Clone, Serialize)]
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

impl RuleCondition {
    /// Returns the severity of this condition.
    pub fn severity(&self) -> Severity {
        match self {
            Self::NumericThreshold { severity, .. }
            | Self::Equals { severity, .. }
            | Self::NonEmpty { severity, .. }
            | Self::RegexMatch { severity, .. }
            | Self::All { severity, .. }
            | Self::Any { severity, .. } => severity.clone(),
        }
    }
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
    pub id: String,
    pub title: String,
    pub description: String,
    #[serde(default)]
    pub remediation: Option<RemediationTemplate>,
    /// Iterate over a list and produce one finding per item.
    #[serde(default)]
    pub for_each: Option<OutcomeForEach>,
}

/// Iteration directive on an outcome: produce one finding per list item.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OutcomeForEach {
    /// Pipeline expression that must resolve to a list.
    pub list: String,
    /// Variable name exposed to the outcome template for each item.
    #[serde(rename = "as")]
    pub item_var: String,
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
}
