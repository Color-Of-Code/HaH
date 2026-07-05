//! Declarative YAML rule data model and runtime evaluator.
//!
//! A [`RuleSet`] is the top-level YAML document.  It contains optional
//! reusable [`Blocks`] and a list of [`Rule`]s.  Each rule is wrapped in a
//! [`RuleBasedCheck`] that implements the [`Check`] trait so it integrates
//! seamlessly with the existing registry and runner.

mod condition;
mod eval;

pub mod check;
pub mod model;

use std::path::Path;
use std::sync::Arc;

use anyhow::{Result, anyhow};

pub use check::RuleBasedCheck;
pub use model::{
    Blocks, CommandSpec, CompareOp, ExpectedValue, FileSpec, OutcomeForEach, OutcomeFragment,
    ProbeSpec, RemediationTemplate, Rule, RuleCondition, RuleGuard, RuleOutcome, RuleSet,
    RuleTrigger, UseRef,
};

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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests;
