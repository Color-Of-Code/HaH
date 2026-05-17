//! Compact condition deserialization.
//!
//! Only the compact format is supported:
//!   - `{ info: "$x > 0" }` / `{ warning: "$list" }` / `{ critical: "..." }`
//!   - `{ all: [...] }` / `{ any: [...] }`

use serde::Deserialize;

use hah_core::model::Severity;

use crate::parsers::dsl::{CompareToken, ConditionExpr, parse_condition_expr};

use super::model::{CompareOp, ExpectedValue, RuleCondition};

/// Compact condition: `{ info: "$x > 0" }` / `{ warning: "$list" }` /
/// `{ all: [...] }` / `{ any: [...] }` etc.
#[derive(Deserialize)]
struct CompactCondition {
    #[serde(default)]
    info: Option<String>,
    #[serde(default)]
    warning: Option<String>,
    #[serde(default)]
    critical: Option<String>,
    #[serde(default)]
    all: Option<Vec<RuleCondition>>,
    #[serde(default)]
    any: Option<Vec<RuleCondition>>,
}

impl CompactCondition {
    fn into_rule_condition(self) -> std::result::Result<RuleCondition, String> {
        if let Some(conditions) = self.all {
            let severity = max_severity(&conditions)?;
            return Ok(RuleCondition::All {
                conditions,
                severity,
            });
        }
        if let Some(conditions) = self.any {
            let severity = max_severity(&conditions)?;
            return Ok(RuleCondition::Any {
                conditions,
                severity,
            });
        }
        let (severity, expr) = if let Some(e) = self.info {
            (Severity::Info, e)
        } else if let Some(e) = self.warning {
            (Severity::Warning, e)
        } else if let Some(e) = self.critical {
            (Severity::Critical, e)
        } else {
            return Err(
                "compact condition requires info, warning, critical, all, or any key".into(),
            );
        };
        build_from_compact_expr(severity, &expr)
    }
}

fn max_severity(conditions: &[RuleCondition]) -> std::result::Result<Severity, String> {
    conditions
        .iter()
        .map(RuleCondition::severity)
        .max()
        .ok_or_else(|| "all/any requires at least one child condition".to_string())
}

fn compare_token_to_op(tok: CompareToken) -> CompareOp {
    match tok {
        CompareToken::Gte => CompareOp::Gte,
        CompareToken::Lte => CompareOp::Lte,
        CompareToken::Neq => CompareOp::Neq,
        CompareToken::Eq => CompareOp::Eq,
        CompareToken::Gt => CompareOp::Gt,
        CompareToken::Lt => CompareOp::Lt,
        CompareToken::Match => unreachable!("Match handled before compare_token_to_op"),
    }
}

fn build_from_compact_expr(
    severity: Severity,
    expr: &str,
) -> std::result::Result<RuleCondition, String> {
    match parse_condition_expr(expr) {
        ConditionExpr::Compare { lhs, op, rhs } => {
            // Regex match: `$value =~ "^pattern"`
            if op == CompareToken::Match {
                let pattern = strip_quotes(&rhs);
                return Ok(RuleCondition::RegexMatch {
                    value: lhs,
                    pattern,
                    severity,
                });
            }
            // Check for bool equality: `$x == true`, `$x != false`, etc.
            if matches!(op, CompareToken::Eq | CompareToken::Neq)
                && let Some(cond) = try_bool_equals(&lhs, op, &rhs, &severity)
            {
                return Ok(cond);
            }
            // Check for quoted string equality: `$x == "hello"`
            if matches!(op, CompareToken::Eq | CompareToken::Neq) && is_quoted(&rhs) {
                let s = strip_quotes(&rhs);
                let expected = if op == CompareToken::Eq {
                    ExpectedValue::Str(s)
                } else {
                    // != "str" not directly expressible as Equals; fall through
                    // to numeric (will error at runtime for non-numeric).
                    return Ok(RuleCondition::NumericThreshold {
                        value: lhs,
                        operator: compare_token_to_op(op),
                        threshold: rhs,
                        severity,
                    });
                };
                return Ok(RuleCondition::Equals {
                    value: lhs,
                    expected,
                    severity,
                });
            }
            Ok(RuleCondition::NumericThreshold {
                value: lhs,
                operator: compare_token_to_op(op),
                threshold: rhs,
                severity,
            })
        }
        ConditionExpr::Bare(pipeline) => Ok(RuleCondition::NonEmpty {
            value: pipeline,
            severity,
        }),
    }
}

/// Strip surrounding single or double quotes from a string, if present.
fn strip_quotes(s: &str) -> String {
    let s = s.trim();
    if (s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')) {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

/// Returns true if the string is surrounded by quotes.
fn is_quoted(s: &str) -> bool {
    let s = s.trim();
    (s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\''))
}

fn try_bool_equals(
    lhs: &str,
    op: CompareToken,
    rhs: &str,
    severity: &Severity,
) -> Option<RuleCondition> {
    let rhs_trimmed = rhs.trim();
    let bool_val = match rhs_trimmed {
        "true" => true,
        "false" => false,
        _ => return None,
    };
    // `!= true` → expected false; `!= false` → expected true
    let expected = if op == CompareToken::Eq {
        bool_val
    } else {
        !bool_val
    };
    Some(RuleCondition::Equals {
        value: lhs.to_string(),
        expected: ExpectedValue::Bool(expected),
        severity: severity.clone(),
    })
}

impl<'de> Deserialize<'de> for RuleCondition {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        let compact = CompactCondition::deserialize(deserializer)?;
        compact.into_rule_condition().map_err(D::Error::custom)
    }
}
