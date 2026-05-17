//! Condition evaluation logic.

use anyhow::{Result, anyhow};

use crate::pipeline::{ValueMap, eval_expr};

use super::model::{CompareOp, ExpectedValue, RuleCondition};

/// Evaluate a single condition against the value map.
pub fn eval_condition(
    condition: &RuleCondition,
    values: &ValueMap,
    recurse: &dyn Fn(&RuleCondition, &ValueMap) -> Result<bool>,
) -> Result<bool> {
    match condition {
        RuleCondition::NumericThreshold {
            value,
            operator,
            threshold,
            ..
        } => eval_numeric_threshold(value, operator, threshold, values),

        RuleCondition::Equals {
            value, expected, ..
        } => eval_equals(value, expected, values),

        RuleCondition::NonEmpty { value, .. } => Ok(eval_expr(value, values)?.is_truthy()),

        RuleCondition::RegexMatch { value, pattern, .. } => {
            eval_regex_match(value, pattern, values)
        }

        RuleCondition::All { conditions, .. } => conditions
            .iter()
            .try_fold(true, |acc, c| Ok(acc && recurse(c, values)?)),

        RuleCondition::Any { conditions, .. } => {
            for c in conditions {
                if recurse(c, values)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
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

fn eval_numeric_threshold(
    value: &str,
    operator: &CompareOp,
    threshold: &str,
    values: &ValueMap,
) -> Result<bool> {
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

fn eval_equals(value: &str, expected: &ExpectedValue, values: &ValueMap) -> Result<bool> {
    let actual = eval_expr(value, values)?;
    Ok(match expected {
        ExpectedValue::Bool(b) => actual.as_bool() == Some(*b),
        ExpectedValue::Int(n) => actual.as_int() == Some(*n),
        ExpectedValue::Str(s) => actual.as_str() == Some(s.as_str()),
    })
}

fn eval_regex_match(value: &str, pattern: &str, values: &ValueMap) -> Result<bool> {
    let re = regex::Regex::new(pattern)
        .map_err(|e| anyhow!("invalid regex pattern {pattern:?}: {e}"))?;
    let v = eval_expr(value, values)?;
    Ok(re.is_match(v.as_str().unwrap_or("")))
}
