//! Small, readable filter-pipeline language for the HaH DSL.
//!
//! A pipeline is a string such as:
//!
//! ```text
//! $stdout | lines | nth(1) | trim | number
//! ```
//!
//! The first token names the source variable (with a leading `$`).  Every
//! subsequent token is a filter step that transforms the current value.
//!
//! Use [`eval_expr`] for the public entry point.  Use [`render_template`] to
//! substitute `{varname}` placeholders in outcome strings.

use std::collections::HashMap;

use anyhow::{Result, anyhow};

// ── Runtime value ─────────────────────────────────────────────────────────────

/// A typed runtime value produced or consumed by a filter pipeline.
#[derive(Debug, Clone, PartialEq)]
pub enum RuleValue {
    Bool(bool),
    Int(i64),
    Str(String),
    List(Vec<RuleValue>),
    Null,
}

impl RuleValue {
    /// Return the value as a `&str` if it is a [`RuleValue::Str`].
    pub fn as_str(&self) -> Option<&str> {
        if let Self::Str(s) = self {
            Some(s)
        } else {
            None
        }
    }

    /// Return the value as an `i64`, parsing from a string if necessary.
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Self::Int(n) => Some(*n),
            Self::Str(s) => s.trim().parse().ok(),
            _ => None,
        }
    }

    /// Return the value as a `bool` if it is a [`RuleValue::Bool`].
    pub fn as_bool(&self) -> Option<bool> {
        if let Self::Bool(b) = self {
            Some(*b)
        } else {
            None
        }
    }

    /// Return the value as a slice if it is a [`RuleValue::List`].
    pub fn as_list(&self) -> Option<&[RuleValue]> {
        if let Self::List(v) = self {
            Some(v)
        } else {
            None
        }
    }

    /// Human-readable form used in template substitution and `join`.
    pub fn display(&self) -> String {
        match self {
            Self::Bool(b) => b.to_string(),
            Self::Int(n) => n.to_string(),
            Self::Str(s) => s.clone(),
            Self::List(v) => v.iter().map(Self::display).collect::<Vec<_>>().join(", "),
            Self::Null => String::new(),
        }
    }

    /// Whether the value is considered truthy (non-empty, non-zero, non-null).
    pub fn is_truthy(&self) -> bool {
        match self {
            Self::Bool(b) => *b,
            Self::Int(n) => *n != 0,
            Self::Str(s) => !s.is_empty(),
            Self::List(v) => !v.is_empty(),
            Self::Null => false,
        }
    }
}

/// Map from variable names to their runtime values.
pub type ValueMap = HashMap<String, RuleValue>;

// ── Filter steps ─────────────────────────────────────────────────────────────

/// A single transformation step in a pipeline.
#[derive(Debug, Clone, PartialEq)]
pub enum Filter {
    Trim,
    Lines,
    NonEmpty,
    Skip(usize),
    First,
    Nth(usize),
    Field(usize),
    Number,
    PrefixStrip(String),
    StartsWith(String),
    Contains(String),
    RejectContains(String),
    Count,
    Sort,
    Unique,
    Join(String),
    BytesToMb,
    Default(String),
    Last,
    IContains(String),
    GroupCount(usize),
    WhereGt(i64),
}

// ── Public API ────────────────────────────────────────────────────────────────
/// Evaluate an expression using the new strongly typed engine.
pub fn eval_expr(expr: &str, values: &ValueMap) -> Result<RuleValue> {
    let mut input = expr.trim();
    let ast = crate::parsers::dsl::parse_eval_expr(&mut input)
        .map_err(|e| anyhow!("Failed to parse expression {:?}: {}", expr, e))?;
    ast.eval(values)
}

/// Substitute `{varname}` placeholders in a template string using the value map.
pub fn render_template(template: &str, values: &ValueMap) -> String {
    let mut result = template.to_string();
    for (key, value) in values {
        result = result.replace(&format!("{{{key}}}"), &value.display());
    }
    result
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::testutil::{map_of, sv};

    // ── eval_expr ─────────────────────────────────────────────────────────────

    #[test]
    fn eval_expr_bare_variable() {
        let values = map_of(&[("foo", RuleValue::Int(7))]);
        let v = eval_expr("$foo", &values).unwrap();
        assert_eq!(v, RuleValue::Int(7));
    }

    #[test]
    fn eval_expr_missing_variable_returns_null() {
        let v = eval_expr("$missing", &ValueMap::new()).unwrap();
        assert_eq!(v, RuleValue::Null);
    }

    #[test]
    fn eval_expr_integer_literal() {
        let v = eval_expr("42", &ValueMap::new()).unwrap();
        assert_eq!(v, RuleValue::Int(42));
    }

    #[test]
    fn eval_expr_boolean_literal() {
        assert_eq!(
            eval_expr("true", &ValueMap::new()).unwrap(),
            RuleValue::Bool(true)
        );
        assert_eq!(
            eval_expr("false", &ValueMap::new()).unwrap(),
            RuleValue::Bool(false)
        );
    }

    #[test]
    fn eval_expr_pipeline() {
        let values = map_of(&[("out", sv("  42  "))]);
        let v = eval_expr("$out | trim | number", &values).unwrap();
        assert_eq!(v, RuleValue::Int(42));
    }

    #[test]
    fn eval_expr_pipeline_nth_and_trim() {
        let values = map_of(&[("out", sv("header\n  99  \n"))]);
        let v = eval_expr("$out | lines | nth(1) | trim | number", &values).unwrap();
        assert_eq!(v, RuleValue::Int(99));
    }

    // ── render_template ───────────────────────────────────────────────────────

    #[test]
    fn render_template_substitutes_placeholders() {
        let values = map_of(&[
            ("name", sv("linux-image-5.15")),
            ("count", RuleValue::Int(3)),
        ]);
        let result = render_template("{count} package(s): {name}", &values);
        assert_eq!(result, "3 package(s): linux-image-5.15");
    }

    #[test]
    fn render_template_unknown_placeholder_kept() {
        let result = render_template("{unknown}", &ValueMap::new());
        assert_eq!(result, "{unknown}");
    }

    // ── RuleValue methods ─────────────────────────────────────────────────────

    #[test]
    fn rule_value_display_all_variants() {
        assert_eq!(RuleValue::Bool(true).display(), "true");
        assert_eq!(RuleValue::Bool(false).display(), "false");
        assert_eq!(RuleValue::Int(42).display(), "42");
        assert_eq!(RuleValue::Null.display(), "");
        assert_eq!(
            RuleValue::List(vec![sv("a"), RuleValue::Int(1)]).display(),
            "a, 1"
        );
    }

    #[test]
    fn rule_value_is_truthy_all_variants() {
        assert!(RuleValue::Bool(true).is_truthy());
        assert!(!RuleValue::Bool(false).is_truthy());
        assert!(RuleValue::Int(1).is_truthy());
        assert!(!RuleValue::Int(0).is_truthy());
        assert!(RuleValue::Str("x".into()).is_truthy());
        assert!(!RuleValue::Str(String::new()).is_truthy());
        assert!(RuleValue::List(vec![RuleValue::Null]).is_truthy());
        assert!(!RuleValue::List(vec![]).is_truthy());
        assert!(!RuleValue::Null.is_truthy());
    }

    #[test]
    fn rule_value_as_accessors() {
        // as_str
        assert_eq!(RuleValue::Str("x".into()).as_str(), Some("x"));
        assert_eq!(RuleValue::Int(3).as_str(), None);
        // as_bool
        assert_eq!(RuleValue::Bool(true).as_bool(), Some(true));
        assert_eq!(RuleValue::Str("y".into()).as_bool(), None);
        // as_list
        let items = vec![RuleValue::Null];
        assert_eq!(
            RuleValue::List(items.clone()).as_list(),
            Some(items.as_slice())
        );
        assert_eq!(RuleValue::Null.as_list(), None);
        // as_int
        assert_eq!(RuleValue::Int(5).as_int(), Some(5));
        assert_eq!(RuleValue::Str("7".into()).as_int(), Some(7));
        assert_eq!(RuleValue::Null.as_int(), None);
        assert_eq!(RuleValue::Bool(true).as_int(), None);
    }
}
