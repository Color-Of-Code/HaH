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

use std::collections::{HashMap, HashSet};

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
#[derive(Debug, Clone)]
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
}

fn parse_filter(token: &str) -> Result<Filter> {
    let token = token.trim();
    if let Some(paren_pos) = token.find('(') {
        if !token.ends_with(')') {
            return Err(anyhow!(
                "malformed filter (missing closing parenthesis): {token}"
            ));
        }
        let name = token[..paren_pos].trim();
        let raw_arg = token[paren_pos + 1..token.len() - 1].trim();
        let arg = raw_arg.trim_matches('\'').trim_matches('"');
        return parse_filter_with_arg(name, arg);
    }
    match token {
        "trim" => Ok(Filter::Trim),
        "lines" => Ok(Filter::Lines),
        "non_empty" => Ok(Filter::NonEmpty),
        "first" => Ok(Filter::First),
        "number" => Ok(Filter::Number),
        "count" => Ok(Filter::Count),
        "sort" => Ok(Filter::Sort),
        "unique" => Ok(Filter::Unique),
        "bytes_to_mb" => Ok(Filter::BytesToMb),
        other => Err(anyhow!("unknown filter: {other}")),
    }
}

fn parse_filter_with_arg(name: &str, arg: &str) -> Result<Filter> {
    match name {
        "skip" => arg
            .parse::<usize>()
            .map(Filter::Skip)
            .map_err(|_| anyhow!("skip: expected an integer argument, got {arg:?}")),
        "nth" => arg
            .parse::<usize>()
            .map(Filter::Nth)
            .map_err(|_| anyhow!("nth: expected an integer argument, got {arg:?}")),
        "field" => arg
            .parse::<usize>()
            .map(Filter::Field)
            .map_err(|_| anyhow!("field: expected an integer argument, got {arg:?}")),
        "prefix_strip" => Ok(Filter::PrefixStrip(arg.to_string())),
        "starts_with" => Ok(Filter::StartsWith(arg.to_string())),
        "contains" => Ok(Filter::Contains(arg.to_string())),
        "reject_contains" => Ok(Filter::RejectContains(arg.to_string())),
        "join" => Ok(Filter::Join(arg.to_string())),
        "default" => Ok(Filter::Default(arg.to_string())),
        other => Err(anyhow!("unknown filter with arguments: {other}")),
    }
}

// ── Pipeline ─────────────────────────────────────────────────────────────────

/// A parsed transformation pipeline.
#[derive(Debug)]
pub struct Pipeline {
    /// Variable name (without the leading `$`) used as the initial value.
    pub source: String,
    /// Ordered sequence of filter steps applied left to right.
    pub filters: Vec<Filter>,
}

/// Split a pipeline string on `|` while respecting single-quoted string
/// arguments such as `join(', ')`.
fn split_pipeline(expr: &str) -> Vec<String> {
    let mut parts: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut in_single = false;
    for ch in expr.chars() {
        match ch {
            '\'' => {
                in_single = !in_single;
                current.push(ch);
            }
            '|' if !in_single => {
                let part = current.trim().to_string();
                if !part.is_empty() {
                    parts.push(part);
                }
                current = String::new();
            }
            _ => current.push(ch),
        }
    }
    let last = current.trim().to_string();
    if !last.is_empty() {
        parts.push(last);
    }
    parts
}

/// Parse a pipeline expression string into a [`Pipeline`].
pub fn parse_pipeline(expr: &str) -> Result<Pipeline> {
    let parts = split_pipeline(expr);
    if parts.is_empty() {
        return Err(anyhow!("empty pipeline expression"));
    }
    let source_token = parts[0].trim();
    if !source_token.starts_with('$') {
        return Err(anyhow!(
            "pipeline source must start with '$', got: {source_token:?}"
        ));
    }
    let source = source_token.trim_start_matches('$').to_string();
    let filters = parts[1..]
        .iter()
        .map(|t| parse_filter(t))
        .collect::<Result<Vec<_>>>()?;
    Ok(Pipeline { source, filters })
}

// ── Individual filter implementations ────────────────────────────────────────

fn filter_trim(value: RuleValue) -> Result<RuleValue> {
    match value {
        RuleValue::Str(s) => Ok(RuleValue::Str(s.trim().to_string())),
        other => Ok(other),
    }
}

fn filter_lines(value: RuleValue) -> Result<RuleValue> {
    match value {
        RuleValue::Str(s) => Ok(RuleValue::List(
            s.lines().map(|l| RuleValue::Str(l.to_string())).collect(),
        )),
        other => Ok(RuleValue::List(vec![other])),
    }
}

fn filter_non_empty(value: RuleValue) -> Result<RuleValue> {
    match value {
        RuleValue::List(v) => Ok(RuleValue::List(
            v.into_iter()
                .filter(|x| match x {
                    RuleValue::Str(s) => !s.is_empty(),
                    RuleValue::Null => false,
                    _ => true,
                })
                .collect(),
        )),
        RuleValue::Str(s) if s.is_empty() => Ok(RuleValue::Null),
        other => Ok(other),
    }
}

fn filter_skip(value: RuleValue, n: usize) -> Result<RuleValue> {
    match value {
        RuleValue::List(v) => Ok(RuleValue::List(v.into_iter().skip(n).collect())),
        other => Err(anyhow!("skip: expected a list, got {:?}", other.display())),
    }
}

fn filter_first(value: RuleValue) -> Result<RuleValue> {
    match value {
        RuleValue::List(mut v) => Ok(if v.is_empty() {
            RuleValue::Null
        } else {
            v.remove(0)
        }),
        other => Ok(other),
    }
}

fn filter_nth(value: RuleValue, n: usize) -> Result<RuleValue> {
    match value {
        RuleValue::List(v) => Ok(v.into_iter().nth(n).unwrap_or(RuleValue::Null)),
        other => Err(anyhow!("nth: expected a list, got {:?}", other.display())),
    }
}

fn filter_field(value: RuleValue, n: usize) -> Result<RuleValue> {
    match value {
        RuleValue::Str(s) => Ok(s
            .split_whitespace()
            .nth(n)
            .map_or(RuleValue::Null, |f| RuleValue::Str(f.to_string()))),
        other => Err(anyhow!(
            "field: expected a string, got {:?}",
            other.display()
        )),
    }
}

fn filter_number(value: RuleValue) -> Result<RuleValue> {
    match value {
        RuleValue::Int(n) => Ok(RuleValue::Int(n)),
        RuleValue::Str(s) => s
            .trim()
            .parse::<i64>()
            .map(RuleValue::Int)
            .map_err(|_| anyhow!("number: cannot parse {:?} as an integer", s)),
        other => Err(anyhow!(
            "number: expected a string or int, got {:?}",
            other.display()
        )),
    }
}

fn filter_count(value: &RuleValue) -> RuleValue {
    let n: i64 = match value {
        RuleValue::List(v) => v.len() as i64,
        RuleValue::Str(s) => i64::from(!s.is_empty()),
        RuleValue::Null => 0,
        _ => 1,
    };
    RuleValue::Int(n)
}

fn filter_prefix_strip(value: RuleValue, prefix: &str) -> Result<RuleValue> {
    match value {
        RuleValue::Str(s) => Ok(RuleValue::Str(
            s.strip_prefix(prefix).unwrap_or(&s).to_string(),
        )),
        RuleValue::List(v) => Ok(RuleValue::List(
            v.into_iter()
                .map(|item| match item {
                    RuleValue::Str(s) => {
                        RuleValue::Str(s.strip_prefix(prefix).unwrap_or(&s).to_string())
                    }
                    other => other,
                })
                .collect(),
        )),
        other => Err(anyhow!(
            "prefix_strip: expected a string or list, got {:?}",
            other.display()
        )),
    }
}

fn filter_starts_with(value: RuleValue, prefix: &str) -> Result<RuleValue> {
    match value {
        RuleValue::List(v) => Ok(RuleValue::List(
            v.into_iter()
                .filter(|item| match item {
                    RuleValue::Str(s) => s.starts_with(prefix),
                    _ => false,
                })
                .collect(),
        )),
        RuleValue::Str(s) => Ok(if s.starts_with(prefix) {
            RuleValue::Str(s)
        } else {
            RuleValue::Null
        }),
        other => Err(anyhow!(
            "starts_with: expected a list or string, got {:?}",
            other.display()
        )),
    }
}

fn filter_contains(value: &RuleValue, substring: &str) -> Result<RuleValue> {
    match value {
        RuleValue::List(v) => Ok(RuleValue::Bool(v.iter().any(|item| match item {
            RuleValue::Str(s) => s.contains(substring),
            _ => false,
        }))),
        RuleValue::Str(s) => Ok(RuleValue::Bool(s.contains(substring))),
        _ => Ok(RuleValue::Bool(false)),
    }
}

fn filter_reject_contains(value: RuleValue, substring: &str) -> Result<RuleValue> {
    match value {
        RuleValue::List(v) => Ok(RuleValue::List(
            v.into_iter()
                .filter(|item| match item {
                    RuleValue::Str(s) => !s.contains(substring),
                    _ => true,
                })
                .collect(),
        )),
        other => Err(anyhow!(
            "reject_contains: expected a list, got {:?}",
            other.display()
        )),
    }
}

fn filter_sort(value: RuleValue) -> Result<RuleValue> {
    match value {
        RuleValue::List(mut v) => {
            v.sort_by_key(RuleValue::display);
            Ok(RuleValue::List(v))
        }
        other => Ok(other),
    }
}

fn filter_unique(value: RuleValue) -> Result<RuleValue> {
    match value {
        RuleValue::List(v) => {
            let mut seen = HashSet::new();
            Ok(RuleValue::List(
                v.into_iter().filter(|x| seen.insert(x.display())).collect(),
            ))
        }
        other => Ok(other),
    }
}

fn filter_join(value: RuleValue, sep: &str) -> Result<RuleValue> {
    match value {
        RuleValue::List(v) => Ok(RuleValue::Str(
            v.iter()
                .map(RuleValue::display)
                .collect::<Vec<_>>()
                .join(sep),
        )),
        RuleValue::Str(s) => Ok(RuleValue::Str(s)),
        other => Err(anyhow!("join: expected a list, got {:?}", other.display())),
    }
}

fn filter_bytes_to_mb(value: RuleValue) -> Result<RuleValue> {
    match value {
        RuleValue::Int(n) => Ok(RuleValue::Int(n / 1_048_576)),
        RuleValue::Str(s) => s
            .trim()
            .parse::<i64>()
            .map(|n| RuleValue::Int(n / 1_048_576))
            .map_err(|_| anyhow!("bytes_to_mb: cannot parse {:?} as an integer", s)),
        other => Err(anyhow!(
            "bytes_to_mb: expected int or string, got {:?}",
            other.display()
        )),
    }
}

fn filter_default(value: RuleValue, default_val: &str) -> RuleValue {
    let use_default =
        matches!(value, RuleValue::Null) || matches!(&value, RuleValue::Str(s) if s.is_empty());
    if use_default {
        RuleValue::Str(default_val.to_string())
    } else {
        value
    }
}

// ── Filter dispatch ───────────────────────────────────────────────────────────

fn apply_scalar_filter(value: RuleValue, filter: &Filter) -> Result<RuleValue> {
    match filter {
        Filter::Trim => filter_trim(value),
        Filter::Lines => filter_lines(value),
        Filter::NonEmpty => filter_non_empty(value),
        Filter::First => filter_first(value),
        Filter::Sort => filter_sort(value),
        Filter::Unique => filter_unique(value),
        Filter::Count => Ok(filter_count(&value)),
        Filter::Skip(n) => filter_skip(value, *n),
        Filter::Nth(n) => filter_nth(value, *n),
        Filter::Field(n) => filter_field(value, *n),
        Filter::Number => filter_number(value),
        _ => unreachable!(),
    }
}

fn apply_string_filter(value: RuleValue, filter: &Filter) -> Result<RuleValue> {
    match filter {
        Filter::PrefixStrip(p) => filter_prefix_strip(value, p),
        Filter::StartsWith(p) => filter_starts_with(value, p),
        Filter::Contains(s) => filter_contains(&value, s),
        Filter::RejectContains(s) => filter_reject_contains(value, s),
        Filter::Join(sep) => filter_join(value, sep),
        Filter::BytesToMb => filter_bytes_to_mb(value),
        Filter::Default(d) => Ok(filter_default(value, d)),
        _ => unreachable!(),
    }
}

pub fn apply_filter_public(value: RuleValue, filter: &Filter) -> Result<RuleValue> {
    apply_filter(value, filter)
}

fn apply_filter(value: RuleValue, filter: &Filter) -> Result<RuleValue> {
    match filter {
        Filter::Trim
        | Filter::Lines
        | Filter::NonEmpty
        | Filter::First
        | Filter::Sort
        | Filter::Unique
        | Filter::Count
        | Filter::Skip(_)
        | Filter::Nth(_)
        | Filter::Field(_)
        | Filter::Number => apply_scalar_filter(value, filter),
        _ => apply_string_filter(value, filter),
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Evaluate a parsed pipeline against the given value map.
pub fn eval_pipeline(pipeline: &Pipeline, values: &ValueMap) -> Result<RuleValue> {
    let mut current = values
        .get(&pipeline.source)
        .cloned()
        .unwrap_or(RuleValue::Null);
    for filter in &pipeline.filters {
        current = apply_filter(current, filter)?;
    }
    Ok(current)
}

/// Evaluate an expression using the new strongly typed engine.
pub fn eval_expr(expr: &str, values: &ValueMap) -> Result<RuleValue> {
    let mut input = expr.trim();
    let ast = crate::parser::parse_eval_expr(&mut input)
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

    fn str_val(s: &str) -> RuleValue {
        RuleValue::Str(s.to_string())
    }
    fn list_val(items: &[&str]) -> RuleValue {
        RuleValue::List(items.iter().copied().map(str_val).collect())
    }
    fn map_of(pairs: &[(&str, RuleValue)]) -> ValueMap {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), v.clone()))
            .collect()
    }

    // ── parse_filter ─────────────────────────────────────────────────────────

    #[test]
    fn parse_filter_no_args() {
        assert!(matches!(parse_filter("trim").unwrap(), Filter::Trim));
        assert!(matches!(parse_filter("lines").unwrap(), Filter::Lines));
        assert!(matches!(parse_filter("count").unwrap(), Filter::Count));
        assert!(matches!(parse_filter("sort").unwrap(), Filter::Sort));
        assert!(matches!(parse_filter("unique").unwrap(), Filter::Unique));
        assert!(matches!(parse_filter("number").unwrap(), Filter::Number));
        assert!(matches!(
            parse_filter("bytes_to_mb").unwrap(),
            Filter::BytesToMb
        ));
    }

    #[test]
    fn parse_filter_with_int_arg() {
        assert!(matches!(parse_filter("nth(2)").unwrap(), Filter::Nth(2)));
        assert!(matches!(parse_filter("skip(3)").unwrap(), Filter::Skip(3)));
        assert!(matches!(
            parse_filter("field(0)").unwrap(),
            Filter::Field(0)
        ));
    }

    #[test]
    fn parse_filter_with_string_arg() {
        let f = parse_filter("join(', ')").unwrap();
        assert!(matches!(f, Filter::Join(s) if s == ", "));
        let f = parse_filter("prefix_strip('foo ')").unwrap();
        assert!(matches!(f, Filter::PrefixStrip(s) if s == "foo "));
    }

    #[test]
    fn parse_filter_unknown_returns_err() {
        assert!(parse_filter("nonexistent").is_err());
    }

    // ── parse_pipeline ────────────────────────────────────────────────────────

    #[test]
    fn parse_pipeline_simple() {
        let p = parse_pipeline("$stdout | lines | trim").unwrap();
        assert_eq!(p.source, "stdout");
        assert_eq!(p.filters.len(), 2);
    }

    #[test]
    fn parse_pipeline_no_filters() {
        let p = parse_pipeline("$result").unwrap();
        assert_eq!(p.source, "result");
        assert!(p.filters.is_empty());
    }

    #[test]
    fn parse_pipeline_quoted_separator_in_arg() {
        // The ',' inside join('|') must not be treated as a separator
        let p = parse_pipeline("$list | join(' | ')").unwrap();
        assert_eq!(p.source, "list");
        assert_eq!(p.filters.len(), 1);
        assert!(matches!(&p.filters[0], Filter::Join(s) if s == " | "));
    }

    #[test]
    fn parse_pipeline_missing_dollar_returns_err() {
        assert!(parse_pipeline("stdout | lines").is_err());
    }

    // ── apply_filter ─────────────────────────────────────────────────────────

    #[test]
    fn filter_trim() {
        let v = apply_filter(str_val("  hello  "), &Filter::Trim).unwrap();
        assert_eq!(v, str_val("hello"));
    }

    #[test]
    fn filter_lines_splits_by_newline() {
        let v = apply_filter(str_val("a\nb\nc"), &Filter::Lines).unwrap();
        assert_eq!(v, list_val(&["a", "b", "c"]));
    }

    #[test]
    fn filter_non_empty_removes_blanks() {
        let v = apply_filter(list_val(&["a", "", "b", ""]), &Filter::NonEmpty).unwrap();
        assert_eq!(v, list_val(&["a", "b"]));
    }

    #[test]
    fn filter_nth_returns_correct_item() {
        let v = apply_filter(list_val(&["a", "b", "c"]), &Filter::Nth(1)).unwrap();
        assert_eq!(v, str_val("b"));
    }

    #[test]
    fn filter_nth_out_of_range_returns_null() {
        let v = apply_filter(list_val(&["a"]), &Filter::Nth(5)).unwrap();
        assert_eq!(v, RuleValue::Null);
    }

    #[test]
    fn filter_number_parses_string() {
        let v = apply_filter(str_val("  42  "), &Filter::Number).unwrap();
        assert_eq!(v, RuleValue::Int(42));
    }

    #[test]
    fn filter_number_invalid_returns_err() {
        assert!(apply_filter(str_val("not-a-number"), &Filter::Number).is_err());
    }

    #[test]
    fn filter_starts_with_filters_list() {
        let v = apply_filter(
            list_val(&["foo bar", "baz", "foo qux"]),
            &Filter::StartsWith("foo".to_string()),
        )
        .unwrap();
        assert_eq!(v, list_val(&["foo bar", "foo qux"]));
    }

    #[test]
    fn filter_prefix_strip_on_list() {
        let v = apply_filter(
            list_val(&["rc pkg-a", "rc pkg-b"]),
            &Filter::PrefixStrip("rc ".to_string()),
        )
        .unwrap();
        assert_eq!(v, list_val(&["pkg-a", "pkg-b"]));
    }

    #[test]
    fn filter_reject_contains() {
        let v = apply_filter(
            list_val(&["linux-image-5.15", "linux-image-6.1", "linux-image-meta"]),
            &Filter::RejectContains("meta".to_string()),
        )
        .unwrap();
        assert_eq!(v, list_val(&["linux-image-5.15", "linux-image-6.1"]));
    }

    #[test]
    fn filter_count_on_list() {
        let v = apply_filter(list_val(&["a", "b", "c"]), &Filter::Count).unwrap();
        assert_eq!(v, RuleValue::Int(3));
    }

    #[test]
    fn filter_sort() {
        let v = apply_filter(list_val(&["banana", "apple", "cherry"]), &Filter::Sort).unwrap();
        assert_eq!(v, list_val(&["apple", "banana", "cherry"]));
    }

    #[test]
    fn filter_unique_removes_duplicates() {
        let v = apply_filter(list_val(&["a", "b", "a", "c", "b"]), &Filter::Unique).unwrap();
        assert_eq!(v, list_val(&["a", "b", "c"]));
    }

    #[test]
    fn filter_join_produces_string() {
        let v = apply_filter(list_val(&["x", "y", "z"]), &Filter::Join(", ".to_string())).unwrap();
        assert_eq!(v, str_val("x, y, z"));
    }

    #[test]
    fn filter_bytes_to_mb() {
        let v = apply_filter(RuleValue::Int(2 * 1_048_576), &Filter::BytesToMb).unwrap();
        assert_eq!(v, RuleValue::Int(2));
    }

    #[test]
    fn filter_default_on_null() {
        let v = apply_filter(RuleValue::Null, &Filter::Default("fallback".to_string())).unwrap();
        assert_eq!(v, str_val("fallback"));
    }

    #[test]
    fn filter_default_on_non_null_passes_through() {
        let v = apply_filter(str_val("actual"), &Filter::Default("fallback".to_string())).unwrap();
        assert_eq!(v, str_val("actual"));
    }

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
        let values = map_of(&[("out", str_val("  42  "))]);
        let v = eval_expr("$out | trim | number", &values).unwrap();
        assert_eq!(v, RuleValue::Int(42));
    }

    #[test]
    fn eval_expr_pipeline_nth_and_trim() {
        let values = map_of(&[("out", str_val("header\n  99  \n"))]);
        let v = eval_expr("$out | lines | nth(1) | trim | number", &values).unwrap();
        assert_eq!(v, RuleValue::Int(99));
    }

    // ── render_template ───────────────────────────────────────────────────────

    #[test]
    fn render_template_substitutes_placeholders() {
        let values = map_of(&[
            ("name", str_val("linux-image-5.15")),
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
            RuleValue::List(vec![str_val("a"), RuleValue::Int(1)]).display(),
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

    // ── Filter error paths ────────────────────────────────────────────────────

    #[test]
    fn filter_skip_non_list_returns_err() {
        assert!(apply_filter(RuleValue::Int(1), &Filter::Skip(1)).is_err());
    }

    #[test]
    fn filter_nth_non_list_returns_err() {
        assert!(apply_filter(RuleValue::Int(1), &Filter::Nth(0)).is_err());
    }

    #[test]
    fn filter_field_non_string_returns_err() {
        assert!(apply_filter(RuleValue::Int(1), &Filter::Field(0)).is_err());
    }

    #[test]
    fn filter_number_null_returns_err() {
        assert!(apply_filter(RuleValue::Null, &Filter::Number).is_err());
    }

    #[test]
    fn filter_prefix_strip_on_other_returns_err() {
        assert!(apply_filter(RuleValue::Null, &Filter::PrefixStrip("x".into())).is_err());
    }

    #[test]
    fn filter_starts_with_on_other_returns_err() {
        assert!(apply_filter(RuleValue::Int(1), &Filter::StartsWith("x".into())).is_err());
    }

    #[test]
    fn filter_reject_contains_non_list_returns_err() {
        assert!(apply_filter(RuleValue::Int(1), &Filter::RejectContains("x".into())).is_err());
    }

    #[test]
    fn filter_join_non_list_non_str_returns_err() {
        assert!(apply_filter(RuleValue::Int(1), &Filter::Join(",".into())).is_err());
    }

    #[test]
    fn filter_bytes_to_mb_on_null_returns_err() {
        assert!(apply_filter(RuleValue::Null, &Filter::BytesToMb).is_err());
    }

    #[test]
    fn filter_bytes_to_mb_invalid_str_returns_err() {
        assert!(apply_filter(str_val("not-a-number"), &Filter::BytesToMb).is_err());
    }

    // ── Filter positive paths not yet exercised ───────────────────────────────

    #[test]
    fn filter_trim_on_non_str_passes_through() {
        let v = apply_filter(RuleValue::Int(5), &Filter::Trim).unwrap();
        assert_eq!(v, RuleValue::Int(5));
    }

    #[test]
    fn filter_lines_on_non_str_wraps_in_list() {
        let v = apply_filter(RuleValue::Int(1), &Filter::Lines).unwrap();
        assert_eq!(v, RuleValue::List(vec![RuleValue::Int(1)]));
    }

    #[test]
    fn filter_non_empty_non_empty_str_passes_through() {
        let v = apply_filter(str_val("hello"), &Filter::NonEmpty).unwrap();
        assert_eq!(v, str_val("hello"));
    }

    #[test]
    fn filter_non_empty_other_variant_passes_through() {
        let v = apply_filter(RuleValue::Int(1), &Filter::NonEmpty).unwrap();
        assert_eq!(v, RuleValue::Int(1));
    }

    #[test]
    fn filter_skip_on_list() {
        let v = apply_filter(list_val(&["a", "b", "c"]), &Filter::Skip(1)).unwrap();
        assert_eq!(v, list_val(&["b", "c"]));
    }

    #[test]
    fn filter_first_on_non_empty_list() {
        let v = apply_filter(list_val(&["x", "y"]), &Filter::First).unwrap();
        assert_eq!(v, str_val("x"));
    }

    #[test]
    fn filter_first_on_empty_list_returns_null() {
        let v = apply_filter(RuleValue::List(vec![]), &Filter::First).unwrap();
        assert_eq!(v, RuleValue::Null);
    }

    #[test]
    fn filter_first_on_non_list_passes_through() {
        let v = apply_filter(str_val("abc"), &Filter::First).unwrap();
        assert_eq!(v, str_val("abc"));
    }

    #[test]
    fn filter_field_on_string() {
        let v = apply_filter(str_val("hello world foo"), &Filter::Field(1)).unwrap();
        assert_eq!(v, str_val("world"));
    }

    #[test]
    fn filter_field_out_of_bounds_returns_null() {
        let v = apply_filter(str_val("one two"), &Filter::Field(5)).unwrap();
        assert_eq!(v, RuleValue::Null);
    }

    #[test]
    fn filter_number_on_int_passes_through() {
        let v = apply_filter(RuleValue::Int(7), &Filter::Number).unwrap();
        assert_eq!(v, RuleValue::Int(7));
    }

    #[test]
    fn filter_prefix_strip_on_single_str() {
        let v = apply_filter(str_val("rc pkg"), &Filter::PrefixStrip("rc ".into())).unwrap();
        assert_eq!(v, str_val("pkg"));
    }

    #[test]
    fn filter_prefix_strip_no_prefix_match_unchanged() {
        let v = apply_filter(str_val("other"), &Filter::PrefixStrip("rc ".into())).unwrap();
        assert_eq!(v, str_val("other"));
    }

    #[test]
    fn filter_prefix_strip_in_list_no_match_unchanged() {
        let v = apply_filter(
            list_val(&["foo bar", "baz"]),
            &Filter::PrefixStrip("qux ".into()),
        )
        .unwrap();
        assert_eq!(v, list_val(&["foo bar", "baz"]));
    }

    #[test]
    fn filter_starts_with_on_matching_str() {
        let v = apply_filter(str_val("foo bar"), &Filter::StartsWith("foo".into())).unwrap();
        assert_eq!(v, str_val("foo bar"));
    }

    #[test]
    fn filter_starts_with_on_non_matching_str_returns_null() {
        let v = apply_filter(str_val("bar"), &Filter::StartsWith("foo".into())).unwrap();
        assert_eq!(v, RuleValue::Null);
    }

    #[test]
    fn filter_contains_in_list_true() {
        let v = apply_filter(list_val(&["foo", "bar"]), &Filter::Contains("foo".into())).unwrap();
        assert_eq!(v, RuleValue::Bool(true));
    }

    #[test]
    fn filter_contains_in_list_false() {
        let v = apply_filter(list_val(&["foo", "bar"]), &Filter::Contains("baz".into())).unwrap();
        assert_eq!(v, RuleValue::Bool(false));
    }

    #[test]
    fn filter_contains_in_str() {
        let v = apply_filter(str_val("hello world"), &Filter::Contains("world".into())).unwrap();
        assert_eq!(v, RuleValue::Bool(true));
    }

    #[test]
    fn filter_contains_on_other_returns_false() {
        let v = apply_filter(RuleValue::Null, &Filter::Contains("x".into())).unwrap();
        assert_eq!(v, RuleValue::Bool(false));
    }

    #[test]
    fn filter_count_on_empty_str() {
        let v = apply_filter(str_val(""), &Filter::Count).unwrap();
        assert_eq!(v, RuleValue::Int(0));
    }

    #[test]
    fn filter_count_on_non_empty_str() {
        let v = apply_filter(str_val("x"), &Filter::Count).unwrap();
        assert_eq!(v, RuleValue::Int(1));
    }

    #[test]
    fn filter_count_on_null() {
        let v = apply_filter(RuleValue::Null, &Filter::Count).unwrap();
        assert_eq!(v, RuleValue::Int(0));
    }

    #[test]
    fn filter_count_on_int() {
        let v = apply_filter(RuleValue::Int(99), &Filter::Count).unwrap();
        assert_eq!(v, RuleValue::Int(1));
    }

    #[test]
    fn filter_sort_on_non_list_passes_through() {
        let v = apply_filter(str_val("z"), &Filter::Sort).unwrap();
        assert_eq!(v, str_val("z"));
    }

    #[test]
    fn filter_unique_on_non_list_passes_through() {
        let v = apply_filter(RuleValue::Int(5), &Filter::Unique).unwrap();
        assert_eq!(v, RuleValue::Int(5));
    }

    #[test]
    fn filter_join_str_passes_through() {
        let v = apply_filter(str_val("abc"), &Filter::Join(",".into())).unwrap();
        assert_eq!(v, str_val("abc"));
    }

    #[test]
    fn filter_bytes_to_mb_from_str() {
        let v = apply_filter(str_val("2097152"), &Filter::BytesToMb).unwrap();
        assert_eq!(v, RuleValue::Int(2));
    }

    #[test]
    fn filter_default_on_empty_str() {
        let v = apply_filter(str_val(""), &Filter::Default("fallback".into())).unwrap();
        assert_eq!(v, str_val("fallback"));
    }

    // ── Additional parse tests ────────────────────────────────────────────────

    #[test]
    fn parse_filter_unclosed_paren_returns_err() {
        assert!(parse_filter("nth(5").is_err());
    }

    #[test]
    fn parse_pipeline_empty_string_returns_err() {
        assert!(parse_pipeline("").is_err());
    }

    #[test]
    fn eval_expr_string_literal() {
        let v = eval_expr("hello world", &ValueMap::new()).unwrap();
        assert_eq!(v, RuleValue::Str("hello world".into()));
    }
}
