//! Strongly typed expression AST for the HaH DSL.

use crate::pipeline::{Filter, RuleValue, ValueMap};
use anyhow::{Result, anyhow};

#[derive(Debug, Clone, PartialEq)]
pub enum Expression {
    /// A variable reference (e.g., `$stdout`).
    Variable(String),
    /// A literal value (e.g., `'foo'`, `42`, `true`).
    Literal(RuleValue),
    /// A function call or filter (e.g., `trim`, `nth(1)`).
    Filter { name: String, args: Vec<Expression> },
    /// A pipeline of expressions (e.g., `expr | expr | expr`).
    Pipeline(Vec<Expression>),
}

impl Expression {
    pub fn eval(&self, values: &ValueMap) -> Result<RuleValue> {
        match self {
            Self::Variable(name) => Ok(values.get(name).cloned().unwrap_or(RuleValue::Null)),
            Self::Literal(val) => Ok(val.clone()),
            Self::Filter { name, args } => {
                // Standalone filter call: evaluate arguments and apply
                let mut evaled_args = Vec::new();
                for arg in args {
                    evaled_args.push(arg.eval(values)?);
                }
                apply_filter_new(RuleValue::Null, name, evaled_args)
            }
            Self::Pipeline(steps) => {
                if steps.is_empty() {
                    return Ok(RuleValue::Null);
                }
                let mut current = steps[0].eval(values)?;
                for step in &steps[1..] {
                    current = match step {
                        Self::Filter { name, args } => {
                            // Evaluate arguments
                            let mut evaled_args = Vec::new();
                            for arg in args {
                                evaled_args.push(arg.eval(values)?);
                            }
                            apply_filter_new(current, name, evaled_args)?
                        }
                        _ => return Err(anyhow!("Expected filter in pipeline, got {:?}", step)),
                    };
                }
                Ok(current)
            }
        }
    }
}

fn apply_filter_new(value: RuleValue, name: &str, args: Vec<RuleValue>) -> Result<RuleValue> {
    let filter = build_filter(name, args)?;
    crate::filters::apply(value, &filter)
}

fn build_filter(name: &str, args: Vec<RuleValue>) -> Result<Filter> {
    // Zero-argument filters
    if let Some(f) = zero_arg_filter(name) {
        return Ok(f);
    }
    // Filters that take an integer argument
    if let Some(f) = int_arg_filter(name, &args)? {
        return Ok(f);
    }
    // Filters that take a string argument
    if let Some(f) = str_arg_filter(name, &args)? {
        return Ok(f);
    }
    Err(anyhow!("Unknown filter: {}", name))
}

fn zero_arg_filter(name: &str) -> Option<Filter> {
    match name {
        "trim" => Some(Filter::Trim),
        "lines" => Some(Filter::Lines),
        "non_empty" => Some(Filter::NonEmpty),
        "first" => Some(Filter::First),
        "number" => Some(Filter::Number),
        "count" => Some(Filter::Count),
        "sort" => Some(Filter::Sort),
        "unique" => Some(Filter::Unique),
        "bytes_to_mb" => Some(Filter::BytesToMb),
        _ => None,
    }
}

fn int_arg_filter(name: &str, args: &[RuleValue]) -> Result<Option<Filter>> {
    let n = || -> Result<usize> {
        args.first()
            .and_then(RuleValue::as_int)
            .map(|n| n as usize)
            .ok_or_else(|| anyhow!("{} requires an integer argument", name))
    };
    match name {
        "skip" => Ok(Some(Filter::Skip(n()?))),
        "nth" => Ok(Some(Filter::Nth(n()?))),
        "field" => Ok(Some(Filter::Field(n()?))),
        _ => Ok(None),
    }
}

fn str_arg_filter(name: &str, args: &[RuleValue]) -> Result<Option<Filter>> {
    let s = || -> Result<String> {
        args.first()
            .and_then(RuleValue::as_str)
            .map(str::to_string)
            .ok_or_else(|| anyhow!("{} requires a string argument", name))
    };
    match name {
        "prefix_strip" => Ok(Some(Filter::PrefixStrip(s()?))),
        "starts_with" => Ok(Some(Filter::StartsWith(s()?))),
        "contains" => Ok(Some(Filter::Contains(s()?))),
        "reject_contains" => Ok(Some(Filter::RejectContains(s()?))),
        "join" => Ok(Some(Filter::Join(s()?))),
        "default" => Ok(Some(Filter::Default(s()?))),
        _ => Ok(None),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::testutil::map_of;
    use std::collections::HashMap;

    // ── Variable ──────────────────────────────────────────────────────────────

    #[test]
    fn eval_variable_found() {
        let values = map_of(&[("x", RuleValue::Int(7))]);
        assert_eq!(
            Expression::Variable("x".into()).eval(&values).unwrap(),
            RuleValue::Int(7)
        );
    }

    #[test]
    fn eval_variable_missing_returns_null() {
        assert_eq!(
            Expression::Variable("missing".into())
                .eval(&HashMap::new())
                .unwrap(),
            RuleValue::Null
        );
    }

    // ── Literal ───────────────────────────────────────────────────────────────

    #[test]
    fn eval_literal_passthrough() {
        assert_eq!(
            Expression::Literal(RuleValue::Bool(true))
                .eval(&HashMap::new())
                .unwrap(),
            RuleValue::Bool(true)
        );
    }

    // ── Standalone filter ─────────────────────────────────────────────────────

    #[test]
    fn eval_standalone_filter_trim() {
        // A standalone Filter applied to Null (degenerate case)
        let expr = Expression::Filter {
            name: "trim".into(),
            args: vec![],
        };
        // trim on Null gives an error — that's the expected behaviour
        assert!(expr.eval(&HashMap::new()).is_err());
    }

    #[test]
    fn eval_unknown_filter_errors() {
        let expr = Expression::Filter {
            name: "no_such_filter".into(),
            args: vec![],
        };
        assert!(expr.eval(&HashMap::new()).is_err());
    }

    // ── Pipeline ──────────────────────────────────────────────────────────────

    #[test]
    fn eval_empty_pipeline_returns_null() {
        assert_eq!(
            Expression::Pipeline(vec![]).eval(&HashMap::new()).unwrap(),
            RuleValue::Null
        );
    }

    #[test]
    fn eval_pipeline_non_filter_step_errors() {
        let expr = Expression::Pipeline(vec![
            Expression::Literal(RuleValue::Str("hello".into())),
            Expression::Literal(RuleValue::Str("not_a_filter".into())),
        ]);
        assert!(expr.eval(&HashMap::new()).is_err());
    }

    #[test]
    fn eval_pipeline_trim() {
        let values = map_of(&[("v", RuleValue::Str("  hi  ".into()))]);
        let expr = Expression::Pipeline(vec![
            Expression::Variable("v".into()),
            Expression::Filter {
                name: "trim".into(),
                args: vec![],
            },
        ]);
        assert_eq!(expr.eval(&values).unwrap(), RuleValue::Str("hi".into()));
    }

    // ── apply_filter_new branches ─────────────────────────────────────────────

    #[test]
    fn all_zero_arg_filters_dispatch_without_panic() {
        for name in &[
            "trim",
            "lines",
            "non_empty",
            "first",
            "number",
            "count",
            "sort",
            "unique",
            "bytes_to_mb",
        ] {
            let expr = Expression::Filter {
                name: name.to_string(),
                args: vec![],
            };
            // We don't care about the result (Null input may error), just that
            // the dispatch arm exists.
            let _ = expr.eval(&HashMap::new());
        }
    }

    #[test]
    fn filter_skip_applies_with_int_arg() {
        let values = map_of(&[(
            "v",
            RuleValue::List(vec![
                RuleValue::Str("a".into()),
                RuleValue::Str("b".into()),
                RuleValue::Str("c".into()),
            ]),
        )]);
        let expr = Expression::Pipeline(vec![
            Expression::Variable("v".into()),
            Expression::Filter {
                name: "skip".into(),
                args: vec![Expression::Literal(RuleValue::Int(1))],
            },
        ]);
        assert_eq!(
            expr.eval(&values).unwrap(),
            RuleValue::List(vec![RuleValue::Str("b".into()), RuleValue::Str("c".into()),])
        );
    }

    #[test]
    fn filter_nth_applies_with_int_arg() {
        let values = map_of(&[(
            "v",
            RuleValue::List(vec![RuleValue::Str("a".into()), RuleValue::Str("b".into())]),
        )]);
        let expr = Expression::Pipeline(vec![
            Expression::Variable("v".into()),
            Expression::Filter {
                name: "nth".into(),
                args: vec![Expression::Literal(RuleValue::Int(1))],
            },
        ]);
        assert_eq!(expr.eval(&values).unwrap(), RuleValue::Str("b".into()));
    }

    #[test]
    fn filter_field_applies_with_int_arg() {
        let values = map_of(&[("v", RuleValue::Str("hello world".into()))]);
        let expr = Expression::Pipeline(vec![
            Expression::Variable("v".into()),
            Expression::Filter {
                name: "field".into(),
                args: vec![Expression::Literal(RuleValue::Int(1))],
            },
        ]);
        assert_eq!(expr.eval(&values).unwrap(), RuleValue::Str("world".into()));
    }

    #[test]
    fn filter_prefix_strip_applies_with_str_arg() {
        let values = map_of(&[("v", RuleValue::Str("linux-5.15".into()))]);
        let expr = Expression::Pipeline(vec![
            Expression::Variable("v".into()),
            Expression::Filter {
                name: "prefix_strip".into(),
                args: vec![Expression::Literal(RuleValue::Str("linux-".into()))],
            },
        ]);
        assert_eq!(expr.eval(&values).unwrap(), RuleValue::Str("5.15".into()));
    }

    #[test]
    fn filter_starts_with_applies_with_str_arg() {
        let values = map_of(&[(
            "v",
            RuleValue::List(vec![
                RuleValue::Str("linux-5".into()),
                RuleValue::Str("other".into()),
            ]),
        )]);
        let expr = Expression::Pipeline(vec![
            Expression::Variable("v".into()),
            Expression::Filter {
                name: "starts_with".into(),
                args: vec![Expression::Literal(RuleValue::Str("linux-".into()))],
            },
        ]);
        assert_eq!(
            expr.eval(&values).unwrap(),
            RuleValue::List(vec![RuleValue::Str("linux-5".into())])
        );
    }

    #[test]
    fn filter_contains_applies_with_str_arg() {
        let values = map_of(&[("v", RuleValue::Str("hello world".into()))]);
        let expr = Expression::Pipeline(vec![
            Expression::Variable("v".into()),
            Expression::Filter {
                name: "contains".into(),
                args: vec![Expression::Literal(RuleValue::Str("world".into()))],
            },
        ]);
        assert_eq!(expr.eval(&values).unwrap(), RuleValue::Bool(true));
    }

    #[test]
    fn filter_reject_contains_applies_with_str_arg() {
        let values = map_of(&[(
            "v",
            RuleValue::List(vec![
                RuleValue::Str("keep".into()),
                RuleValue::Str("drop-this".into()),
            ]),
        )]);
        let expr = Expression::Pipeline(vec![
            Expression::Variable("v".into()),
            Expression::Filter {
                name: "reject_contains".into(),
                args: vec![Expression::Literal(RuleValue::Str("drop".into()))],
            },
        ]);
        assert_eq!(
            expr.eval(&values).unwrap(),
            RuleValue::List(vec![RuleValue::Str("keep".into())])
        );
    }

    #[test]
    fn filter_join_applies_with_str_arg() {
        let values = map_of(&[(
            "v",
            RuleValue::List(vec![RuleValue::Str("a".into()), RuleValue::Str("b".into())]),
        )]);
        let expr = Expression::Pipeline(vec![
            Expression::Variable("v".into()),
            Expression::Filter {
                name: "join".into(),
                args: vec![Expression::Literal(RuleValue::Str(", ".into()))],
            },
        ]);
        assert_eq!(expr.eval(&values).unwrap(), RuleValue::Str("a, b".into()));
    }

    #[test]
    fn filter_default_applies_with_str_arg() {
        let values = map_of(&[("v", RuleValue::Null)]);
        let expr = Expression::Pipeline(vec![
            Expression::Variable("v".into()),
            Expression::Filter {
                name: "default".into(),
                args: vec![Expression::Literal(RuleValue::Str("fallback".into()))],
            },
        ]);
        assert_eq!(
            expr.eval(&values).unwrap(),
            RuleValue::Str("fallback".into())
        );
    }

    #[test]
    fn filter_skip_missing_arg_errors() {
        let expr = Expression::Filter {
            name: "skip".into(),
            args: vec![],
        };
        assert!(expr.eval(&HashMap::new()).is_err());
    }
}
