//! Strongly typed expression AST for the HaH DSL.

use crate::pipeline::{RuleValue, ValueMap};
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
    use crate::pipeline::Filter;

    // Bridge to existing filter implementations in pipeline.rs
    // This is temporary until we refactor pipeline.rs to use the new AST/Evaluator
    let filter = match name {
        "trim" => Filter::Trim,
        "lines" => Filter::Lines,
        "non_empty" => Filter::NonEmpty,
        "first" => Filter::First,
        "number" => Filter::Number,
        "count" => Filter::Count,
        "sort" => Filter::Sort,
        "unique" => Filter::Unique,
        "bytes_to_mb" => Filter::BytesToMb,
        "skip" => {
            let n = args
                .first()
                .and_then(RuleValue::as_int)
                .ok_or_else(|| anyhow!("skip requires an integer argument"))?;
            Filter::Skip(n as usize)
        }
        "nth" => {
            let n = args
                .first()
                .and_then(RuleValue::as_int)
                .ok_or_else(|| anyhow!("nth requires an integer argument"))?;
            Filter::Nth(n as usize)
        }
        "field" => {
            let n = args
                .first()
                .and_then(RuleValue::as_int)
                .ok_or_else(|| anyhow!("field requires an integer argument"))?;
            Filter::Field(n as usize)
        }
        "prefix_strip" => {
            let s = args
                .first()
                .and_then(RuleValue::as_str)
                .ok_or_else(|| anyhow!("prefix_strip requires a string argument"))?;
            Filter::PrefixStrip(s.to_string())
        }
        "starts_with" => {
            let s = args
                .first()
                .and_then(RuleValue::as_str)
                .ok_or_else(|| anyhow!("starts_with requires a string argument"))?;
            Filter::StartsWith(s.to_string())
        }
        "contains" => {
            let s = args
                .first()
                .and_then(RuleValue::as_str)
                .ok_or_else(|| anyhow!("contains requires a string argument"))?;
            Filter::Contains(s.to_string())
        }
        "reject_contains" => {
            let s = args
                .first()
                .and_then(RuleValue::as_str)
                .ok_or_else(|| anyhow!("reject_contains requires a string argument"))?;
            Filter::RejectContains(s.to_string())
        }
        "join" => {
            let s = args
                .first()
                .and_then(RuleValue::as_str)
                .ok_or_else(|| anyhow!("join requires a string argument"))?;
            Filter::Join(s.to_string())
        }
        "default" => {
            let s = args
                .first()
                .and_then(RuleValue::as_str)
                .ok_or_else(|| anyhow!("default requires a string argument"))?;
            Filter::Default(s.to_string())
        }
        _ => return Err(anyhow!("Unknown filter: {}", name)),
    };

    crate::pipeline::apply_filter_public(value, &filter)
}
