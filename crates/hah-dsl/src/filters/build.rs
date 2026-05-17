//! Filter construction: maps filter names and arguments to [`Filter`] variants.

use crate::pipeline::{Filter, RuleValue};
use anyhow::{Result, anyhow};

/// Build a [`Filter`] from a name and evaluated arguments.
pub fn build_filter(name: &str, args: Vec<RuleValue>) -> Result<Filter> {
    Filter::build(name, args)
}

impl Filter {
    pub fn build(name: &str, args: Vec<RuleValue>) -> Result<Self> {
        if let Some(filter) = Self::zero_arg(name) {
            return Ok(filter);
        }
        if let Some(filter) = Self::int_arg(name, &args)? {
            return Ok(filter);
        }
        if let Some(filter) = Self::str_arg(name, &args)? {
            return Ok(filter);
        }
        if let Some(filter) = Self::list_arg(name, &args)? {
            return Ok(filter);
        }
        Err(anyhow!("Unknown filter: {}", name))
    }

    fn zero_arg(name: &str) -> Option<Self> {
        match name {
            "trim" => Some(Self::Trim),
            "lines" => Some(Self::Lines),
            "non_empty" => Some(Self::NonEmpty),
            "first" => Some(Self::First),
            "last" => Some(Self::Last),
            "number" => Some(Self::Number),
            "count" => Some(Self::Count),
            "sort" => Some(Self::Sort),
            "unique" => Some(Self::Unique),
            "bytes_to_mb" => Some(Self::BytesToMb),
            _ => None,
        }
    }

    fn int_arg(name: &str, args: &[RuleValue]) -> Result<Option<Self>> {
        let n = || -> Result<usize> {
            args.first()
                .and_then(RuleValue::as_int)
                .map(|n| n as usize)
                .ok_or_else(|| anyhow!("{} requires an integer argument", name))
        };
        match name {
            "skip" => Ok(Some(Self::Skip(n()?))),
            "nth" => Ok(Some(Self::Nth(n()?))),
            "field" => Ok(Some(Self::Field(n()?))),
            "group_count" => Ok(Some(Self::GroupCount(n()?))),
            "where_gt" => {
                let v = args
                    .first()
                    .and_then(RuleValue::as_int)
                    .ok_or_else(|| anyhow!("where_gt requires an integer argument"))?;
                Ok(Some(Self::WhereGt(v)))
            }
            _ => Ok(None),
        }
    }

    fn require_str_arg<'a>(name: &str, args: &'a [RuleValue]) -> Result<&'a str> {
        args.first()
            .and_then(RuleValue::as_str)
            .ok_or_else(|| anyhow!("{} requires a string argument", name))
    }

    fn str_arg(name: &str, args: &[RuleValue]) -> Result<Option<Self>> {
        let ctor: fn(String) -> Self = match name {
            "prefix_strip" => Self::PrefixStrip,
            "starts_with" => Self::StartsWith,
            "contains" => Self::Contains,
            "reject_contains" => Self::RejectContains,
            "icontains" => Self::IContains,
            "join" => Self::Join,
            "default" => Self::Default,
            _ => return Ok(None),
        };
        Ok(Some(ctor(Self::require_str_arg(name, args)?.to_string())))
    }

    fn list_arg(name: &str, args: &[RuleValue]) -> Result<Option<Self>> {
        match name {
            "intersect" | "reject_in" => {
                let items = args
                    .first()
                    .and_then(RuleValue::as_list)
                    .ok_or_else(|| anyhow!("{name} requires a list argument"))?;
                let strings: Vec<String> = items.iter().map(RuleValue::display).collect();
                Ok(Some(match name {
                    "intersect" => Self::Intersect(strings),
                    _ => Self::RejectIn(strings),
                }))
            }
            _ => Ok(None),
        }
    }
}
