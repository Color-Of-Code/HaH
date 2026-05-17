//! Filter construction: maps filter names and arguments to [`Filter`] variants.

use crate::pipeline::{Filter, RuleValue};
use anyhow::{Result, anyhow};

/// Build a [`Filter`] from a name and evaluated arguments.
pub fn build_filter(name: &str, args: Vec<RuleValue>) -> Result<Filter> {
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
    // Filters that take a list argument
    if let Some(f) = list_arg_filter(name, &args)? {
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
        "last" => Some(Filter::Last),
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
        "group_count" => Ok(Some(Filter::GroupCount(n()?))),
        "where_gt" => {
            let v = args
                .first()
                .and_then(RuleValue::as_int)
                .ok_or_else(|| anyhow!("where_gt requires an integer argument"))?;
            Ok(Some(Filter::WhereGt(v)))
        }
        _ => Ok(None),
    }
}

fn require_str_arg<'a>(name: &str, args: &'a [RuleValue]) -> Result<&'a str> {
    args.first()
        .and_then(RuleValue::as_str)
        .ok_or_else(|| anyhow!("{} requires a string argument", name))
}

fn str_arg_filter(name: &str, args: &[RuleValue]) -> Result<Option<Filter>> {
    let ctor: fn(String) -> Filter = match name {
        "prefix_strip" => Filter::PrefixStrip,
        "starts_with" => Filter::StartsWith,
        "contains" => Filter::Contains,
        "reject_contains" => Filter::RejectContains,
        "icontains" => Filter::IContains,
        "join" => Filter::Join,
        "default" => Filter::Default,
        _ => return Ok(None),
    };
    Ok(Some(ctor(require_str_arg(name, args)?.to_string())))
}

fn list_arg_filter(name: &str, args: &[RuleValue]) -> Result<Option<Filter>> {
    match name {
        "intersect" | "reject_in" => {
            let items = args
                .first()
                .and_then(RuleValue::as_list)
                .ok_or_else(|| anyhow!("{name} requires a list argument"))?;
            let strings: Vec<String> = items.iter().map(RuleValue::display).collect();
            Ok(Some(match name {
                "intersect" => Filter::Intersect(strings),
                _ => Filter::RejectIn(strings),
            }))
        }
        _ => Ok(None),
    }
}
