//! Filter construction: maps filter names and arguments to [`Filter`] variants.

use crate::pipeline::{Filter, RuleValue};
use anyhow::{Result, anyhow};

macro_rules! zero_arg_filters {
    ($name:expr; $( $filter_name:literal => $variant:ident ),+ $(,)?) => {
        match $name {
            $( $filter_name => Some(Self::$variant), )+
            _ => None,
        }
    };
}

macro_rules! unary_arg_filters {
    ($name:expr, $arg:expr; $( $filter_name:literal => $variant:ident ),+ $(,)?) => {
        match $name {
            $( $filter_name => Ok(Some(Self::$variant($arg))), )+
            _ => Ok(None),
        }
    };
}

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
        zero_arg_filters!(name;
            "trim" => Trim,
            "lines" => Lines,
            "non_empty" => NonEmpty,
            "first" => First,
            "last" => Last,
            "number" => Number,
            "count" => Count,
            "sort" => Sort,
            "unique" => Unique,
            "bytes_to_mb" => BytesToMb,
            "to_bytes" => ToBytes,
            "conflicts" => Conflicts,
        )
    }

    fn int_arg(name: &str, args: &[RuleValue]) -> Result<Option<Self>> {
        match name {
            "where_gt" => Ok(Some(Self::WhereGt(Self::require_int_arg(name, args)?))),
            _ => unary_arg_filters!(name, Self::require_usize_arg(name, args)?;
                "skip" => Skip,
                "nth" => Nth,
                "field" => Field,
                "group_count" => GroupCount,
            ),
        }
    }

    fn require_int_arg(name: &str, args: &[RuleValue]) -> Result<i64> {
        args.first()
            .and_then(RuleValue::as_int)
            .ok_or_else(|| anyhow!("{} requires an integer argument", name))
    }

    fn require_usize_arg(name: &str, args: &[RuleValue]) -> Result<usize> {
        Ok(Self::require_int_arg(name, args)? as usize)
    }

    fn require_str_arg<'a>(name: &str, args: &'a [RuleValue]) -> Result<&'a str> {
        args.first()
            .and_then(RuleValue::as_str)
            .ok_or_else(|| anyhow!("{} requires a string argument", name))
    }

    fn require_list_arg<'a>(name: &str, args: &'a [RuleValue]) -> Result<&'a [RuleValue]> {
        match args.first() {
            Some(RuleValue::List(items)) => Ok(items),
            Some(RuleValue::Null) => Ok(&[]),
            _ => Err(anyhow!("{name} requires a list argument")),
        }
    }

    fn str_arg(name: &str, args: &[RuleValue]) -> Result<Option<Self>> {
        unary_arg_filters!(name, Self::require_str_arg(name, args)?.to_string();
            "prefix_strip" => PrefixStrip,
            "starts_with" => StartsWith,
            "contains" => Contains,
            "reject_contains" => RejectContains,
            "icontains" => IContains,
            "join" => Join,
            "default" => Default,
            "grep" => Grep,
            "reject_grep" => RejectGrep,
        )
    }

    fn list_arg(name: &str, args: &[RuleValue]) -> Result<Option<Self>> {
        match name {
            "intersect" | "reject_in" => {
                let items = Self::require_list_arg(name, args)?;
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
