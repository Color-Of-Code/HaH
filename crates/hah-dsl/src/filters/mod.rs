use crate::pipeline::{Filter, RuleValue};
use anyhow::Result;

pub mod list;
pub mod scalar;
pub mod string;

pub fn apply(value: RuleValue, filter: &Filter) -> Result<RuleValue> {
    apply_list(value, filter)
        .or_else(|(v, f)| apply_string(v, f))
        .or_else(|(v, f)| apply_scalar(v, f))
        .unwrap_or_else(|_| unreachable!("all Filter variants are handled"))
}

fn apply_list(
    value: RuleValue,
    filter: &Filter,
) -> std::result::Result<Result<RuleValue>, (RuleValue, &Filter)> {
    match filter {
        Filter::NonEmpty => Ok(list::non_empty(value)),
        Filter::First => Ok(list::first(value)),
        Filter::Last => Ok(list::last(value)),
        Filter::Sort => Ok(list::sort(value)),
        Filter::Unique => Ok(list::unique(value)),
        Filter::Count => Ok(Ok(list::count(&value))),
        Filter::Skip(n) => Ok(list::skip(value, *n)),
        Filter::Nth(n) => Ok(list::nth(value, *n)),
        Filter::Join(s) => Ok(list::join(value, s)),
        Filter::GroupCount(n) => Ok(list::group_count(value, *n)),
        Filter::WhereGt(threshold) => Ok(list::where_gt(value, *threshold)),
        Filter::Intersect(other) => Ok(list::intersect(value, other)),
        Filter::RejectIn(other) => Ok(list::reject_in(value, other)),
        _ => Err((value, filter)),
    }
}

fn apply_string(
    value: RuleValue,
    filter: &Filter,
) -> std::result::Result<Result<RuleValue>, (RuleValue, &Filter)> {
    match filter {
        Filter::Trim => Ok(string::trim(value)),
        Filter::Lines => Ok(string::lines(value)),
        Filter::Field(n) => Ok(string::field(value, *n)),
        Filter::PrefixStrip(s) => Ok(string::prefix_strip(value, s)),
        Filter::StartsWith(s) => Ok(string::starts_with(value, s)),
        Filter::Contains(s) => Ok(string::contains(&value, s)),
        Filter::RejectContains(s) => Ok(string::reject_contains(value, s)),
        Filter::IContains(s) => Ok(string::icontains(value, s)),
        _ => Err((value, filter)),
    }
}

fn apply_scalar(
    value: RuleValue,
    filter: &Filter,
) -> std::result::Result<Result<RuleValue>, (RuleValue, &Filter)> {
    match filter {
        Filter::Number => Ok(scalar::number(value)),
        Filter::BytesToMb => Ok(scalar::bytes_to_mb(value)),
        Filter::Default(s) => Ok(scalar::default_val(value, s.clone())),
        _ => Err((value, filter)),
    }
}
