use crate::pipeline::{Filter, RuleValue};
use anyhow::Result;

pub mod build;
pub mod list;
pub mod scalar;
pub mod string;

pub fn apply(value: RuleValue, filter: &Filter) -> Result<RuleValue> {
    filter.apply(value)
}

impl Filter {
    pub fn apply(&self, value: RuleValue) -> Result<RuleValue> {
        self.apply_list_basic(value)
            .or_else(|value| self.apply_list_pattern(value))
            .or_else(|value| self.apply_string(value))
            .or_else(|value| self.apply_scalar(value))
            .unwrap_or_else(|_| unreachable!("all Filter variants are handled"))
    }

    fn apply_list_basic(
        &self,
        value: RuleValue,
    ) -> std::result::Result<Result<RuleValue>, RuleValue> {
        match self {
            Filter::NonEmpty => Ok(list::non_empty(value)),
            Filter::Skip(n) => Ok(list::skip(value, *n)),
            Filter::First => Ok(list::first(value)),
            Filter::Nth(n) => Ok(list::nth(value, *n)),
            Filter::Count => Ok(Ok(list::count(&value))),
            Filter::Sort => Ok(list::sort(value)),
            Filter::Unique => Ok(list::unique(value)),
            Filter::Join(s) => Ok(list::join(value, s)),
            Filter::Last => Ok(list::last(value)),
            Filter::GroupCount(n) => Ok(list::group_count(value, *n)),
            Filter::Conflicts => Ok(list::conflicts(value)),
            _ => Err(value),
        }
    }

    fn apply_list_pattern(
        &self,
        value: RuleValue,
    ) -> std::result::Result<Result<RuleValue>, RuleValue> {
        match self {
            Filter::WhereGt(threshold) => Ok(list::where_gt(value, *threshold)),
            Filter::Intersect(other) => Ok(list::intersect(value, other)),
            Filter::RejectIn(other) => Ok(list::reject_in(value, other)),
            Filter::RejectMatches(other) => Ok(list::reject_matches(value, other)),
            Filter::Grep(patterns) => Ok(list::grep(value, patterns)),
            Filter::RejectGrep(patterns) => Ok(list::reject_grep(value, patterns)),
            _ => Err(value),
        }
    }

    fn apply_string(&self, value: RuleValue) -> std::result::Result<Result<RuleValue>, RuleValue> {
        match self {
            Filter::Trim => Ok(string::trim(value)),
            Filter::RegexEscape => Ok(string::regex_escape(value)),
            Filter::Lines => Ok(string::lines(value)),
            Filter::Field(n) => Ok(string::field(value, *n)),
            Filter::PrefixStrip(s) => Ok(string::prefix_strip(value, s)),
            Filter::PrefixAdd(s) => Ok(string::prefix_add(value, s)),
            Filter::SuffixStrip(s) => Ok(string::suffix_strip(value, s)),
            Filter::StartsWith(s) => Ok(string::starts_with(value, s)),
            Filter::Contains(s) => Ok(string::contains(&value, s)),
            Filter::RejectContains(s) => Ok(string::reject_contains(value, s)),
            Filter::IContains(s) => Ok(string::icontains(value, s)),
            _ => Err(value),
        }
    }

    fn apply_scalar(&self, value: RuleValue) -> std::result::Result<Result<RuleValue>, RuleValue> {
        match self {
            Filter::Number => Ok(scalar::number(value)),
            Filter::BytesToMb => Ok(scalar::bytes_to_mb(value)),
            Filter::ToBytes => Ok(scalar::to_bytes(value)),
            Filter::Default(s) => Ok(scalar::default_val(value, s.clone())),
            _ => Err(value),
        }
    }
}
