pub mod capabilities;
pub mod expr;
pub mod filters;
pub mod parsers;
pub mod pipeline;
pub mod rule;

#[cfg(test)]
pub mod testutil {
    use crate::pipeline::{RuleValue, ValueMap};

    /// Construct a `RuleValue::Str` from a string literal.
    pub fn sv(s: &str) -> RuleValue {
        RuleValue::Str(s.to_string())
    }

    /// Construct a `RuleValue::List` of strings from a slice of string literals.
    pub fn list(items: &[&str]) -> RuleValue {
        RuleValue::List(items.iter().copied().map(sv).collect())
    }

    /// Construct a `ValueMap` from a slice of `(key, value)` pairs.
    pub fn map_of(pairs: &[(&str, RuleValue)]) -> ValueMap {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), v.clone()))
            .collect()
    }
}
