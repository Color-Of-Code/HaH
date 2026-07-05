use crate::pipeline::RuleValue;
use anyhow::{Result, anyhow};

fn map_string_or_list<F>(value: RuleValue, filter_name: &str, map: F) -> Result<RuleValue>
where
    F: Fn(&str) -> RuleValue,
{
    match value {
        RuleValue::Str(s) => Ok(map(&s)),
        RuleValue::List(v) => Ok(RuleValue::List(
            v.into_iter()
                .map(|item| match item {
                    RuleValue::Str(s) => map(&s),
                    other => other,
                })
                .collect(),
        )),
        other => Err(anyhow!(
            "{filter_name}: expected a string or list, got {:?}",
            other
        )),
    }
}

fn filter_string_list<F>(
    value: RuleValue,
    filter_name: &str,
    keep_non_strings: bool,
    predicate: F,
) -> Result<RuleValue>
where
    F: Fn(&str) -> bool,
{
    match value {
        RuleValue::List(v) => Ok(RuleValue::List(
            v.into_iter()
                .filter(|item| match item {
                    RuleValue::Str(s) => predicate(s),
                    _ => keep_non_strings,
                })
                .collect(),
        )),
        RuleValue::Null => Ok(RuleValue::List(vec![])),
        other => Err(anyhow!("{filter_name}: expected a list, got {:?}", other)),
    }
}

pub fn trim(value: RuleValue) -> Result<RuleValue> {
    map_string_or_list(value, "trim", |s| RuleValue::Str(s.trim().to_string()))
}

pub fn regex_escape(value: RuleValue) -> Result<RuleValue> {
    match value {
        RuleValue::Null => Ok(RuleValue::Null),
        RuleValue::Str(s) => Ok(RuleValue::Str(regex::escape(&s))),
        RuleValue::List(v) => Ok(RuleValue::List(
            v.into_iter()
                .map(|item| match item {
                    RuleValue::Str(s) => RuleValue::Str(regex::escape(&s)),
                    other => other,
                })
                .collect(),
        )),
        other => Err(anyhow!(
            "regex_escape: expected a string or list, got {:?}",
            other
        )),
    }
}

pub fn lines(value: RuleValue) -> Result<RuleValue> {
    match value {
        RuleValue::Str(s) => Ok(RuleValue::List(
            s.lines()
                .map(|line| RuleValue::Str(line.to_string()))
                .collect(),
        )),
        RuleValue::Null => Ok(RuleValue::List(vec![])),
        other => Err(anyhow!("lines: expected a string, got {:?}", other)),
    }
}

pub fn field(value: RuleValue, n: usize) -> Result<RuleValue> {
    map_string_or_list(value, "field", |s| {
        let fields: Vec<&str> = s.split_whitespace().collect();
        fields
            .get(n)
            .map_or(RuleValue::Null, |f| RuleValue::Str(f.to_string()))
    })
}

pub fn prefix_strip(value: RuleValue, prefix: &str) -> Result<RuleValue> {
    match value {
        RuleValue::Null => Ok(RuleValue::Null),
        other => map_string_or_list(other, "prefix_strip", |s| {
            RuleValue::Str(s.strip_prefix(prefix).unwrap_or(s).to_string())
        }),
    }
}

pub fn prefix_add(value: RuleValue, prefix: &str) -> Result<RuleValue> {
    match value {
        RuleValue::Null => Ok(RuleValue::Null),
        other => map_string_or_list(other, "prefix_add", |s| {
            RuleValue::Str(format!("{prefix}{s}"))
        }),
    }
}

/// Strip a trailing suffix from each string value, or from a single string input.
pub fn suffix_strip(value: RuleValue, suffix: &str) -> Result<RuleValue> {
    match value {
        RuleValue::Null => Ok(RuleValue::Null),
        other => map_string_or_list(other, "suffix_strip", |s| {
            RuleValue::Str(s.strip_suffix(suffix).unwrap_or(s).to_string())
        }),
    }
}

pub fn starts_with(value: RuleValue, prefix: &str) -> Result<RuleValue> {
    match value {
        RuleValue::List(_) => {
            filter_string_list(value, "starts_with", false, |s| s.starts_with(prefix))
        }
        RuleValue::Str(s) => Ok(if s.starts_with(prefix) {
            RuleValue::Str(s)
        } else {
            RuleValue::Null
        }),
        RuleValue::Null => Ok(RuleValue::Null),
        other => Err(anyhow!(
            "starts_with: expected a list or string, got {:?}",
            other
        )),
    }
}

pub fn contains(value: &RuleValue, substring: &str) -> Result<RuleValue> {
    match value {
        RuleValue::List(v) => Ok(RuleValue::Bool(v.iter().any(|item| match item {
            RuleValue::Str(s) => s.contains(substring),
            _ => false,
        }))),
        RuleValue::Str(s) => Ok(RuleValue::Bool(s.contains(substring))),
        _ => Ok(RuleValue::Bool(false)),
    }
}

pub fn reject_contains(value: RuleValue, substring: &str) -> Result<RuleValue> {
    filter_string_list(value, "reject_contains", true, |s| !s.contains(substring))
}

/// Case-insensitive `contains`.
///
/// On a `List`, keeps only items whose string representation contains the
/// substring (case-insensitively), returning the filtered list.
/// On a `Str`, returns `Bool(true/false)`.
pub fn icontains(value: RuleValue, substring: &str) -> Result<RuleValue> {
    let lower_sub = substring.to_lowercase();
    match value {
        RuleValue::List(_) => filter_string_list(value, "icontains", false, |s| {
            s.to_lowercase().contains(&lower_sub)
        }),
        RuleValue::Str(s) => Ok(RuleValue::Bool(s.to_lowercase().contains(&lower_sub))),
        _ => Ok(RuleValue::Bool(false)),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::testutil::{list, sv};

    #[test]
    fn trim_string() {
        assert_eq!(trim(sv("  hello  ")).unwrap(), sv("hello"));
    }

    #[test]
    fn trim_list() {
        assert_eq!(trim(list(&["  a  ", " b"])).unwrap(), list(&["a", "b"]));
    }

    #[test]
    fn trim_err_on_non_str_non_list() {
        assert!(trim(RuleValue::Int(1)).is_err());
    }

    #[test]
    fn regex_escape_escapes_regex_metacharacters() {
        assert_eq!(
            regex_escape(sv("foo.bar+baz?")).unwrap(),
            sv("foo\\.bar\\+baz\\?")
        );
    }

    #[test]
    fn lines_splits_on_newlines() {
        assert_eq!(lines(sv("a\nb\nc")).unwrap(), list(&["a", "b", "c"]));
    }

    #[test]
    fn lines_err_on_non_str() {
        assert!(lines(RuleValue::Int(1)).is_err());
    }

    #[test]
    fn field_returns_nth_word() {
        assert_eq!(field(sv("hello world foo"), 1).unwrap(), sv("world"));
    }

    #[test]
    fn field_out_of_range_returns_null() {
        assert_eq!(field(sv("a"), 5).unwrap(), RuleValue::Null);
    }

    #[test]
    fn field_on_list_applies_per_element() {
        assert_eq!(field(list(&["a b", "c d"]), 1).unwrap(), list(&["b", "d"]));
    }

    #[test]
    fn field_err_on_non_str_non_list() {
        assert!(field(RuleValue::Int(1), 0).is_err());
    }

    #[test]
    fn prefix_strip_str() {
        assert_eq!(
            prefix_strip(sv("linux-5.15"), "linux-").unwrap(),
            sv("5.15")
        );
    }

    #[test]
    fn prefix_strip_no_match_unchanged() {
        assert_eq!(prefix_strip(sv("other"), "linux-").unwrap(), sv("other"));
    }

    #[test]
    fn prefix_strip_null_returns_null() {
        assert_eq!(
            prefix_strip(RuleValue::Null, "linux-").unwrap(),
            RuleValue::Null
        );
    }

    #[test]
    fn prefix_strip_list() {
        assert_eq!(
            prefix_strip(list(&["linux-1", "other"]), "linux-").unwrap(),
            list(&["1", "other"])
        );
    }

    #[test]
    fn prefix_add_str() {
        assert_eq!(
            prefix_add(sv("5.15"), "linux-image-").unwrap(),
            sv("linux-image-5.15")
        );
    }

    #[test]
    fn prefix_add_list() {
        assert_eq!(
            prefix_add(list(&["1", "2"]), "linux-image-").unwrap(),
            list(&["linux-image-1", "linux-image-2"])
        );
    }

    #[test]
    fn suffix_strip_str() {
        assert_eq!(
            suffix_strip(sv("6.8.0-134-generic"), "-generic").unwrap(),
            sv("6.8.0-134")
        );
    }

    #[test]
    fn suffix_strip_list() {
        assert_eq!(
            suffix_strip(list(&["1-generic", "2-generic"]), "-generic").unwrap(),
            list(&["1", "2"])
        );
    }

    #[test]
    fn prefix_strip_err_on_non_str_non_list() {
        assert!(prefix_strip(RuleValue::Int(1), "x").is_err());
    }

    #[test]
    fn starts_with_filters_list() {
        assert_eq!(
            starts_with(list(&["linux-5", "headers-5", "linux-6"]), "linux-").unwrap(),
            list(&["linux-5", "linux-6"])
        );
    }

    #[test]
    fn starts_with_str_matches() {
        assert_eq!(starts_with(sv("linux-5"), "linux-").unwrap(), sv("linux-5"));
    }

    #[test]
    fn starts_with_str_no_match_returns_null() {
        assert_eq!(starts_with(sv("other"), "linux-").unwrap(), RuleValue::Null);
    }

    #[test]
    fn starts_with_null_returns_null() {
        assert_eq!(
            starts_with(RuleValue::Null, "linux-").unwrap(),
            RuleValue::Null
        );
    }

    #[test]
    fn starts_with_err_on_non_str_non_list() {
        assert!(starts_with(RuleValue::Int(1), "x").is_err());
    }

    #[test]
    fn contains_list_found() {
        assert_eq!(
            contains(&list(&["hello", "world"]), "world").unwrap(),
            RuleValue::Bool(true)
        );
    }

    #[test]
    fn contains_list_not_found() {
        assert_eq!(
            contains(&list(&["hello"]), "missing").unwrap(),
            RuleValue::Bool(false)
        );
    }

    #[test]
    fn contains_str_found() {
        assert_eq!(
            contains(&sv("hello world"), "world").unwrap(),
            RuleValue::Bool(true)
        );
    }

    #[test]
    fn contains_non_str_returns_false() {
        assert_eq!(
            contains(&RuleValue::Int(1), "x").unwrap(),
            RuleValue::Bool(false)
        );
    }

    #[test]
    fn reject_contains_filters_list() {
        assert_eq!(
            reject_contains(list(&["keep", "drop-this", "keep2"]), "drop").unwrap(),
            list(&["keep", "keep2"])
        );
    }

    #[test]
    fn reject_contains_err_on_non_list() {
        assert!(reject_contains(sv("x"), "x").is_err());
    }

    #[test]
    fn icontains_list_case_insensitive() {
        let input = list(&["Broken module", "ok", "NOT INSTALLED"]);
        let result = icontains(input, "broken").unwrap();
        assert_eq!(result, list(&["Broken module"]));
    }

    #[test]
    fn icontains_list_no_match() {
        let result = icontains(list(&["ok", "installed"]), "broken").unwrap();
        assert_eq!(result, list(&[]));
    }

    #[test]
    fn icontains_str_true() {
        assert_eq!(
            icontains(sv("BROKEN module"), "broken").unwrap(),
            RuleValue::Bool(true)
        );
    }

    #[test]
    fn icontains_str_false() {
        assert_eq!(
            icontains(sv("ok"), "broken").unwrap(),
            RuleValue::Bool(false)
        );
    }

    #[test]
    fn icontains_non_str_returns_false() {
        assert_eq!(
            icontains(RuleValue::Int(1), "x").unwrap(),
            RuleValue::Bool(false)
        );
    }
}
