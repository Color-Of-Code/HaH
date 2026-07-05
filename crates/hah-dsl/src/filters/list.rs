use crate::pipeline::RuleValue;
use anyhow::{Result, anyhow};
use regex::Regex;
use std::collections::{HashMap, HashSet};

pub fn non_empty(value: RuleValue) -> Result<RuleValue> {
    match value {
        RuleValue::List(v) => Ok(RuleValue::List(
            v.into_iter()
                .filter(|item| !matches!(item, RuleValue::Null))
                .filter(|item| !matches!(item, RuleValue::Str(s) if s.is_empty()))
                .collect(),
        )),
        other => Err(anyhow!("non_empty: expected a list, got {:?}", other)),
    }
}

pub fn first(value: RuleValue) -> Result<RuleValue> {
    match value {
        RuleValue::List(mut v) => Ok(if v.is_empty() {
            RuleValue::Null
        } else {
            v.remove(0)
        }),
        other => Err(anyhow!("first: expected a list, got {:?}", other)),
    }
}

pub fn last(value: RuleValue) -> Result<RuleValue> {
    match value {
        RuleValue::List(mut v) => Ok(if v.is_empty() {
            RuleValue::Null
        } else {
            v.pop().unwrap_or(RuleValue::Null)
        }),
        other => Err(anyhow!("last: expected a list, got {:?}", other)),
    }
}

pub fn skip(value: RuleValue, n: usize) -> Result<RuleValue> {
    match value {
        RuleValue::List(mut v) => {
            if n < v.len() {
                Ok(RuleValue::List(v.split_off(n)))
            } else {
                Ok(RuleValue::List(vec![]))
            }
        }
        other => Err(anyhow!("skip: expected a list, got {:?}", other)),
    }
}

pub fn nth(value: RuleValue, n: usize) -> Result<RuleValue> {
    match value {
        RuleValue::List(v) => Ok(v.get(n).cloned().unwrap_or(RuleValue::Null)),
        other => Err(anyhow!("nth: expected a list, got {:?}", other)),
    }
}

pub fn count(value: &RuleValue) -> RuleValue {
    match value {
        RuleValue::List(v) => RuleValue::Int(v.len() as i64),
        RuleValue::Null => RuleValue::Int(0),
        _ => RuleValue::Int(1),
    }
}

pub fn sort(value: RuleValue) -> Result<RuleValue> {
    match value {
        RuleValue::List(mut v) => {
            v.sort_by_key(RuleValue::display);
            Ok(RuleValue::List(v))
        }
        other => Err(anyhow!("sort: expected a list, got {:?}", other)),
    }
}

pub fn unique(value: RuleValue) -> Result<RuleValue> {
    match value {
        RuleValue::List(mut v) => {
            v.sort_by_key(RuleValue::display);
            v.dedup();
            Ok(RuleValue::List(v))
        }
        other => Err(anyhow!("unique: expected a list, got {:?}", other)),
    }
}

pub fn join(value: RuleValue, sep: &str) -> Result<RuleValue> {
    match value {
        RuleValue::List(v) => Ok(RuleValue::Str(
            v.iter()
                .map(RuleValue::display)
                .collect::<Vec<_>>()
                .join(sep),
        )),
        RuleValue::Str(s) => Ok(RuleValue::Str(s)),
        other => Err(anyhow!("join: expected a list, got {:?}", other)),
    }
}

/// Group list items by whitespace-field `n`, returning `"count key"` strings
/// sorted alphabetically by key.
pub fn group_count(value: RuleValue, n: usize) -> Result<RuleValue> {
    match value {
        RuleValue::List(v) => {
            let mut counts: HashMap<String, i64> = HashMap::new();
            for item in &v {
                let key = match item {
                    RuleValue::Str(s) => s.split_whitespace().nth(n).unwrap_or("").to_string(),
                    _ => String::new(),
                };
                *counts.entry(key).or_default() += 1;
            }
            let mut pairs: Vec<_> = counts.into_iter().collect();
            pairs.sort_by(|a, b| a.0.cmp(&b.0));
            Ok(RuleValue::List(
                pairs
                    .into_iter()
                    .map(|(key, cnt)| RuleValue::Str(format!("{cnt} {key}")))
                    .collect(),
            ))
        }
        other => Err(anyhow!("group_count: expected a list, got {:?}", other)),
    }
}

/// Keep only items whose first whitespace-field (parsed as integer) exceeds
/// `threshold`.  Designed to follow `group_count`.
pub fn where_gt(value: RuleValue, threshold: i64) -> Result<RuleValue> {
    match value {
        RuleValue::List(v) => Ok(RuleValue::List(
            v.into_iter()
                .filter(|item| match item {
                    RuleValue::Str(s) => s
                        .split_whitespace()
                        .next()
                        .and_then(|n| n.parse::<i64>().ok())
                        .is_some_and(|n| n > threshold),
                    _ => false,
                })
                .collect(),
        )),
        other => Err(anyhow!("where_gt: expected a list, got {:?}", other)),
    }
}

/// Set intersection: keep only items whose display form appears in `other`.
pub fn intersect(value: RuleValue, other: &[String]) -> Result<RuleValue> {
    match value {
        RuleValue::List(v) => {
            let set: HashSet<&str> = other.iter().map(String::as_str).collect();
            Ok(RuleValue::List(
                v.into_iter()
                    .filter(|item| set.contains(item.display().as_str()))
                    .collect(),
            ))
        }
        other_val => Err(anyhow!("intersect: expected a list, got {:?}", other_val)),
    }
}

/// Set subtraction: remove items whose display form appears in `other`.
pub fn reject_in(value: RuleValue, other: &[String]) -> Result<RuleValue> {
    match value {
        RuleValue::List(v) => {
            let set: HashSet<&str> = other.iter().map(String::as_str).collect();
            Ok(RuleValue::List(
                v.into_iter()
                    .filter(|item| !set.contains(item.display().as_str()))
                    .collect(),
            ))
        }
        other_val => Err(anyhow!("reject_in: expected a list, got {:?}", other_val)),
    }
}

/// Keep only list items (or the string itself) that match `pattern`.
///
/// Applied to a `Str`, returns a single-item list when the string matches,
/// or an empty list when it does not.
pub fn grep(value: RuleValue, pattern: &str) -> Result<RuleValue> {
    let re =
        Regex::new(pattern).map_err(|e| anyhow!("grep: invalid regex {:?}: {}", pattern, e))?;
    match value {
        RuleValue::List(v) => Ok(RuleValue::List(
            v.into_iter()
                .filter(|item| re.is_match(&item.display()))
                .collect(),
        )),
        RuleValue::Str(s) => Ok(RuleValue::List(if re.is_match(&s) {
            vec![RuleValue::Str(s)]
        } else {
            vec![]
        })),
        other => Err(anyhow!("grep: expected a list or string, got {:?}", other)),
    }
}

/// Remove list items (or the string itself) that match `pattern`.
///
/// Applied to a `Str`, returns an empty list when the string matches,
/// or a single-item list when it does not.
pub fn reject_grep(value: RuleValue, pattern: &str) -> Result<RuleValue> {
    let re = Regex::new(pattern)
        .map_err(|e| anyhow!("reject_grep: invalid regex {:?}: {}", pattern, e))?;
    match value {
        RuleValue::List(v) => Ok(RuleValue::List(
            v.into_iter()
                .filter(|item| !re.is_match(&item.display()))
                .collect(),
        )),
        RuleValue::Str(s) => Ok(RuleValue::List(if re.is_match(&s) {
            vec![]
        } else {
            vec![RuleValue::Str(s)]
        })),
        other => Err(anyhow!(
            "reject_grep: expected a list or string, got {:?}",
            other
        )),
    }
}

/// Detect configuration-key conflicts across files from `grep -rH` output.
///
/// Each input item is expected in the form `<file>:<key> = <value>` (as emitted
/// by `grep -rH`).  Comment lines (content starting with `#` or `;`) are
/// ignored.  Returns one `"<key>: <fileA>=<valA>, <fileB>=<valB>"` string per
/// key that is assigned at least two *different* values, sorted by key.
pub fn conflicts(value: RuleValue) -> Result<RuleValue> {
    match value {
        RuleValue::List(v) => {
            let mut seen: HashMap<String, Vec<(String, String)>> = HashMap::new();
            for item in &v {
                let line = item.display();
                let Some((file, rest)) = line.split_once(':') else {
                    continue;
                };
                let content = rest.trim();
                if content.is_empty() || content.starts_with('#') || content.starts_with(';') {
                    continue;
                }
                if let Some((key, val)) = content.split_once('=') {
                    seen.entry(key.trim().to_string())
                        .or_default()
                        .push((file.trim().to_string(), val.trim().to_string()));
                }
            }
            let mut keys: Vec<&String> = seen.keys().collect();
            keys.sort();
            let mut out = Vec::new();
            for key in keys {
                let occ = &seen[key];
                if occ.len() < 2 {
                    continue;
                }
                let first = &occ[0].1;
                if occ.iter().any(|(_, v)| v != first) {
                    let detail = occ
                        .iter()
                        .map(|(f, val)| format!("{f}={val}"))
                        .collect::<Vec<_>>()
                        .join(", ");
                    out.push(RuleValue::Str(format!("{key}: {detail}")));
                }
            }
            Ok(RuleValue::List(out))
        }
        other => Err(anyhow!("conflicts: expected a list, got {:?}", other)),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::testutil::{list, sv};

    #[test]
    fn non_empty_removes_null_and_empty_strings() {
        let input = RuleValue::List(vec![sv("a"), RuleValue::Null, sv(""), sv("b")]);
        assert_eq!(non_empty(input).unwrap(), list(&["a", "b"]));
    }

    #[test]
    fn non_empty_err_on_non_list() {
        assert!(non_empty(sv("x")).is_err());
    }

    #[test]
    fn first_returns_head() {
        assert_eq!(first(list(&["a", "b"])).unwrap(), sv("a"));
    }

    #[test]
    fn first_returns_null_on_empty_list() {
        assert_eq!(first(RuleValue::List(vec![])).unwrap(), RuleValue::Null);
    }

    #[test]
    fn first_err_on_non_list() {
        assert!(first(sv("x")).is_err());
    }

    #[test]
    fn skip_removes_n_elements() {
        assert_eq!(skip(list(&["a", "b", "c"]), 2).unwrap(), list(&["c"]));
    }

    #[test]
    fn skip_past_end_returns_empty() {
        assert_eq!(skip(list(&["a"]), 5).unwrap(), RuleValue::List(vec![]));
    }

    #[test]
    fn skip_err_on_non_list() {
        assert!(skip(sv("x"), 1).is_err());
    }

    #[test]
    fn nth_returns_element() {
        assert_eq!(nth(list(&["a", "b", "c"]), 1).unwrap(), sv("b"));
    }

    #[test]
    fn nth_out_of_bounds_returns_null() {
        assert_eq!(nth(list(&["a"]), 5).unwrap(), RuleValue::Null);
    }

    #[test]
    fn nth_err_on_non_list() {
        assert!(nth(sv("x"), 0).is_err());
    }

    #[test]
    fn count_list() {
        assert_eq!(count(&list(&["a", "b", "c"])), RuleValue::Int(3));
    }

    #[test]
    fn count_null() {
        assert_eq!(count(&RuleValue::Null), RuleValue::Int(0));
    }

    #[test]
    fn count_scalar() {
        assert_eq!(count(&sv("x")), RuleValue::Int(1));
    }

    #[test]
    fn sort_orders_alphabetically() {
        let sorted = sort(list(&["c", "a", "b"])).unwrap();
        assert_eq!(sorted, list(&["a", "b", "c"]));
    }

    #[test]
    fn sort_err_on_non_list() {
        assert!(sort(sv("x")).is_err());
    }

    #[test]
    fn unique_deduplicates() {
        let u = unique(list(&["b", "a", "b", "a"])).unwrap();
        assert_eq!(u, list(&["a", "b"]));
    }

    #[test]
    fn unique_err_on_non_list() {
        assert!(unique(sv("x")).is_err());
    }

    #[test]
    fn join_list_with_separator() {
        assert_eq!(join(list(&["a", "b", "c"]), ", ").unwrap(), sv("a, b, c"));
    }

    #[test]
    fn join_str_passthrough() {
        assert_eq!(join(sv("hello"), ",").unwrap(), sv("hello"));
    }

    #[test]
    fn join_err_on_non_list_non_str() {
        assert!(join(RuleValue::Int(1), ",").is_err());
    }

    #[test]
    fn last_returns_last_element() {
        assert_eq!(last(list(&["a", "b", "c"])).unwrap(), sv("c"));
    }

    #[test]
    fn last_empty_list_returns_null() {
        assert_eq!(last(RuleValue::List(vec![])).unwrap(), RuleValue::Null);
    }

    #[test]
    fn last_err_on_non_list() {
        assert!(last(sv("x")).is_err());
    }

    #[test]
    fn group_count_groups_by_field() {
        let input = list(&[
            "firefox 101 rev1",
            "firefox 101 rev2",
            "firefox 101 rev3",
            "chromium 100 rev1",
        ]);
        let result = group_count(input, 0).unwrap();
        assert_eq!(result, list(&["1 chromium", "3 firefox"]));
    }

    #[test]
    fn group_count_single_entry_per_key() {
        let input = list(&["a x", "b y", "c z"]);
        let result = group_count(input, 0).unwrap();
        assert_eq!(result, list(&["1 a", "1 b", "1 c"]));
    }

    #[test]
    fn group_count_err_on_non_list() {
        assert!(group_count(sv("x"), 0).is_err());
    }

    #[test]
    fn where_gt_filters_by_first_field() {
        let input = list(&["3 firefox", "1 chromium", "2 vscode"]);
        let result = where_gt(input, 2).unwrap();
        assert_eq!(result, list(&["3 firefox"]));
    }

    #[test]
    fn where_gt_returns_empty_when_none_exceed() {
        let input = list(&["1 a", "2 b"]);
        let result = where_gt(input, 5).unwrap();
        assert_eq!(result, RuleValue::List(vec![]));
    }

    #[test]
    fn where_gt_err_on_non_list() {
        assert!(where_gt(sv("x"), 1).is_err());
    }

    #[test]
    fn intersect_keeps_common_items() {
        let input = list(&["firefox", "chromium", "vscode"]);
        let other = vec![
            "chromium".to_string(),
            "vscode".to_string(),
            "vim".to_string(),
        ];
        let result = intersect(input, &other).unwrap();
        assert_eq!(result, list(&["chromium", "vscode"]));
    }

    #[test]
    fn intersect_returns_empty_when_no_overlap() {
        let input = list(&["a", "b"]);
        let other = vec!["c".to_string(), "d".to_string()];
        let result = intersect(input, &other).unwrap();
        assert_eq!(result, RuleValue::List(vec![]));
    }

    #[test]
    fn intersect_err_on_non_list() {
        assert!(intersect(sv("x"), &["y".to_string()]).is_err());
    }

    #[test]
    fn reject_in_removes_matching_items() {
        let input = list(&["firefox", "chromium", "vscode"]);
        let other = vec!["chromium".to_string(), "vim".to_string()];
        let result = reject_in(input, &other).unwrap();
        assert_eq!(result, list(&["firefox", "vscode"]));
    }

    #[test]
    fn reject_in_err_on_non_list() {
        assert!(reject_in(sv("x"), &["y".to_string()]).is_err());
    }

    #[test]
    fn grep_keeps_matching_items() {
        let input = list(&["error: disk full", "info: all good", "warn: memory high"]);
        let result = grep(input, "(?i)(error|warn)").unwrap();
        assert_eq!(result, list(&["error: disk full", "warn: memory high"]));
    }

    #[test]
    fn grep_on_string_returns_list() {
        assert_eq!(
            grep(sv("error: bad"), "error").unwrap(),
            list(&["error: bad"])
        );
        assert_eq!(
            grep(sv("info: ok"), "error").unwrap(),
            RuleValue::List(vec![])
        );
    }

    #[test]
    fn grep_invalid_pattern_errors() {
        assert!(grep(list(&["x"]), "[invalid").is_err());
    }

    #[test]
    fn reject_grep_removes_matching_items() {
        let input = list(&["error: disk full", "info: all good", "warn: memory high"]);
        let result = reject_grep(input, "(?i)(error|warn)").unwrap();
        assert_eq!(result, list(&["info: all good"]));
    }

    #[test]
    fn reject_grep_on_string_returns_list() {
        assert_eq!(
            reject_grep(sv("info: ok"), "error").unwrap(),
            list(&["info: ok"])
        );
        assert_eq!(
            reject_grep(sv("error: bad"), "error").unwrap(),
            RuleValue::List(vec![])
        );
    }

    #[test]
    fn reject_grep_invalid_pattern_errors() {
        assert!(reject_grep(list(&["x"]), "[invalid").is_err());
    }

    #[test]
    fn conflicts_detects_differing_values() {
        let input = list(&[
            "/etc/sysctl.d/a.conf:net.ipv4.ip_forward = 0",
            "/etc/sysctl.d/b.conf:net.ipv4.ip_forward = 1",
        ]);
        let result = conflicts(input).unwrap();
        assert_eq!(
            result,
            list(&["net.ipv4.ip_forward: /etc/sysctl.d/a.conf=0, /etc/sysctl.d/b.conf=1"])
        );
    }

    #[test]
    fn conflicts_ignores_same_value_and_singletons() {
        let input = list(&[
            "/etc/sysctl.d/a.conf:vm.swappiness = 10",
            "/etc/sysctl.d/b.conf:vm.swappiness = 10",
            "/etc/sysctl.d/c.conf:kernel.panic = 5",
        ]);
        assert_eq!(conflicts(input).unwrap(), RuleValue::List(vec![]));
    }

    #[test]
    fn conflicts_skips_comments_and_malformed_lines() {
        let input = list(&[
            "/etc/sysctl.d/a.conf:# net.ipv4.ip_forward = 0",
            "/etc/sysctl.d/a.conf:; commented",
            "no-colon-line",
            "/etc/sysctl.d/a.conf:no-equals-here",
        ]);
        assert_eq!(conflicts(input).unwrap(), RuleValue::List(vec![]));
    }

    #[test]
    fn conflicts_err_on_non_list() {
        assert!(conflicts(sv("x")).is_err());
    }
}
