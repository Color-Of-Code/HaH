use crate::pipeline::RuleValue;
use anyhow::{Result, anyhow};

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
}
