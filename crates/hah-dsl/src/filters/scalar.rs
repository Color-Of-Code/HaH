use crate::pipeline::RuleValue;
use anyhow::{Result, anyhow};

pub fn number(value: RuleValue) -> Result<RuleValue> {
    Ok(RuleValue::Int(value.try_int()?))
}

pub fn bytes_to_mb(value: RuleValue) -> Result<RuleValue> {
    let bytes = match &value {
        RuleValue::Int(_) | RuleValue::Str(_) => value.try_int()?,
        _ => return Err(anyhow!("bytes_to_mb requires a number, got {:?}", value)),
    };
    Ok(RuleValue::Int(bytes / (1024 * 1024)))
}

pub fn default_val(value: RuleValue, default: String) -> Result<RuleValue> {
    if value.is_blank() {
        Ok(RuleValue::Str(default))
    } else {
        Ok(value)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn number_from_int_passthrough() {
        assert_eq!(number(RuleValue::Int(5)).unwrap(), RuleValue::Int(5));
    }

    #[test]
    fn number_from_str() {
        assert_eq!(
            number(RuleValue::Str("  42  ".into())).unwrap(),
            RuleValue::Int(42)
        );
    }

    #[test]
    fn number_from_invalid_str_errors() {
        assert!(number(RuleValue::Str("abc".into())).is_err());
    }

    #[test]
    fn number_from_bool_errors() {
        assert!(number(RuleValue::Bool(true)).is_err());
    }

    #[test]
    fn bytes_to_mb_from_int() {
        assert_eq!(
            bytes_to_mb(RuleValue::Int(10 * 1024 * 1024)).unwrap(),
            RuleValue::Int(10)
        );
    }

    #[test]
    fn bytes_to_mb_from_str() {
        assert_eq!(
            bytes_to_mb(RuleValue::Str("2097152".into())).unwrap(),
            RuleValue::Int(2)
        );
    }

    #[test]
    fn bytes_to_mb_from_invalid_str_errors() {
        assert!(bytes_to_mb(RuleValue::Str("nope".into())).is_err());
    }

    #[test]
    fn bytes_to_mb_from_bool_errors() {
        assert!(bytes_to_mb(RuleValue::Bool(true)).is_err());
    }

    #[test]
    fn default_val_null_returns_default() {
        assert_eq!(
            default_val(RuleValue::Null, "fallback".into()).unwrap(),
            RuleValue::Str("fallback".into())
        );
    }

    #[test]
    fn default_val_empty_str_returns_default() {
        assert_eq!(
            default_val(RuleValue::Str(String::new()), "fallback".into()).unwrap(),
            RuleValue::Str("fallback".into())
        );
    }

    #[test]
    fn default_val_non_empty_passthrough() {
        assert_eq!(
            default_val(RuleValue::Str("value".into()), "fallback".into()).unwrap(),
            RuleValue::Str("value".into())
        );
    }
}
