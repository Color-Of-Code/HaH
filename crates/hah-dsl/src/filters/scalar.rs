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

/// Parse a human-readable byte size such as `"600.0M"`, `"1.5G"`, `"512K"`, or a
/// plain number into an integer byte count.  A single trailing `.` (as printed
/// by `journalctl --disk-usage`) is tolerated.  Recognised suffixes are
/// K/M/G/T (case-insensitive), using 1024-based units.
pub fn to_bytes(value: RuleValue) -> Result<RuleValue> {
    let raw = match &value {
        RuleValue::Str(s) => s.trim().trim_end_matches('.').to_string(),
        RuleValue::Int(n) => return Ok(RuleValue::Int(*n)),
        _ => return Err(anyhow!("to_bytes requires a string, got {:?}", value)),
    };
    let (num_part, multiplier) = match raw.chars().last() {
        Some(c @ ('K' | 'k')) => (raw.trim_end_matches(c), 1024_f64),
        Some(c @ ('M' | 'm')) => (raw.trim_end_matches(c), 1024_f64 * 1024.0),
        Some(c @ ('G' | 'g')) => (raw.trim_end_matches(c), 1024_f64 * 1024.0 * 1024.0),
        Some(c @ ('T' | 't')) => (raw.trim_end_matches(c), 1024_f64 * 1024.0 * 1024.0 * 1024.0),
        _ => (raw.as_str(), 1.0),
    };
    let number: f64 = num_part
        .trim()
        .parse()
        .map_err(|_| anyhow!("to_bytes: not a size: {:?}", raw))?;
    Ok(RuleValue::Int((number * multiplier) as i64))
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

    #[test]
    fn to_bytes_parses_megabytes() {
        assert_eq!(
            to_bytes(RuleValue::Str("600.0M.".into())).unwrap(),
            RuleValue::Int((600.0 * 1024.0 * 1024.0) as i64)
        );
    }

    #[test]
    fn to_bytes_parses_gigabytes() {
        assert_eq!(
            to_bytes(RuleValue::Str("1.5G".into())).unwrap(),
            RuleValue::Int((1.5 * 1024.0 * 1024.0 * 1024.0) as i64)
        );
    }

    #[test]
    fn to_bytes_parses_kilo_and_tera() {
        assert_eq!(
            to_bytes(RuleValue::Str("512k".into())).unwrap(),
            RuleValue::Int(512 * 1024)
        );
        assert_eq!(
            to_bytes(RuleValue::Str("2T".into())).unwrap(),
            RuleValue::Int(2 * 1024 * 1024 * 1024 * 1024)
        );
    }

    #[test]
    fn to_bytes_plain_number() {
        assert_eq!(
            to_bytes(RuleValue::Str("1024".into())).unwrap(),
            RuleValue::Int(1024)
        );
    }

    #[test]
    fn to_bytes_int_passthrough() {
        assert_eq!(to_bytes(RuleValue::Int(42)).unwrap(), RuleValue::Int(42));
    }

    #[test]
    fn to_bytes_invalid_errors() {
        assert!(to_bytes(RuleValue::Str("nope".into())).is_err());
    }

    #[test]
    fn to_bytes_non_string_errors() {
        assert!(to_bytes(RuleValue::Bool(true)).is_err());
    }
}
