//! Structured-data (YAML) serialisation facade.
//!
//! Import from this module rather than from any specific YAML library so that
//! the underlying implementation can be swapped without touching callers.

use serde::{Serialize, de::DeserializeOwned};

/// Error type returned when YAML parsing or serialisation fails.
pub type Error = serde_yaml_ng::Error;

/// Parse a YAML string into a value of type `T`.
///
/// # Errors
/// Returns an error if the YAML is malformed or its structure does not match `T`.
pub fn parse<T: DeserializeOwned>(s: &str) -> Result<T, Error> {
    serde_yaml_ng::from_str(s)
}

/// Serialise a value of type `T` to a YAML string.
///
/// # Errors
/// Returns an error if `T` cannot be represented as YAML.
pub fn serialize<T: Serialize>(v: &T) -> Result<String, Error> {
    serde_yaml_ng::to_string(v)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn parse_simple_map() {
        let m: BTreeMap<String, i64> = parse("a: 1\nb: 2").unwrap();
        assert_eq!(m["a"], 1);
        assert_eq!(m["b"], 2);
    }

    #[test]
    fn parse_returns_error_on_invalid_yaml() {
        let result = parse::<BTreeMap<String, i64>>("not: valid: yaml: :");
        assert!(result.is_err());
    }

    #[test]
    fn serialize_integer() {
        let s = serialize(&42i64).unwrap();
        assert_eq!(s.trim(), "42");
    }

    #[test]
    fn serialize_map() {
        let mut m = BTreeMap::new();
        m.insert("key", "value");
        let s = serialize(&m).unwrap();
        assert!(s.contains("key"));
        assert!(s.contains("value"));
    }
}
