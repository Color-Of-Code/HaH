//! Structured-data (JSON) serialisation facade.
//!
//! Import from this module rather than from any specific JSON library so that
//! the underlying implementation can be swapped without touching callers.

use serde::Serialize;

/// Serialise `v` to a pretty-printed, human-readable JSON string.
///
/// Returns an empty string if serialisation fails (which should not happen
/// for standard `serde`-derived types).
pub fn serialize_pretty<T: Serialize>(v: &T) -> String {
    serde_json::to_string_pretty(v).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn serialize_pretty_formats_map() {
        let mut m = BTreeMap::new();
        m.insert("key", "value");
        let s = serialize_pretty(&m);
        assert!(s.contains("\"key\""));
        assert!(s.contains("\"value\""));
        // Pretty-printed output spans multiple lines
        assert!(s.contains('\n'));
    }

    #[test]
    fn serialize_pretty_integer() {
        let s = serialize_pretty(&42i64);
        assert_eq!(s.trim(), "42");
    }
}
