pub mod caps_bridge;
pub mod expr;
pub mod filters;
pub mod parsers;
pub mod pipeline;
pub mod rule;

use std::path::Path;

use rule::RuleSet;

/// Validate a single YAML rule file.
///
/// Returns a list of human-readable error strings.  An empty vector means
/// the file is valid.
pub fn validate_rule_file(path: &Path) -> Vec<String> {
    let mut errors = Vec::new();
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            errors.push(format!("cannot read file: {e}"));
            return errors;
        }
    };
    let rule_set: RuleSet = match hah_utils::yaml::parse(&content) {
        Ok(rs) => rs,
        Err(e) => {
            errors.push(format!("YAML parse error: {e}"));
            return errors;
        }
    };
    // Check rule IDs are non-empty and unique within file.
    let mut seen = std::collections::HashSet::new();
    for rule in &rule_set.rules {
        if rule.id.is_empty() {
            errors.push("rule has empty id".into());
        } else if !seen.insert(&rule.id) {
            errors.push(format!("duplicate rule id: {}", rule.id));
        }
    }
    errors
}

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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn validate_valid_rule_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("good.yaml");
        std::fs::write(
            &path,
            r#"
rules:
  - id: test
    title: Test
    conditions:
      - info: "$x > 0"
    outcome:
      finding_id: test
      title: T
      description: D
"#,
        )
        .unwrap();
        assert!(validate_rule_file(&path).is_empty());
    }

    #[test]
    fn validate_invalid_yaml_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.yaml");
        std::fs::write(&path, "not: [valid: yaml: {{").unwrap();
        let errors = validate_rule_file(&path);
        assert!(!errors.is_empty());
        assert!(errors[0].contains("YAML parse error"));
    }

    #[test]
    fn validate_duplicate_id_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dup.yaml");
        std::fs::write(
            &path,
            r#"
rules:
  - id: same
    title: A
    conditions:
      - info: "$x > 0"
    outcome:
      finding_id: a
      title: A
      description: A
  - id: same
    title: B
    conditions:
      - info: "$y > 0"
    outcome:
      finding_id: b
      title: B
      description: B
"#,
        )
        .unwrap();
        let errors = validate_rule_file(&path);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("duplicate rule id: same"));
    }

    #[test]
    fn validate_nonexistent_file_returns_error() {
        let errors = validate_rule_file(Path::new("/nonexistent/xyz.yaml"));
        assert!(!errors.is_empty());
        assert!(errors[0].contains("cannot read file"));
    }

    #[test]
    fn validate_empty_id_returns_error() {
        let mut f = tempfile::NamedTempFile::with_suffix(".yaml").unwrap();
        writeln!(
            f,
            r#"
rules:
  - id: ""
    title: T
    conditions:
      - info: "$x > 0"
    outcome:
      finding_id: t
      title: T
      description: D
"#
        )
        .unwrap();
        let errors = validate_rule_file(f.path());
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("empty id"));
    }
}
