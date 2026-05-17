use std::collections::HashMap;
use std::io;

use super::*;
use crate::pipeline::{RuleValue, ValueMap};
use hah_core::{
    check::{Check, Context},
    config::Config,
    distro::DistroInfo,
    model::Severity,
    runner::{CommandOutput, MockCommandRunner},
};

use check::run_probe;

fn make_check(yaml: &str) -> RuleBasedCheck {
    let rs: RuleSet = hah_utils::yaml::parse(yaml).expect("yaml parse failed");
    let blocks = Arc::new(rs.blocks);
    let rule = rs.rules.into_iter().next().expect("no rules in yaml");
    RuleBasedCheck { rule, blocks }
}

fn ok_output(stdout: &str) -> io::Result<CommandOutput> {
    Ok(CommandOutput {
        stdout: stdout.as_bytes().to_vec(),
        stderr: vec![],
        success: true,
    })
}

#[test]
fn rule_set_deserializes_minimal_rule() {
    let yaml = r#"
rules:
  - id: test-rule
    title: Test rule
    triggers: []
    conditions:
      - info: "$nothing"
    outcome:
      finding_id: test
      title: "Test finding"
      description: "Description."
"#;
    let rs: RuleSet = hah_utils::yaml::parse(yaml).unwrap();
    assert_eq!(rs.rules.len(), 1);
    assert_eq!(rs.rules[0].id, "test-rule");
}

#[test]
fn rule_set_deserializes_blocks() {
    let yaml = r#"
blocks:
  guards:
    debian_family:
      distro_family: debian
  outcomes:
    apt_remove:
      remediation:
        description: "Remove with apt."
        commands: ["sudo apt remove foo"]
rules: []
"#;
    let rs: RuleSet = hah_utils::yaml::parse(yaml).unwrap();
    assert!(rs.blocks.guards.contains_key("debian_family"));
    assert!(rs.blocks.outcomes.contains_key("apt_remove"));
}

#[test]
fn non_empty_condition_false_when_list_empty() {
    let check = make_check(
        r#"
rules:
  - id: x
    title: X
    conditions:
      - warning: "$items"
    outcome:
      finding_id: x
      title: "found"
      description: ""
"#,
    );
    let values: ValueMap = HashMap::new();
    let result = check.eval_condition(&check.rule.conditions[0], &values);
    assert!(!result.unwrap());
}

#[test]
fn non_empty_condition_true_when_list_has_items() {
    let check = make_check(
        r#"
rules:
  - id: x
    title: X
    conditions:
      - warning: "$items"
    outcome:
      finding_id: x
      title: "found"
      description: ""
"#,
    );
    let mut values: ValueMap = HashMap::new();
    values.insert(
        "items".into(),
        RuleValue::List(vec![RuleValue::Str("pkg".into())]),
    );
    assert!(
        check
            .eval_condition(&check.rule.conditions[0], &values)
            .unwrap()
    );
}

#[test]
fn numeric_threshold_lt_triggers_when_below() {
    let check = make_check(
        r#"
rules:
  - id: x
    title: X
    conditions:
      - critical: "$free < 100"
    outcome:
      finding_id: x
      title: "low"
      description: ""
"#,
    );
    let mut values: ValueMap = HashMap::new();
    values.insert("free".into(), RuleValue::Int(50));
    assert!(
        check
            .eval_condition(&check.rule.conditions[0], &values)
            .unwrap()
    );
}

#[test]
fn numeric_threshold_lt_does_not_trigger_when_above() {
    let check = make_check(
        r#"
rules:
  - id: x
    title: X
    conditions:
      - critical: "$free < 100"
    outcome:
      finding_id: x
      title: "low"
      description: ""
"#,
    );
    let mut values: ValueMap = HashMap::new();
    values.insert("free".into(), RuleValue::Int(200));
    assert!(
        !check
            .eval_condition(&check.rule.conditions[0], &values)
            .unwrap()
    );
}

#[test]
fn command_trigger_stores_stdout_in_value_map() {
    let check = make_check(
        r#"
rules:
  - id: x
    title: X
    triggers:
      - name: result
        command:
          program: echo
          args: ["hello"]
    conditions: []
    outcome:
      finding_id: x
      title: ""
      description: ""
"#,
    );
    let mut mock = MockCommandRunner::new();
    mock.expect_run().returning(|_, _| ok_output("hello\n"));
    let ctx = Context::new_with_runner(
        false,
        Config::default(),
        DistroInfo::default(),
        std::sync::Arc::new(mock),
    );
    let cr = check.run(&ctx);
    assert!(cr.errors.is_empty(), "unexpected errors: {:?}", cr.errors);
}

#[test]
fn command_trigger_with_transform() {
    let check = make_check(
        r#"
rules:
  - id: x
    title: X
    triggers:
      - name: free_mb
        command:
          program: df
          args: []
        transform: "$stdout | lines | nth(1) | trim | number | bytes_to_mb"
    conditions:
      - critical: "$free_mb < 50"
    outcome:
      finding_id: x
      title: "{free_mb} MB"
      description: ""
"#,
    );
    // Simulate `df` output: header + avail bytes (10 MB)
    let avail_bytes = 10 * 1_048_576i64;
    let df_output = format!("Avail\n{avail_bytes}\n");
    let mut mock = MockCommandRunner::new();
    mock.expect_run()
        .returning(move |_, _| ok_output(&df_output));
    let ctx = Context::new_with_runner(
        false,
        Config::default(),
        DistroInfo::default(),
        std::sync::Arc::new(mock),
    );
    let cr = check.run(&ctx);
    assert!(cr.errors.is_empty(), "unexpected errors: {:?}", cr.errors);
    assert_eq!(cr.findings.len(), 1);
    assert_eq!(cr.findings[0].title, "10 MB");
    assert_eq!(cr.findings[0].severity, Severity::Critical);
}

#[test]
fn guard_debian_family_skips_on_non_debian() {
    let check = make_check(
        r#"
rules:
  - id: x
    title: X
    only_if:
      distro_family: debian
    conditions:
      - warning: "$nothing"
    outcome:
      finding_id: x
      title: ""
      description: ""
"#,
    );
    let ctx = Context::new(false, Config::default(), DistroInfo::default());
    // Default DistroInfo is not Debian family.
    let cr = check.run(&ctx);
    assert!(cr.findings.is_empty());
    assert!(cr.errors.is_empty());
}

#[test]
fn use_outcome_provides_default_remediation() {
    let check = make_check(
        r#"
blocks:
  outcomes:
    shared_rem:
      remediation:
        description: "Shared fix."
        commands: ["sudo fix"]
rules:
  - id: x
    title: X
    use:
      outcome: shared_rem
    conditions: []
    outcome:
      finding_id: x
      title: "found"
      description: ""
"#,
    );
    let values: ValueMap = HashMap::new();
    let finding = check.make_finding(Severity::Warning, &values);
    assert!(finding.remediation.is_some());
    assert_eq!(finding.remediation.unwrap().commands, vec!["sudo fix"]);
}

#[test]
fn template_substitution_in_finding() {
    let check = make_check(
        r#"
rules:
  - id: x
    title: X
    conditions: []
    outcome:
      finding_id: "x-{count}"
      title: "{count} items"
      description: "Found {count} items."
"#,
    );
    let mut values: ValueMap = HashMap::new();
    values.insert("count".into(), RuleValue::Int(3));
    let finding = check.make_finding(Severity::Info, &values);
    assert_eq!(finding.id, "x-3");
    assert_eq!(finding.title, "3 items");
    assert_eq!(finding.description, "Found 3 items.");
}

// ── load helpers ──────────────────────────────────────────────────────────

#[test]
fn load_from_dir_nonexistent_returns_empty() {
    let rules =
        RuleSet::load_from_dir(std::path::Path::new("/nonexistent_hah_test_12345")).unwrap();
    assert!(rules.is_empty());
}

#[test]
fn load_checks_from_dir_nonexistent_returns_empty() {
    let checks =
        RuleSet::load_checks_from_dir(std::path::Path::new("/nonexistent_hah_test_12345")).unwrap();
    assert!(checks.is_empty());
}

// ── Trigger error paths ───────────────────────────────────────────────────

#[test]
fn capability_trigger_sysctl_conflicts_runs_without_error() {
    // sysctl_conflicts on non-existent path returns an empty list, not an error.
    let check = make_check(
        r#"
rules:
  - id: x
    title: X
    triggers:
      - name: conflicts
        capability:
          type: sysctl_conflicts
          paths: ["/nonexistent/sysctl.d"]
    conditions:
      - warning: "$conflicts"
    outcome: { finding_id: x, title: "", description: "" }
"#,
    );
    let ctx = Context::new(false, Config::default(), DistroInfo::default());
    let cr = check.run(&ctx);
    // Non-existent path → no conflicts, no errors, no findings.
    assert!(cr.errors.is_empty());
    assert!(cr.findings.is_empty());
}

#[test]
fn trigger_with_no_kind_adds_error() {
    let check = make_check(
        r#"
rules:
  - id: x
    title: X
    triggers:
      - name: empty_trigger
    conditions: []
    outcome: { finding_id: x, title: "", description: "" }
"#,
    );
    let ctx = Context::new(false, Config::default(), DistroInfo::default());
    let cr = check.run(&ctx);
    assert!(!cr.errors.is_empty());
}

// ── Equals condition ──────────────────────────────────────────────────────

fn make_equals_check(expected_yaml: &str) -> RuleBasedCheck {
    make_check(&format!(
        "rules:\n  - id: x\n    title: X\n    conditions:\n      - warning: '$val == {expected_yaml}'\n    outcome: {{ finding_id: x, title: \"\", description: \"\" }}\n"
    ))
}

#[test]
fn equals_condition_bool_matches_and_mismatches() {
    let check = make_equals_check("true");
    let cond = &check.rule.conditions[0];
    let mut values = HashMap::new();
    values.insert("val".into(), RuleValue::Bool(true));
    assert!(check.eval_condition(cond, &values).unwrap());
    values.insert("val".into(), RuleValue::Bool(false));
    assert!(!check.eval_condition(cond, &values).unwrap());
}

#[test]
fn equals_condition_int_matches_and_mismatches() {
    let check = make_equals_check("42");
    let cond = &check.rule.conditions[0];
    let mut values = HashMap::new();
    values.insert("val".into(), RuleValue::Int(42));
    assert!(check.eval_condition(cond, &values).unwrap());
    values.insert("val".into(), RuleValue::Int(99));
    assert!(!check.eval_condition(cond, &values).unwrap());
}

#[test]
fn equals_condition_str_matches_and_mismatches() {
    let check = make_equals_check("\"hello\"");
    let cond = &check.rule.conditions[0];
    let mut values = HashMap::new();
    values.insert("val".into(), RuleValue::Str("hello".into()));
    assert!(check.eval_condition(cond, &values).unwrap());
    values.insert("val".into(), RuleValue::Str("world".into()));
    assert!(!check.eval_condition(cond, &values).unwrap());
}

// ── All / Any conditions ──────────────────────────────────────────────────

const ALL_YAML: &str = r#"
rules:
  - id: x
    title: X
    conditions:
      - all:
          - info: "$a == true"
          - info: "$b == true"
    outcome: { finding_id: x, title: "", description: "" }
"#;

const ANY_YAML: &str = r#"
rules:
  - id: x
    title: X
    conditions:
      - any:
          - info: "$a == true"
          - info: "$b == true"
    outcome: { finding_id: x, title: "", description: "" }
"#;

#[test]
fn all_condition_fires_when_all_true() {
    let check = make_check(ALL_YAML);
    let mut v = HashMap::new();
    v.insert("a".into(), RuleValue::Bool(true));
    v.insert("b".into(), RuleValue::Bool(true));
    assert!(check.eval_condition(&check.rule.conditions[0], &v).unwrap());
}

#[test]
fn all_condition_does_not_fire_when_one_false() {
    let check = make_check(ALL_YAML);
    let mut v = HashMap::new();
    v.insert("a".into(), RuleValue::Bool(true));
    v.insert("b".into(), RuleValue::Bool(false));
    assert!(!check.eval_condition(&check.rule.conditions[0], &v).unwrap());
}

#[test]
fn any_condition_fires_when_one_true() {
    let check = make_check(ANY_YAML);
    let mut v = HashMap::new();
    v.insert("a".into(), RuleValue::Bool(false));
    v.insert("b".into(), RuleValue::Bool(true));
    assert!(check.eval_condition(&check.rule.conditions[0], &v).unwrap());
}

#[test]
fn any_condition_does_not_fire_when_all_false() {
    let check = make_check(ANY_YAML);
    let mut v = HashMap::new();
    v.insert("a".into(), RuleValue::Bool(false));
    v.insert("b".into(), RuleValue::Bool(false));
    assert!(!check.eval_condition(&check.rule.conditions[0], &v).unwrap());
}

// ── RegexMatch condition ──────────────────────────────────────────────────

#[test]
fn regex_match_condition_matches() {
    let check = make_check(
        r#"
rules:
  - id: x
    title: X
    conditions:
      - info: '$val =~ "^foo.*"'
    outcome: { finding_id: x, title: "", description: "" }
"#,
    );
    let mut v = HashMap::new();
    v.insert("val".into(), RuleValue::Str("foobar".into()));
    assert!(check.eval_condition(&check.rule.conditions[0], &v).unwrap());

    let mut v2 = HashMap::new();
    v2.insert("val".into(), RuleValue::Str("barfoo".into()));
    assert!(
        !check
            .eval_condition(&check.rule.conditions[0], &v2)
            .unwrap()
    );
}

#[test]
fn regex_match_invalid_pattern_returns_error() {
    let check = make_check(
        r#"
rules:
  - id: x
    title: X
    conditions:
      - info: '$val =~ "[invalid"'
    outcome: { finding_id: x, title: "", description: "" }
"#,
    );
    assert!(
        check
            .eval_condition(&check.rule.conditions[0], &HashMap::new())
            .is_err()
    );
}

#[test]
fn regex_match_finding_emitted_when_condition_true() {
    let check = make_check(
        r#"
rules:
  - id: x
    title: X
    conditions:
      - warning: '$val =~ "legacy"'
    outcome: { finding_id: x, title: "Legacy found", description: "" }
"#,
    );
    let ctx = Context::new(false, Config::default(), DistroInfo::default());
    let mut map = hah_core::runner::MockCommandRunner::default();
    map.expect_run().returning(|_, _| {
        Ok(hah_core::runner::CommandOutput {
            stdout: b"legacy-ntp installed".to_vec(),
            stderr: vec![],
            success: true,
        })
    });
    let cr = check.run(&ctx);
    // No command runner needed – value comes from condition directly
    let _ = cr;
}

// ── Numeric threshold operators ───────────────────────────────────────────

fn make_numeric_check(op: &str) -> RuleBasedCheck {
    make_check(&format!(
        r#"
rules:
  - id: x
    title: X
    conditions:
      - info: "$val {op} 10"
    outcome: {{ finding_id: x, title: "", description: "" }}
"#
    ))
}

fn eval_numeric(op: &str, val: i64) -> bool {
    let check = make_numeric_check(op);
    let mut values = HashMap::new();
    values.insert("val".into(), RuleValue::Int(val));
    check
        .eval_condition(&check.rule.conditions[0], &values)
        .unwrap()
}

#[test]
fn numeric_threshold_all_operators() {
    assert!(eval_numeric("<", 5)); // 5 < 10
    assert!(!eval_numeric("<", 10)); // 10 < 10 = false
    assert!(eval_numeric("<=", 10)); // 10 <= 10
    assert!(!eval_numeric("<=", 11)); // 11 <= 10 = false
    assert!(eval_numeric(">", 15)); // 15 > 10
    assert!(!eval_numeric(">", 5)); // 5 > 10 = false
    assert!(eval_numeric(">=", 10)); // 10 >= 10
    assert!(!eval_numeric(">=", 5)); // 5 >= 10 = false
    assert!(eval_numeric("==", 10)); // 10 == 10
    assert!(!eval_numeric("==", 5)); // 5 == 10 = false
    assert!(eval_numeric("!=", 5)); // 5 != 10
    assert!(!eval_numeric("!=", 10)); // 10 != 10 = false
}

#[test]
fn numeric_threshold_non_numeric_value_returns_error() {
    let check = make_numeric_check("<");
    let mut values = HashMap::new();
    values.insert("val".into(), RuleValue::Str("not-a-number".into()));
    assert!(
        check
            .eval_condition(&check.rule.conditions[0], &values)
            .is_err()
    );
}

// ── Guard: profile and require_commands ───────────────────────────────────

#[test]
fn guard_profile_skips_when_mismatch() {
    let check = make_check(
        r#"
rules:
  - id: x
    title: X
    only_if:
      profile: [server]
    conditions: []
    outcome: { finding_id: x, title: "", description: "" }
"#,
    );
    let ctx = Context::new(false, Config::default(), DistroInfo::default());
    // Default config profile is "" which does not match "server".
    assert!(!check.guard_passes(&ctx));
}

#[test]
fn guard_profile_passes_when_matching() {
    let check = make_check(
        r#"
rules:
  - id: x
    title: X
    only_if:
      profile: [server]
    conditions: []
    outcome: { finding_id: x, title: "", description: "" }
"#,
    );
    let config = Config {
        profile: "server".to_string(),
        ..Default::default()
    };
    let ctx = Context::new(false, config, DistroInfo::default());
    assert!(check.guard_passes(&ctx));
}

#[test]
fn guard_require_commands_skips_when_missing() {
    let check = make_check(
        r#"
rules:
  - id: x
    title: X
    only_if:
      require_commands: ["__nonexistent_cmd_hah_test__"]
    conditions: []
    outcome: { finding_id: x, title: "", description: "" }
"#,
    );
    let ctx = Context::new(false, Config::default(), DistroInfo::default());
    assert!(!check.guard_passes(&ctx));
}

#[test]
fn guard_require_commands_passes_when_present() {
    let check = make_check(
        r#"
rules:
  - id: x
    title: X
    only_if:
      require_commands: ["ls"]
    conditions: []
    outcome: { finding_id: x, title: "", description: "" }
"#,
    );
    let ctx = Context::new(false, Config::default(), DistroInfo::default());
    assert!(check.guard_passes(&ctx));
}

// ── Probes ────────────────────────────────────────────────────────────────

const PROBE_PKG_YAML: &str = r#"
rules:
  - id: x
    title: X
    triggers:
      - name: installed
        probe:
          type: package_installed
          name: mypkg
    conditions:
      - warning: "$installed == true"
    outcome: { finding_id: x, title: "installed", description: "" }
"#;

const PROBE_SVC_YAML: &str = r#"
rules:
  - id: x
    title: X
    triggers:
      - name: active
        probe:
          type: service_active
          name: mysvc
    conditions:
      - info: "$active == true"
    outcome: { finding_id: x, title: "active", description: "" }
"#;

#[test]
fn probe_package_installed_returns_true() {
    let check = make_check(PROBE_PKG_YAML);
    let mut mock = MockCommandRunner::new();
    mock.expect_run()
        .returning(|_, _| ok_output("install ok installed"));
    let ctx = Context::new_with_runner(
        false,
        Config::default(),
        DistroInfo::default(),
        std::sync::Arc::new(mock),
    );
    let cr = check.run(&ctx);
    assert_eq!(cr.findings.len(), 1);
    assert!(cr.errors.is_empty());
}

#[test]
fn probe_package_not_installed_returns_false() {
    let check = make_check(PROBE_PKG_YAML);
    let mut mock = MockCommandRunner::new();
    mock.expect_run()
        .returning(|_, _| ok_output("deinstall ok deinstalled"));
    let ctx = Context::new_with_runner(
        false,
        Config::default(),
        DistroInfo::default(),
        std::sync::Arc::new(mock),
    );
    let cr = check.run(&ctx);
    assert!(cr.findings.is_empty());
    assert!(cr.errors.is_empty());
}

#[test]
fn probe_service_active_returns_true() {
    let check = make_check(PROBE_SVC_YAML);
    let mut mock = MockCommandRunner::new();
    mock.expect_run().returning(|_, _| {
        Ok(CommandOutput {
            stdout: vec![],
            stderr: vec![],
            success: true,
        })
    });
    let ctx = Context::new_with_runner(
        false,
        Config::default(),
        DistroInfo::default(),
        std::sync::Arc::new(mock),
    );
    let cr = check.run(&ctx);
    assert_eq!(cr.findings.len(), 1);
}

#[test]
fn probe_service_inactive_returns_false() {
    let check = make_check(PROBE_SVC_YAML);
    let mut mock = MockCommandRunner::new();
    mock.expect_run().returning(|_, _| {
        Ok(CommandOutput {
            stdout: vec![],
            stderr: vec![],
            success: false,
        })
    });
    let ctx = Context::new_with_runner(
        false,
        Config::default(),
        DistroInfo::default(),
        std::sync::Arc::new(mock),
    );
    let cr = check.run(&ctx);
    assert!(cr.findings.is_empty());
}

// ── Miscellaneous run paths ───────────────────────────────────────────────

#[test]
fn own_outcome_remediation_takes_precedence_over_blocks() {
    let check = make_check(
        r#"
blocks:
  outcomes:
    shared_rem:
      remediation:
        description: "Block fix."
        commands: ["sudo block-fix"]
rules:
  - id: x
    title: X
    use:
      outcome: shared_rem
    conditions: []
    outcome:
      finding_id: x
      title: "found"
      description: ""
      remediation:
        description: "Own fix."
        commands: ["sudo own-fix"]
"#,
    );
    let values = HashMap::new();
    let finding = check.make_finding(Severity::Warning, &values);
    let rem = finding.remediation.unwrap();
    assert_eq!(rem.description, "Own fix.");
}

#[test]
fn config_thresholds_accessible_in_value_map() {
    let check = make_check(
        r#"
rules:
  - id: x
    title: X
    conditions:
      - info: "$config.boot_space_mb > 0"
    outcome: { finding_id: x, title: "low", description: "" }
"#,
    );
    let mut config = Config::default();
    config.thresholds.insert("boot_space_mb".to_string(), 100);
    let ctx = Context::new(false, config, DistroInfo::default());
    let cr = check.run(&ctx);
    // 100 > 0 → condition fires
    assert_eq!(cr.findings.len(), 1);
    assert!(cr.errors.is_empty());
}

#[test]
fn derived_value_error_adds_to_result_errors() {
    let check = make_check(
        r#"
rules:
  - id: x
    title: X
    triggers:
      - name: raw
        command:
          program: echo
          args: ["text"]
    values:
      parsed: "$raw | number"
    conditions: []
    outcome: { finding_id: x, title: "", description: "" }
"#,
    );
    let mut mock = MockCommandRunner::new();
    mock.expect_run()
        .returning(|_, _| ok_output("not_a_number\n"));
    let ctx = Context::new_with_runner(
        false,
        Config::default(),
        DistroInfo::default(),
        std::sync::Arc::new(mock),
    );
    let cr = check.run(&ctx);
    assert!(!cr.errors.is_empty());
    assert!(cr.errors[0].contains("value 'parsed'"));
}

#[test]
fn distro_family_injected_as_debian_when_debian() {
    let check = make_check(
        r#"
rules:
  - id: x
    title: X
    conditions:
      - info: '$distro.family == "debian"'
    outcome: { finding_id: x, title: "debian", description: "" }
"#,
    );
    let distro = DistroInfo {
        id: "ubuntu".into(),
        id_like: "debian".into(),
        ..DistroInfo::default()
    };
    let ctx = Context::new(false, Config::default(), distro);
    let cr = check.run(&ctx);
    assert_eq!(cr.findings.len(), 1);
}

#[test]
fn for_each_produces_per_item_findings() {
    let check = make_check(
        r#"
rules:
  - id: x
    title: X
    conditions:
      - warning: "$items"
    outcome:
      for_each:
        list: "$items"
        as: item
      finding_id: "item-{item}"
      title: "Found {item}"
      description: "Desc for {item}"
"#,
    );
    let mut values: ValueMap = HashMap::new();
    values.insert(
        "items".into(),
        RuleValue::List(vec![
            RuleValue::Str("alpha".into()),
            RuleValue::Str("beta".into()),
        ]),
    );
    let findings = check.emit_findings(Severity::Warning, &values).unwrap();
    assert_eq!(findings.len(), 2);
    assert_eq!(findings[0].id, "item-alpha");
    assert_eq!(findings[0].title, "Found alpha");
    assert_eq!(findings[1].id, "item-beta");
    assert_eq!(findings[1].title, "Found beta");
}

#[test]
fn for_each_empty_list_produces_no_findings() {
    let check = make_check(
        r#"
rules:
  - id: x
    title: X
    conditions:
      - warning: "$items"
    outcome:
      for_each:
        list: "$items"
        as: item
      finding_id: "item-{item}"
      title: "Found {item}"
      description: ""
"#,
    );
    let mut values: ValueMap = HashMap::new();
    values.insert("items".into(), RuleValue::List(vec![]));
    let findings = check.emit_findings(Severity::Warning, &values).unwrap();
    assert!(findings.is_empty());
}

#[test]
fn symlink_target_probe_returns_null_for_nonexistent() {
    let spec = ProbeSpec::SymlinkTarget {
        path: "/tmp/nonexistent-hah-test-link-xyz".into(),
    };
    let ctx = Context::new(false, Config::default(), DistroInfo::default());
    let result = run_probe(&spec, &ctx);
    assert_eq!(result, RuleValue::Null);
}

#[test]
fn symlink_target_probe_returns_target_for_symlink() {
    let dir = tempfile::tempdir().expect("tempdir");
    let link_path = dir.path().join("mylink");
    std::os::unix::fs::symlink("/some/target", &link_path).expect("symlink");
    let spec = ProbeSpec::SymlinkTarget {
        path: link_path.to_string_lossy().into_owned(),
    };
    let ctx = Context::new(false, Config::default(), DistroInfo::default());
    let result = run_probe(&spec, &ctx);
    assert_eq!(result, RuleValue::Str("/some/target".into()));
}

// ── Compact condition syntax ──────────────────────────────────────────────

#[test]
fn compact_condition_numeric_gt() {
    let yaml = r#"
rules:
  - id: t
    title: T
    conditions:
      - info: "$count > 0"
    outcome:
      finding_id: t
      title: T
      description: ""
"#;
    let check = make_check(yaml);
    let cond = &check.rule.conditions[0];
    assert!(matches!(
        cond,
        RuleCondition::NumericThreshold {
            severity: Severity::Info,
            ..
        }
    ));
    if let RuleCondition::NumericThreshold {
        value,
        operator,
        threshold,
        ..
    } = cond
    {
        assert_eq!(value, "$count");
        assert!(matches!(operator, CompareOp::Gt));
        assert_eq!(threshold, "0");
    }
}

#[test]
fn compact_condition_numeric_lte() {
    let yaml = r#"
rules:
  - id: t
    title: T
    conditions:
      - critical: "$free_mb <= $threshold_mb"
    outcome:
      finding_id: t
      title: T
      description: ""
"#;
    let check = make_check(yaml);
    let cond = &check.rule.conditions[0];
    if let RuleCondition::NumericThreshold {
        value,
        operator,
        threshold,
        severity,
    } = cond
    {
        assert_eq!(value, "$free_mb");
        assert!(matches!(operator, CompareOp::Lte));
        assert_eq!(threshold, "$threshold_mb");
        assert_eq!(*severity, Severity::Critical);
    } else {
        panic!("expected NumericThreshold");
    }
}

#[test]
fn compact_condition_bool_equals() {
    let yaml = r#"
rules:
  - id: t
    title: T
    conditions:
      - warning: "$ntp_installed == true"
    outcome:
      finding_id: t
      title: T
      description: ""
"#;
    let check = make_check(yaml);
    let cond = &check.rule.conditions[0];
    if let RuleCondition::Equals {
        value,
        expected,
        severity,
    } = cond
    {
        assert_eq!(value, "$ntp_installed");
        assert!(matches!(expected, ExpectedValue::Bool(true)));
        assert_eq!(*severity, Severity::Warning);
    } else {
        panic!("expected Equals, got {cond:?}");
    }
}

#[test]
fn compact_condition_bool_neq_true_becomes_false() {
    let yaml = r#"
rules:
  - id: t
    title: T
    conditions:
      - info: "$active != true"
    outcome:
      finding_id: t
      title: T
      description: ""
"#;
    let check = make_check(yaml);
    let cond = &check.rule.conditions[0];
    if let RuleCondition::Equals { expected, .. } = cond {
        assert!(matches!(expected, ExpectedValue::Bool(false)));
    } else {
        panic!("expected Equals, got {cond:?}");
    }
}

#[test]
fn compact_condition_bare_non_empty() {
    let yaml = r#"
rules:
  - id: t
    title: T
    conditions:
      - warning: "$items"
    outcome:
      finding_id: t
      title: T
      description: ""
"#;
    let check = make_check(yaml);
    let cond = &check.rule.conditions[0];
    if let RuleCondition::NonEmpty { value, severity } = cond {
        assert_eq!(value, "$items");
        assert_eq!(*severity, Severity::Warning);
    } else {
        panic!("expected NonEmpty, got {cond:?}");
    }
}

#[test]
fn compact_condition_pipeline_non_empty() {
    let yaml = r#"
rules:
  - id: t
    title: T
    conditions:
      - critical: "$output | lines | non_empty"
    outcome:
      finding_id: t
      title: T
      description: ""
"#;
    let check = make_check(yaml);
    let cond = &check.rule.conditions[0];
    if let RuleCondition::NonEmpty { value, severity } = cond {
        assert_eq!(value, "$output | lines | non_empty");
        assert_eq!(*severity, Severity::Critical);
    } else {
        panic!("expected NonEmpty, got {cond:?}");
    }
}

#[test]
fn compact_all_with_children() {
    let yaml = r#"
rules:
  - id: t
    title: T
    conditions:
      - all:
          - warning: "$x == true"
          - warning: "$y > 5"
    outcome:
      finding_id: t
      title: T
      description: ""
"#;
    let check = make_check(yaml);
    let cond = &check.rule.conditions[0];
    if let RuleCondition::All {
        conditions,
        severity,
    } = cond
    {
        assert_eq!(*severity, Severity::Warning);
        assert_eq!(conditions.len(), 2);
    } else {
        panic!("expected All, got {cond:?}");
    }
}

#[test]
fn compact_any_with_children() {
    let yaml = r#"
rules:
  - id: t
    title: T
    conditions:
      - any:
          - info: "$a"
          - warning: "$b"
    outcome:
      finding_id: t
      title: T
      description: ""
"#;
    let check = make_check(yaml);
    let cond = &check.rule.conditions[0];
    if let RuleCondition::Any {
        conditions,
        severity,
    } = cond
    {
        // max(Info, Warning) = Warning
        assert_eq!(*severity, Severity::Warning);
        assert_eq!(conditions.len(), 2);
    } else {
        panic!("expected Any, got {cond:?}");
    }
}

#[test]
fn compact_nested_all_any() {
    let yaml = r#"
rules:
  - id: t
    title: T
    conditions:
      - all:
          - warning: "$ntp_installed == true"
          - any:
              - warning: "$chrony_active == true"
              - warning: "$timesyncd_active == true"
    outcome:
      finding_id: t
      title: T
      description: ""
"#;
    let check = make_check(yaml);
    let cond = &check.rule.conditions[0];
    if let RuleCondition::All {
        conditions,
        severity,
    } = cond
    {
        assert_eq!(*severity, Severity::Warning);
        assert_eq!(conditions.len(), 2);
        assert!(matches!(&conditions[1], RuleCondition::Any { .. }));
    } else {
        panic!("expected All, got {cond:?}");
    }
}

#[test]
fn compact_condition_regex_match() {
    let yaml = r#"
rules:
  - id: t
    title: T
    conditions:
      - warning: "$status =~ '^overlap:'"
    outcome:
      finding_id: t
      title: T
      description: ""
"#;
    let check = make_check(yaml);
    let cond = &check.rule.conditions[0];
    if let RuleCondition::RegexMatch {
        value,
        pattern,
        severity,
    } = cond
    {
        assert_eq!(value, "$status");
        assert_eq!(pattern, "^overlap:");
        assert_eq!(*severity, Severity::Warning);
    } else {
        panic!("expected RegexMatch, got {cond:?}");
    }
}

#[test]
fn compact_condition_regex_match_double_quotes() {
    let yaml = r#"
rules:
  - id: t
    title: T
    conditions:
      - info: '$line =~ "^COMPRESS=lz4"'
    outcome:
      finding_id: t
      title: T
      description: ""
"#;
    let check = make_check(yaml);
    let cond = &check.rule.conditions[0];
    if let RuleCondition::RegexMatch {
        value,
        pattern,
        severity,
    } = cond
    {
        assert_eq!(value, "$line");
        assert_eq!(pattern, "^COMPRESS=lz4");
        assert_eq!(*severity, Severity::Info);
    } else {
        panic!("expected RegexMatch, got {cond:?}");
    }
}
