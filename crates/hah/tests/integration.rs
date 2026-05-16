//! Integration tests that exercise the `hah` binary through `std::process::Command`.
//! These cover `main()` itself and verify end-to-end CLI behaviour.
#![allow(clippy::expect_used)]

use std::process::Command;

fn hah() -> Command {
    Command::new(env!("CARGO_BIN_EXE_hah"))
}

#[test]
fn list_checks_exits_0() {
    let status = hah()
        .arg("list-checks")
        .status()
        .expect("failed to run hah");
    assert_eq!(status.code(), Some(0));
}

#[test]
fn list_checks_prints_check_ids() {
    let output = hah()
        .arg("list-checks")
        .output()
        .expect("failed to run hah");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("boot-space"),
        "expected 'boot-space' in list-checks output"
    );
}

#[test]
fn scan_nonexistent_check_exits_0() {
    let status = hah()
        .args(["scan", "--check", "__nonexistent__"])
        .status()
        .expect("failed to run hah");
    assert_eq!(status.code(), Some(0));
}

#[test]
fn scan_json_output_is_valid_json() {
    let output = hah()
        .args(["scan", "--check", "__nonexistent__", "--output", "json"])
        .output()
        .expect("failed to run hah");
    assert_eq!(output.status.code(), Some(0));
    // Either an empty JSON array or object — just verify it's not an error body
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    assert!(
        stdout.starts_with('[') || stdout.starts_with('{') || stdout.is_empty(),
        "expected JSON output, got: {stdout}"
    );
}

#[test]
fn scan_yaml_output_exits_cleanly() {
    let status = hah()
        .args(["scan", "--check", "__nonexistent__", "--output", "yaml"])
        .status()
        .expect("failed to run hah");
    assert_eq!(status.code(), Some(0));
}

#[test]
fn scan_dry_run_flag_exits_cleanly() {
    let status = hah()
        .args(["scan", "--check", "__nonexistent__", "--dry-run"])
        .status()
        .expect("failed to run hah");
    assert_eq!(status.code(), Some(0));
}

#[test]
fn invalid_subcommand_exits_nonzero() {
    let status = hah()
        .arg("not-a-real-subcommand")
        .status()
        .expect("failed to run hah");
    assert_ne!(status.code(), Some(0));
}
