# User Guide

HaH is a diagnostic tool for Linux systems. It scans your system for common maintenance issues and provides information on why they might be problematic and how to address them.

## Installation

HaH is currently in development. You can build it from source using Rust:

```bash
cargo build --release
```

The binary will be available at `target/release/hah`.

## Basic Usage

Run a full system scan:

```bash
hah scan
```

Scan for specific issues:

```bash
hah scan --check boot-space
```

List all available checks:

```bash
hah list
```

## Controlling what runs

Checks gather data by running read-only system commands (for example `find`,
`dpkg-query`, `journalctl`). Only programs on the **command allowlist** are
permitted; any check needing a command that is not allowlisted is reported as
`SKIPPED`. See the [Configuration Guide](../config.md) to customise the
allowlist.

Preview exactly which commands each check would run, without executing anything:

```bash
hah scan --dry-run
```

Approve each non-allowlisted command interactively before it runs:

```bash
hah scan --ask
```

## Remediation

When HaH finds an issue, it provides a "Remediation" section. This contains suggestions on how to fix the problem.

**Important:** HaH only detects issues. It is up to you to evaluate the suggestions and decide whether to execute any commands or make changes to your system. HaH will never modify your system automatically.

## Configuration

See the [Configuration Guide](../config.md) for details on how to customize thresholds and filter results.
