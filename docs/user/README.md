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
hah list-checks
```

## Remediation

When HaH finds an issue, it provides a "Remediation" section. This contains suggestions on how to fix the problem.

**Important:** HaH only detects issues. It is up to you to evaluate the suggestions and decide whether to execute any commands or make changes to your system. HaH will never modify your system automatically.

## Configuration

See the [Configuration Guide](../config.md) for details on how to customize thresholds and filter results.
