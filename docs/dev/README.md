# Developer Guide

Welcome to the HaH development documentation. This section covers the internals, project structure, and how to contribute to HaH.

## Project Structure

HaH is organized as a Cargo workspace:

- `hah`: The main CLI binary.
- `hah-core`: Core data models, traits, command runner, execution policy, and common functionality.
- `hah-dsl`: YAML rule engine and pipeline evaluator.
- `hah-utils`: Low-level shared utilities and library facades.

## Key Concepts

- **Checks**: Units of diagnostic logic that implement the `Check` trait.
- **Findings**: Results returned by checks, containing a severity and remediation suggestions.
- **Triggers**: How a rule gathers data — a `command`, a declarative `pipeline` of commands, a `file` read, or a built-in `probe`.
- **Command policy**: An allowlist of programs (regexes) enforced by `PolicyRunner`; non-allowlisted commands are skipped unless approved in `--ask` mode.

## Documentation Index

- [Architecture Overview](architecture.md)
- [DSL Language Reference](../dsl.md)
- [Utilities Library (hah-utils)](utils.md)
- [Project Plan](plan.md)

## Development Workflow

Refer to the [Agent Guidelines](../../AGENTS.md) for the full quality gate requirements (`make check`).
