# Developer Guide

Welcome to the HaH development documentation. This section covers the internals, project structure, and how to contribute to HaH.

## Project Structure

HaH is organized as a Cargo workspace:

- `hah`: The main CLI binary.
- `hah-core`: Core data models, traits, and common functionality.
- `hah-dsl`: YAML rule engine, pipeline evaluator, and capability functions.
- `hah-utils`: Low-level shared utilities and library facades.

## Key Concepts

- **Checks**: Units of diagnostic logic that implement the `Check` trait.
- **Findings**: Results returned by checks, containing a severity and remediation suggestions.
- **Capabilities**: (DSL only) Data sources (like `apt`, `files`, `sysctl`) that rules can query.

## Documentation Index

- [Architecture Overview](architecture.md)
- [DSL Language Reference](../dsl.md)
- [Utilities Library (hah-utils)](utils.md)
- [Project Plan](plan.md)
- [Roadmap](roadmap.md)

## Development Workflow

Refer to the [Agent Guidelines](../../AGENTS.md) for the full quality gate requirements (`make check`).
