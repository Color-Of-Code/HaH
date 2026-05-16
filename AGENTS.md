# Agent Guidelines

## Validation Gate

Every change **must** pass the full quality gate before being considered done:

```bash
make check
```

This runs, in order:

| Step           | Command                                                          | Requirement             |
| -------------- | ---------------------------------------------------------------- | ----------------------- |
| Format check   | `cargo fmt --all -- --check`                                     | No formatting diffs     |
| Lint           | `cargo clippy --all-targets -- -D warnings`                      | Zero warnings           |
| Tests          | `cargo test --all`                                               | All tests green         |
| Security audit | `cargo audit`                                                    | No unpatched advisories |
| Coverage       | `cargo llvm-cov --all-targets --workspace --fail-under-lines 95` | ≥ 95 % line coverage    |

### One-time setup (if tools are missing)

```bash
make setup
```

## Workflow

1. Make your changes.
2. Run `make fmt` to auto-format before committing.
3. Run `make check` and fix every reported issue.
4. Do **not** submit or push until `make check` exits with code 0.

## Non-negotiable rules

- Never suppress a Clippy warning with `#[allow(...)]` unless it is inside a `#[cfg(test)]` block and the suppression is genuinely test-only (e.g. `clippy::unwrap_used`, `clippy::panic`).
- Never lower or remove the `--fail-under-lines 95` threshold.
- New public functions must have tests that exercise their main code paths.

## Relevant Instructions
- **[.copilot-instructions.md](.copilot-instructions.md)**: Contains detailed Rust coding patterns, project architecture overview, and error handling policies. Always refer to this for implementation details.
