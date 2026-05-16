.PHONY: all setup fmt fmt-check lint test audit check doc-dependencies

all: check

## Install required Cargo tools (run once)
setup:
	cargo install cargo-audit
	cargo install cargo-llvm-cov
	rustup component add llvm-tools-preview

## Auto-format all code
fmt:
	cargo fmt --all

## Check formatting without modifying files (used in CI)
fmt-check:
	cargo fmt --all -- --check

## Run Clippy; treat all warnings as errors
lint:
	cargo clippy --all-targets -- -D warnings

## Run all tests
test:
	cargo test --all

## Run security audit against RustSec advisory database
audit:
	cargo audit

## Generate HTML coverage report (opens in target/llvm-cov/html/)
coverage:
	cargo llvm-cov --all-targets --workspace --html

## Fail the build if line coverage drops below 95 %
coverage-ci:
	cargo llvm-cov --all-targets --workspace --fail-under-lines 95

## Full quality gate: format-check + lint + test + audit + coverage
check: fmt-check lint test audit coverage-ci

## Regenerate DEPENDENCIES.md from live cargo metadata
doc-dependencies:
	python3 tools/gen_deps_doc.py > DEPENDENCIES.md
