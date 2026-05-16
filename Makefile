.PHONY: all setup fmt fmt-check lint test audit coverage coverage-ci metrics check doc-dependencies

# Configuration for quality gates
COVERAGE_MIN_THRESHOLD ?= 95
METRIC_MAX_COMPLEXITY  ?= 15
METRIC_MAX_LENGTH      ?= 60

all: check

## Install required Cargo tools and pre-build the metrics analyser (run once)
setup:
	rustup component add llvm-tools-preview clippy rustfmt
	cargo install cargo-audit
	cargo install cargo-llvm-cov
	python3 --version
	cargo build --manifest-path tools/hah-metrics/Cargo.toml --release

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

lint:
	cargo clippy --all-targets -- -D warnings

test:
	cargo test --all

audit:
	cargo audit

coverage:
	cargo llvm-cov --all-targets --workspace --html

coverage-ci:
	cargo llvm-cov --all-targets --workspace --fail-under-lines $(COVERAGE_MIN_THRESHOLD)

metrics:
	cargo run --manifest-path tools/hah-metrics/Cargo.toml --release --quiet -- \
		--max-complexity $(METRIC_MAX_COMPLEXITY) \
		--max-length $(METRIC_MAX_LENGTH)

doc-dependencies:
	python3 tools/gen_deps_doc.py > DEPENDENCIES.md

check: fmt-check lint test audit coverage-ci metrics

