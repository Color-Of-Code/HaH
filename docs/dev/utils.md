# hah-utils

The `hah-utils` crate provides low-level shared utilities and facades for third-party libraries used across the HaH workspace. It serves as a HAL (Hardware Abstraction Layer) of sorts for OS and library interactions, ensuring consistency and making it easier to swap out dependencies.

## Modules

### `fs`

Filesystem helpers including:

- ID sanitization for filenames.
- Helpers for walking directories to find broken symlinks.
- Scanning for files older than a certain duration.

### `json`

Pretty-printing and serialization helpers for JSON output.

### `paths`

Utilities for resolving platform-specific configuration and data directories (e.g., following XDG Base Directory Specification on Linux).

### `size`

Parsing and formatting for human-readable byte sizes (e.g., "100MB", "1.5GiB").

### `sysctl`

Algorithms for detecting conflicts in `sysctl` configurations, such as multiple files setting the same key to different values.

### `yaml`

Thin wrapper around YAML parsing and serialization to ensure consistent configuration throughout the workspace.

## Philosophy

Other crates in the workspace should generally prefer using `hah-utils` over adding direct dependencies on common low-level crates like `serde_json`, `walkdir`, or `directories`.
