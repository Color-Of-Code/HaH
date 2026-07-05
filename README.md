# HaH

HaH is a diagnostic utility for inspecting Linux systems. The goal is to detect common system maintenance problems, explain why they matter, and offer safe remediation suggestions.

## Usage

```bash
hah <COMMAND>
```

### Commands

| Command        | Description                                       |
| -------------- | ------------------------------------------------- |
| `hah scan`     | Run all enabled checks and report findings        |
| `hah list`     | List every registered check with its ID and title |
| `hah validate` | Validate rule file syntax without running checks  |

### `hah scan` options

| Option              | Default        | Description                                  |
| ------------------- | -------------- | -------------------------------------------- |
| `--output <FORMAT>` | `terminal`     | Output format: `terminal`, `json`, or `yaml` |
| `--check <ID>`      | _(all checks)_ | Run only the single check with this ID       |

### Exit codes

| Code | Meaning                                      |
| ---- | -------------------------------------------- |
| `0`  | No findings, or only Info / Warning findings |
| `1`  | At least one Critical finding was detected   |

---

## Documentation

- [User Guide](docs/user/README.md) — Getting started and usage
- [Configuration Guide](docs/config.md) — Customizing thresholds and filters
- [Shipped Checks](docs/checks.md) — List shipped rules and how to browse them
- [DSL Reference](docs/dsl.md) — Writing custom YAML rules
- [Developer Guide](docs/dev/README.md) — Working on the HaH codebase

---

## Scope

HaH is intended to help with:

- package and repository hygiene
- boot partition cleanup
- kernel and driver compatibility issues
- leftover files from upgrades or migrations
- duplicate software installs across package managers
- network configuration hygiene (NTP, DHCP, DNS, interface management)
- general system health checks
