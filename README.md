# HaH

HaH is a diagnostic utility for inspecting Linux systems. The goal is to detect common system maintenance problems, explain why they matter, and offer safe remediation suggestions.

## Usage

```bash
hah <COMMAND>
```

### Commands

| Command           | Description                                       |
| ----------------- | ------------------------------------------------- |
| `hah scan`        | Run all enabled checks and report findings        |
| `hah list-checks` | List every registered check with its ID and title |

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
- [Built-in Checks](docs/checks.md) — List of what HaH detects
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

## Capabilities

HaH detects a wide range of system maintenance issues and provides information on why they matter, along with remediation suggestions.

### Boot and Kernel

- **Disk Space**: Low free space on `/boot`.
- **Cleanup**: Unused kernels and stale kernel headers/modules.
- **Configuration**: Suboptimal initramfs compression or oversized images.
- **Drivers**: DKMS modules that fail to build or broken driver states.

### Package Hygiene (APT, Snap, Dpkg)

- **State**: Failed or partial package states (`dpkg --audit`).
- **Cleanup**: Residual configuration files (`rc` state) and auto-removable packages.
- **Security**: Deprecated `apt-key` usage and legacy repository formats.
- **Conflicts**: Software duplicated across multiple package managers (e.g., APT and Snap).
- **Custom Rules**: Support for user-defined package denylists via configuration.

### Network Configuration

- **Redundancy**: Multiple active NTP or DHCP clients causing management overlap.
- **Legacy**: Outdated network tooling (`ifupdown`, `ntp`) alongside modern managers.
- **Resolved**: Incorrect `systemd-resolved` stub resolver configuration.

### System Drift and Tuning

- **Integrity**: Broken symbolic links and stale systemd units.
- **Resources**: Excessive journal growth and old crash dumps.
- **Kernel Tuning**: Conflicting or redundant `sysctl` parameters across different files.

---

## Future Direction

HaH is evolving into a comprehensive diagnostic assistant for long-lived Linux systems. Future goals include:

- **Audit Reports**: Generation of detailed maintenance reports in HTML or Markdown.
- **System Profiles**: Check sets tailored for specific roles (Desktop, Server, Container).
- **Extended Diagnostics**: Integration with SMART data, filesystem health, and hardware metrics.
- **Release Lifecycle**: Detection of unsupported end-of-life distribution releases.
- **DSL Expansion**: More powerful data sources and filtering for the YAML rule engine.
