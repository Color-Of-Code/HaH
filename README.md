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

| Code | Meaning                      |
| ---- | ---------------------------- |
| `0`  | No findings (clean system)   |
| `1`  | Highest severity is Info     |
| `2`  | Highest severity is Warning  |
| `3`  | Highest severity is Critical |

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

---

## Security

HaH is **read-only**—it performs no writes, no socket modifications, and no privileged operations. It can safely run with **zero Linux capabilities**.

### Recommended hardened deployment

```bash
# Create dedicated non-root user with minimal group membership
useradd -r -s /usr/sbin/nologin hah-checker
usermod -a -G adm,systemd-journal hah-checker

# Drop all capabilities from the binary
setcap -r /path/to/hah

# Run as that user (group membership handles all file access)
sudo -u hah-checker hah scan
```

### Container deployment

```bash
docker run \
  --read-only \
  --cap-drop=ALL \
  --user hah-checker \
  hah scan
```

HaH requires **no capabilities**—standard Unix group permissions (`adm` for logs, `systemd-journal` for journal access) provide all necessary access without privilege escalation.
