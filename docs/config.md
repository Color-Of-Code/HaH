# Configuration

HaH loads configuration from these locations in order, with later files overriding earlier ones:

1. `/etc/hah/config.yaml` — system-wide defaults
2. `~/.config/hah/config.yaml` — per-user overrides

All keys are optional. HaH runs with sensible defaults when no config file is present.

---

## Full Config Reference

```yaml
# ── Profile ───────────────────────────────────────────────────────────────────
# Free-form label; no behaviour is currently gated on this value.
profile: desktop          # default: ""

# ── Thresholds ────────────────────────────────────────────────────────────────
thresholds:
  boot_space_mb: 100      # Warn when free space on /boot drops below this (MB).
  initramfs_size_mb: 100  # Warn on initramfs images larger than this (MB).
  journal_size_mb: 500    # Warn when the systemd journal exceeds this (MB).
  snap_max_revisions: 2   # Warn when a snap retains more revisions than this.
  crash_dump_max_days: 30 # Warn on crash dumps older than this many days.

# ── Package allowlist ─────────────────────────────────────────────────────────
# Packages listed here are silently ignored by checks that would otherwise
# flag them (e.g. autoremovable, residual-config, user-denylist).
allowlist:
  packages:
    - some-package-to-ignore

# ── Package denylist ──────────────────────────────────────────────────────────
# The user-denylist check flags any installed package in this list.
denylist:
  packages:
    - name: flashplugin-installer
      reason: "Adobe Flash is end-of-life and a security risk"

# ── Check selection ───────────────────────────────────────────────────────────
# Disable specific checks by ID. Use `hah list` to see all IDs.
disabled_checks:
  - broken-symlinks

# Enable only a specific subset of checks (if set, all others are skipped).
enabled_checks:
  - apt-key
  - residual-config

# ── Preferred Snap packages ───────────────────────────────────────────────────
# Packages listed here are excluded from the snap-apt-duplicate check because
# you intentionally prefer the Snap version over the APT version.
preferred_snap:
  - firefox
  - chromium

# ── YAML rule directories ─────────────────────────────────────────────────────
# Additional directories to scan for *.yaml rule files, beyond the two
# default locations (/etc/hah/rules.d and ~/.config/hah/rules.d).
rule_dirs:
  - /opt/custom-hah-rules
```

---

## Output Formats

The `--output` flag on `hah scan` selects the output format:

| Value      | Description |
| ---------- | ----------- |
| `terminal` | Human-readable coloured output (default) |
| `json`     | JSON array of findings with full metadata |
| `yaml`     | YAML array of findings with full metadata |

---

## Severity Levels

| Level      | Colour  | Exit code |
| ---------- | ------- | --------- |
| `Info`     | cyan    | 0 |
| `Warning`  | yellow  | 0 |
| `Critical` | red     | 1 |

HaH exits with code `1` if at least one Critical finding was detected. Info and Warning findings do not affect the exit code.
