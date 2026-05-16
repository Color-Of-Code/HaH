# HaH

HaH is a "hunt and heal" utility for inspecting and cleaning up Linux systems. The goal is to detect common system maintenance problems, explain why they matter, and offer safe cleanup or repair actions.

## Usage

```
hah <COMMAND>
```

### Commands

| Command           | Description                                       |
| ----------------- | ------------------------------------------------- |
| `hah scan`        | Run all enabled checks and report findings        |
| `hah list-checks` | List every registered check with its ID and title |

### `hah scan` options

| Option              | Default        | Description                                                                 |
| ------------------- | -------------- | --------------------------------------------------------------------------- |
| `--output <FORMAT>` | `terminal`     | Output format: `terminal`, `json`, or `yaml`                                |
| `--check <ID>`      | _(all checks)_ | Run only the single check with this ID                                      |
| `--fix`             | off            | Apply safe remediations automatically                                       |
| `--dry-run`         | on             | Report findings only, no changes (default behavior, conflicts with `--fix`) |

### Exit codes

| Code | Meaning                                      |
| ---- | -------------------------------------------- |
| `0`  | No findings, or only Info / Warning findings |
| `1`  | At least one Critical finding was detected   |

### Configuration

HaH loads configuration from the following locations in order, with later files taking precedence:

1. `/etc/hah/config.yaml` — system-wide defaults
2. `~/.config/hah/config.yaml` — per-user overrides

Example configuration:

```yaml
thresholds:
  boot_space_mb: 100 # warn when /boot free space drops below this
  initramfs_size_mb: 100 # warn on initramfs images larger than this
  journal_size_mb: 500 # warn when the systemd journal exceeds this
  snap_max_revisions: 2 # warn when a snap retains more revisions than this
  crash_dump_max_days: 30 # warn on crash dumps older than this many days

allowlist:
  packages:
    - some-package-to-ignore # suppress findings for this package

denylist:
  packages:
    - name: flashplugin-installer
      reason: "Adobe Flash is end-of-life and a security risk"

disabled_checks:
  - broken-symlinks # skip this check entirely
```

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

## Target Problems

### Boot and Kernel Maintenance

- low disk space on `/boot`
- unused kernels that can be removed safely
- oversized or outdated initramfs images
- initramfs compression choices that waste boot partition space
- stale kernel headers and modules
- mismatched running kernel versus installed kernel packages

### Drivers and DKMS

- DKMS modules that fail to build on newer kernels
- orphaned driver sources left behind after upgrades
- third-party drivers that block kernel upgrades
- NVIDIA, VirtualBox, ZFS, or similar modules with broken rebuild status
- missing build dependencies required for DKMS recovery

### APT and Repository Cleanup

- old or deprecated APT repositories
- duplicate repository definitions across `/etc/apt/sources.list` and `sources.list.d`
- leftover repository keys or keyrings that are no longer used
- old signing keys stored with deprecated trust methods such as `apt-key`
- legacy APT source formats that should be migrated to newer `.sources` entries or modern keyring usage
- outdated APT configuration snippets that override current defaults or reference removed repositories
- packages installed from repositories that no longer exist
- failed or partial package states in `dpkg` or `apt`

### Package Hygiene

- packages that should no longer be installed
- obsolete packages left over from distro migrations
- package cleanup rules driven by YAML configuration
- automatically removable packages that were never cleaned up
- residual config packages in the `rc` state

### Snap and Cross-Package-Manager Conflicts

- software installed via both APT and Snap
- cases where the Snap package is preferred because it is still maintained
- broken Snap installs, disabled revisions, or excessive retained revisions
- packages duplicated across APT, Snap, Flatpak, or manual installs

### Network Configuration

- legacy NTP daemon (`ntp` / ISC ntpd) installed instead of `chrony` or `systemd-timesyncd`
- multiple time-sync services active simultaneously, competing to adjust the clock
- legacy ISC DHCP client (`dhclient`) still installed when NetworkManager or `systemd-networkd` handles DHCP
- non-loopback interface definitions in `/etc/network/interfaces` (ifupdown) alongside Netplan or NetworkManager
- `/etc/resolv.conf` not linked to `systemd-resolved`'s stub resolver after an upgrade
- `resolvconf` package conflicting with `systemd-resolved`
- `ifupdown` installed alongside a modern network manager causing management overlap

### Leftovers and System Drift

- residual configuration files from removed software
- old log files, caches, and temporary artifacts
- broken symlinks left by removed packages
- stale systemd units, timers, or service drop-ins
- configuration drift after in-place upgrades
- outdated configuration files or settings carried forward across releases
- legacy defaults that no longer match current distro recommendations
- missing, conflicting, or suspicious `sysctl` parameters
- `sysctl` overrides that degrade security, stability, or network behavior

## Additional Ideas

- dry-run mode that reports findings without changing the system
- severity levels such as info, warning, and critical
- clear remediation output with exact commands before execution
- backup or snapshot hooks before destructive actions
- allowlist and denylist support for packages and repositories
- profile-based scans for desktop, server, VM, or container hosts
- distro-specific handlers for Debian, Ubuntu, Mint, and related systems
- machine-readable output such as JSON or YAML
- audit report generation for scheduled maintenance runs
- interactive mode for reviewing each fix before applying it
- non-interactive mode for automation
- plugin or rule system so checks can be added incrementally
- safety checks to avoid removing the currently running kernel
- detection of unsupported end-of-life releases
- checks for held packages that block security updates
- checks for interrupted upgrades or pending reboot requirements
- cleanup of old crash dumps and journal growth
- validation of `sysctl.d` ordering, overrides, and obsolete kernel tunables
- detection of deprecated config formats across package manager and system settings
- detection of conflicting or redundant NTP, DHCP, and DNS resolver configurations
- migration guidance from legacy network tooling to Netplan or NetworkManager
- optional integration with SMART, filesystem, and memory health checks

## Future Direction

HaH could evolve into a rule-based maintenance assistant that combines detection, explanation, and safe remediation for long-lived Linux systems.
