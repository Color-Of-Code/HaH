# Built-in Checks

HaH ships a set of read-only diagnostic checks as declarative YAML rules backed
by capabilities. All checks are loaded from YAML at startup.
Run `hah list-checks` to see every registered check with its ID and title.

---

## Boot & Kernel

| Check ID                | What it detects | Threshold |
| ----------------------- | --------------- | --------- |
| `boot-space`            | Free space on `/boot` below threshold | `boot_space_mb` (default 100 MB) |
| `unused-kernels`        | Installed kernel packages that do not match the running kernel | — |
| `stale-kernel-headers`  | `linux-headers-*` packages with no matching `linux-image-*` | — |
| `initramfs-size`        | initramfs images in `/boot` that exceed the size threshold | `initramfs_size_mb` (default 100 MB) |
| `initramfs-compression` | Compression method in `/etc/initramfs-tools/initramfs.conf` not set to `zstd` or `lz4` | — |
| `dkms-status`           | DKMS modules in broken or not-installed state | — |

---

## APT & Packages

| Check ID                | What it detects |
| ----------------------- | --------------- |
| `apt-key`               | Non-empty `/etc/apt/trusted.gpg` — deprecated `apt-key` trust method |
| `legacy-sources-format` | One-line `deb` entries in `sources.list` or `sources.list.d/*.list` instead of the modern `.sources` format |
| `dpkg-state`            | Failed or partial package states reported by `dpkg --audit` |
| `residual-config`       | Packages in the `rc` state (removed but configuration files remain) |
| `autoremovable`         | Automatically-removable packages that were never cleaned up |
| `user-denylist`         | Packages matching the denylist entries in the config file |

---

## Snap

| Check ID             | What it detects | Threshold |
| -------------------- | --------------- | --------- |
| `snap-health`        | Disabled Snap revisions; more retained revisions than allowed | `snap_max_revisions` (default 2) |
| `snap-apt-duplicate` | Software installed via both APT and Snap simultaneously | — |

---

## Network Configuration

| Check ID                    | What it detects |
| --------------------------- | --------------- |
| `legacy-ntp`                | `ntp` (ISC ntpd) installed while `chrony` or `systemd-timesyncd` is also active |
| `ntp-conflict`              | Multiple NTP services active at the same time (ntpd, chrony, openntpd, timesyncd) |
| `legacy-dhcp-client`        | `isc-dhcp-client` (dhclient) installed alongside NetworkManager or systemd-networkd |
| `legacy-network-interfaces` | Non-loopback entries in `/etc/network/interfaces` (legacy ifupdown) alongside Netplan or NetworkManager |
| `resolved-config`           | `/etc/resolv.conf` not symlinked to systemd-resolved's stub resolver when systemd-resolved is active |

---

## System Drift & Sysctl

| Check ID          | What it detects | Threshold |
| ----------------- | --------------- | --------- |
| `broken-symlinks` | Broken symlinks under `/etc`, `/usr/lib`, and `/var/lib` | — |
| `old-crash-dumps` | Files in `/var/crash` and `/var/lib/systemd/coredump` older than the threshold | `crash_dump_max_days` (default 30 days) |
| `journal-size`    | systemd journal disk usage above the threshold | `journal_size_mb` (default 500 MB) |
| `sysctl-ordering` | The same sysctl key assigned conflicting values across multiple `sysctl.d` files | — |

---

## Rule Loading

YAML rules are loaded from these directories at startup:

- `rules/` (shipped defaults)
- `/usr/share/hah/rules/`
- `/etc/hah/rules.d/*.yaml`
- `~/.config/hah/rules.d/*.yaml`
- Any paths listed in `rule_dirs` in the config file

See [`docs/dsl.md`](dsl.md) for the full rule language reference.
