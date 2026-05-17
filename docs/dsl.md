# HaH DSL — Declarative Rule Language

Rules let you define checks in YAML without writing Rust. Rust provides reusable primitives
(capabilities in `hah-caps`, parsers and pipeline filters in `hah-dsl`); YAML composes them
into policy. Use the DSL for straightforward command/probe checks and for wiring up built-in
capabilities.

---

## Rule File Locations

HaH loads all `*.yaml` files from the following directories at startup, in this order:

1. `/etc/hah/rules.d/`
2. `~/.config/hah/rules.d/`
3. Any directories listed under `rule_dirs` in the config file

Duplicate rule IDs across files are rejected with a clear error at load time.
The default rule set shipped with HaH is in [`rules/`](../rules/).

---

## Core Syntax

Every rule has these top-level keys:

```yaml
rules:
  - id: my-check              # stable, unique check ID
    title: Human readable name
    only_if: ...              # optional: environment guards
    triggers: ...             # required: collect values
    values: ...               # optional: derived pipeline expressions
    conditions: ...           # required: when to emit a finding
    outcome: ...              # required: finding text and remediation
    use: ...                  # optional: references to reusable blocks
```

---

## Triggers

### Command trigger

Run a shell command and expose `$<name>.stdout` (and `stderr`, `success`) as pipeline sources.

```yaml
triggers:
  - name: free_bytes
    command:
      program: df
      args: ["--block-size=1", "--output=avail", "/boot"]
    transform: "$stdout | lines | nth(1) | trim | number"
```

### Probe trigger

Check whether a package is installed, a service is active, or get a file's size without running
a custom command.

```yaml
triggers:
  - name: ntp_installed
    probe:
      type: package_installed
      name: ntp

  - name: chrony_active
    probe:
      type: service_active
      name: chrony

  - name: gpg_size
    probe:
      type: file_size
      path: /etc/apt/trusted.gpg

  - name: resolv_target
    probe:
      type: symlink_target
      path: /etc/resolv.conf
```

### File trigger

Read a file's contents into a string variable. Returns `Null` if the file cannot be read;
combine with `require_files` in `only_if` to skip the rule entirely when the file is absent.

```yaml
triggers:
  - name: conf_content
    file:
      path: /etc/initramfs-tools/initramfs.conf
```

### Capability trigger

Call a Rust-backed capability that returns a typed `RuleValue`.

```yaml
triggers:
  - name: conflicts
    capability:
      type: sysctl_conflicts
      paths:
        - /etc/sysctl.d
        - /usr/lib/sysctl.d
```

Available capabilities:

| Capability | Returns | Description |
| ---------- | ------- | ----------- |
| `journal_usage` | `Int(mb)` | Total systemd journal disk usage |
| `old_files` | `List(paths)` | Files older than `older_than_days` in the given directories |
| `broken_symlinks` | `List(paths)` | Broken symlinks in the given directories |
| `sysctl_conflicts` | `List(descriptions)` | Conflicting sysctl key assignments across `sysctl.d` files |
| `kernel_inventory` | `List(pkgs)` | Installed kernel packages (running kernel + all candidates) |
| `stale_kernel_headers` | `List(pkgs)` | `linux-headers-*` packages with no matching `linux-image-*` |
| `large_initramfs` | `List(entries)` | Initramfs images exceeding `threshold_mb` |
| `legacy_apt_sources` | `List(paths)` | Files using legacy one-line `deb` format |
| `legacy_network_interfaces` | `Str(status)` | `/etc/network/interfaces` overlap state |
| `installed_denylist` | `List(entries)` | Installed packages matching the config denylist |

---

## Transformation Pipeline

A pipeline starts from a `$variable` and applies filters separated by `|`:

```text
$stdout | lines | non_empty | reject_contains($running_kernel) | sort
```

Pipelines can appear in `transform:` on a trigger, in `values:` as derived expressions, and in
condition operands.

### Available filters

| Filter | Description |
| ------ | ----------- |
| `trim` | Strip leading/trailing whitespace from a string |
| `lines` | Split a string into a list of lines |
| `non_empty` | Remove empty strings and nulls from a list |
| `skip(n)` | Drop the first _n_ items from a list |
| `first` | Take the first item of a list |
| `last` | Take the last item of a list |
| `nth(n)` | Take the _n_-th item (0-based) |
| `number` | Parse a string as an integer or float |
| `field(n)` | Take the _n_-th whitespace-separated field from a string |
| `prefix_strip(p)` | Remove a leading prefix _p_ from each string in a list |
| `starts_with(p)` | Keep only list items that start with _p_ |
| `contains(v)` | Check whether a string or list contains substring _v_ (returns `Bool`) |
| `icontains(v)` | Case-insensitive version of `contains`; on a list, keeps matching items |
| `reject_contains(v)` | Drop list items that contain substring _v_ |
| `join(sep)` | Join a list of strings into one string with separator _sep_ |
| `default(v)` | Return _v_ if the current value is `Null` |
| `count` | Return the number of items in a list as an `Int` |
| `sort` | Sort a list alphabetically |
| `unique` | Remove duplicate items from a list |
| `bytes_to_mb` | Divide a byte count integer by 1 048 576 and return an `Int` |
| `group_count(n)` | Group list items by whitespace-field _n_, return `"count key"` strings |
| `where_gt(n)` | Keep only items whose first field (parsed as int) exceeds _n_ |
| `intersect($var)` | Set intersection: keep only items whose value appears in the list variable _$var_ |
| `reject_in($var)` | Set subtraction: remove items whose value appears in the list variable _$var_ |

---

## Derived Values

Name intermediate pipeline results with `values:` for readability and reuse:

```yaml
values:
  unused_kernels: "$installed_kernels | reject_contains($running_kernel) | sort"
  unused_kernel_list: "$unused_kernels | join(', ')"
  unused_kernel_count: "$unused_kernels | count"
```

---

## Conditions

| Type | Description |
| ---- | ----------- |
| `numeric_threshold` | Compare a numeric value with `lt`, `lte`, `gt`, `gte`, `eq`, or `neq` against a threshold |
| `equals` | Compare booleans, strings, or numbers for equality |
| `non_empty` | True when a list or string is non-empty |
| `regex_match` | Match a string against a regular expression |
| `all` | Logical AND of a list of child conditions |
| `any` | Logical OR of a list of child conditions |
| `for_each` | Iterate over a list and produce one finding per item |

Every condition requires a `severity` (`Info`, `Warning`, or `Critical`).

### Compact syntax

The most concise way to write conditions. Use a severity key (`info`, `warning`, or `critical`)
with an expression string:

```yaml
conditions:
  - info: "$residual_packages"            # non-empty check
  - warning: "$count > 5"                 # numeric threshold (gt)
  - critical: "$free_mb < 50"             # numeric threshold (lt)
  - info: "$enabled == true"              # boolean equality
  - warning: "$status != true"            # boolean inequality (becomes equals false)
```

Supported operators: `>`, `>=`, `<`, `<=`, `==`, `!=`. When no operator is present, the
expression is treated as a `non_empty` check on the pipeline result.

Use `all:` and `any:` to combine conditions. Severity is auto-derived as the maximum severity
of the children:

```yaml
conditions:
  - all:
      - warning: "$ntp_installed == true"
      - any:
          - warning: "$chrony_active == true"
          - warning: "$timesyncd_active == true"
```

### Inferred syntax

Omit the `type:` field and let HaH infer the condition type from the fields present:

```yaml
conditions:
  - value: "$free_bytes"
    operator: lt
    threshold: "$threshold_bytes"
    severity: Critical

  - value: "$ntp_installed"
    expected: true
    severity: Warning

  - value: "$packages"
    severity: Info

  - value: "$line"
    pattern: "^COMPRESS=lz4"
    severity: Info
```

### Typed syntax (explicit)

Use `type:` for full control or when combining conditions with `all`/`any`:

```yaml
conditions:
  - type: numeric_threshold
    value: "$free_bytes"
    operator: lt
    threshold: "$threshold_bytes"
    severity: Critical

  - type: for_each
    source: "$duplicates"
    item_var: pkg
    severity: Warning

  - type: all
    severity: Warning
    conditions:
      - type: equals
        value: "$ntp_installed"
        expected: true
      - type: any
        conditions:
          - type: equals
            value: "$chrony_active"
            expected: true
          - type: equals
            value: "$timesyncd_active"
            expected: true
```

---

## Guards (`only_if`)

Guards prevent a rule from running when its environment preconditions are not met.

```yaml
only_if:
  distro_family: debian        # run only on Debian/Ubuntu/Mint
  require_commands:            # run only when these commands are on PATH
    - dkms
    - snap
  require_files:               # run only when these files exist
    - /etc/initramfs-tools/initramfs.conf
```

Legacy single-value keys are also supported:

```yaml
only_if:
  command_exists: snap
  package_installed: ntp
  service_active: systemd-resolved
```

Multiple guard keys are combined with AND.

---

## Outcome

```yaml
outcome:
  finding_id: boot-space-low
  title: "/boot has only {free_mb} MB free"
  description: "The /boot partition is nearly full ({free_mb} MB free, threshold: {threshold_boot_space_mb} MB)."
  remediation:
    description: "Remove unused kernels to free space."
    commands:
      - "sudo apt autoremove --purge"
```

Use `{variable}` placeholders in `title`, `description`, and remediation `description`. All
`values:` and trigger names are available for substitution.

---

## Reusable Blocks

Define shared fragments once and reference them from multiple rules:

```yaml
blocks:
  guards:
    debian_family:
      distro_family: debian

  outcomes:
    apt_remove:
      remediation:
        description: "Remove with apt."
        commands: ["sudo apt remove --purge {packages}"]

rules:
  - id: residual-config
    title: Residual package configuration files
    use:
      guard: debian_family
      outcome: apt_remove
    triggers:
      - name: residual_packages
        command:
          program: dpkg-query
          args: ["-W", "-f=${Status} ${Package}\\n"]
        transform: "$stdout | lines | starts_with('deinstall ok config-files ') | prefix_strip('deinstall ok config-files ') | sort"
    conditions:
      - type: non_empty
        value: "$residual_packages"
        severity: Info
    values:
      package_count: "$residual_packages | count"
      packages: "$residual_packages | join(' ')"
    outcome:
      finding_id: residual-config
      title: "{package_count} package(s) with residual configuration"
      description: "These packages were removed but their configuration files remain: {packages}."
```

Available block types: `guards`, `outcomes`. Blocks are resolved at load time; unknown references
cause a load error.

---

## Complete Examples

See [`rules/`](../rules/) for the default rule set shipped with HaH:

| File | What it demonstrates |
| ---- | -------------------- |
| `boot-space.yaml` | Command trigger, `bytes_to_mb`, `numeric_threshold` |
| `autoremovable.yaml` | Command trigger, `non_empty`, list pipeline |
| `residual-config.yaml` | `starts_with` / `prefix_strip`, block reuse |
| `legacy-ntp.yaml` | Multi-probe rule, `all` / `any` conditions |
| `ntp-conflict.yaml` | Shell command trigger, `non_empty`, `count` |
| `snap-apt-duplicate.yaml` | `intersect`, `reject_in`, `for_each` multi-finding |
| `resolved-config.yaml` | `symlink_target` probe, `contains` condition |
| `old-crash-dumps.yaml` | `old_files` capability, `for_each` per-item findings |
| `journal-size.yaml` | `journal_usage` capability |
| `sysctl-ordering.yaml` | `sysctl_conflicts` capability |
| `unused-kernels.yaml` | `kernel_inventory` capability, `reject_contains` |
| `broken-symlinks.yaml` | `broken_symlinks` capability |
| `initramfs-compression.yaml` | File trigger, `require_files` guard, `starts_with` |
| `dkms-status.yaml` | `icontains` filter, `require_commands` guard |
| `snap-health.yaml` | `group_count`, `where_gt`, aggregation pattern |
| `apt-key.yaml` | `file_size` probe, `numeric_threshold` |
| `dpkg-state.yaml` | Simple command + `non_empty` condition |
| `legacy-dhcp-client.yaml` | Multi-probe, `all`/`any` nested conditions |

---

## Validating Rule Files

Use `hah validate` to check rule file syntax without running any checks:

```bash
hah validate                          # validates all rule search dirs
hah validate rules/boot-space.yaml    # validate a specific file
hah validate my-rules/                # validate all YAML files in a directory
```

This catches YAML parse errors, unknown condition types, and duplicate rule IDs early.
