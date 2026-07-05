# HaH DSL — Declarative Rule Language

Rules let you define checks in YAML without writing Rust. Rust provides reusable primitives
(the parsers, pipeline filters, and policy-enforced command runner in `hah-core`/`hah-dsl`);
YAML composes them into policy. A rule gathers data by running commands or command
pipelines and shapes the output with pipeline filters — all declared in YAML.

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

### Pipeline trigger

Run a **declarative command pipeline**: an array of `argv` stages that HaH runs
in-process, feeding each stage's stdout into the next stage's stdin. The final
stage's stdout becomes the trigger value. Shape the result with the
[transformation pipeline](#transformation-pipeline).

```yaml
triggers:
  - name: broken
    pipeline:
      - [find, /etc, /usr/lib, /var/lib, -xtype, l]
    transform: "$stdout | lines | non_empty"

  - name: conflicts
    pipeline:
      - [grep, -rHs, "=", /usr/lib/sysctl.d, /etc/sysctl.d, /run/sysctl.d]
    transform: "$stdout | lines | conflicts"
```

Each stage is a plain `argv` array — **no shell** is involved, so globs and
redirections are not expanded; `find`/`grep` do their own matching. Multiple
stages pipe together just like a shell `|`:

```yaml
pipeline:
  - [dpkg-query, --show, "--showformat=${Package}\n", "linux-image-*"]
  - [sort]
```

Every stage's program is checked against the [command allowlist](config.md). If
a program is not permitted (and not approved in `--ask` mode), the check is
reported as **skipped** rather than run.

> Migrating from log scanning: a file tail plus regex filtering is expressed as
> `pipeline: [[tail, -c, "1048576", /var/log/syslog]]` followed by
> `transform: "$stdout | lines | grep('(?i)error')"`. Pair two such triggers
> with different patterns and condition severities to separate critical and
> warning findings entirely in YAML.

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
| `regex_escape` | Escape regex metacharacters so a string can be used literally in a regex pattern |
| `lines` | Split a string into a list of lines |
| `non_empty` | Remove empty strings and nulls from a list |
| `skip(n)` | Drop the first _n_ items from a list |
| `first` | Take the first item of a list |
| `last` | Take the last item of a list |
| `nth(n)` | Take the _n_-th item (0-based) |
| `number` | Parse a string as an integer or float |
| `to_bytes` | Parse a human size (`600.0M`, `1.5G`, `512K`) into an integer byte count |
| `field(n)` | Take the _n_-th whitespace-separated field from a string |
| `prefix_strip(p)` | Remove a leading prefix _p_ from each string in a list |
| `prefix_add(p)` | Add prefix _p_ to each string in a list or string |
| `suffix_strip(s)` | Remove a trailing suffix _s_ from each string in a list or string |
| `starts_with(p)` | Keep only list items that start with _p_ |
| `contains(v)` | Check whether a string or list contains substring _v_ (returns `Bool`) |
| `icontains(v)` | Case-insensitive version of `contains`; on a list, keeps matching items |
| `reject_contains(v)` | Drop list items that contain substring _v_ |
| `conflicts` | From `grep -rH` `file:key = value` lines, report keys with conflicting values across files |
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
| `grep(pattern)` | Keep list items (or a string) whose text matches any regex _pattern_ |
| `reject_grep(pattern)` | Remove list items (or a string) whose text matches any regex _pattern_ |

Use `grep`/`reject_grep` for regex-based filtering. They accept either a single pattern or a list of patterns, and match when any supplied pattern matches. For literal set-style matching, prefer `intersect` and `reject_in`.

Patterns for `grep` and `reject_grep` are Rust regular expressions. Use `(?i)` for
case-insensitive matching. Applied to a bare `Str`, both filters return a list:

`prefix_add(p)` is handy when you need to turn a bare version string into a package name, for example `"5.15" | prefix_add('linux-image-')` becomes `"linux-image-5.15"`.

```yaml
values:
  errors: "$dmesg_out | lines | grep('(?i)\\berror\\b')"
  clean:  "$lines | reject_grep('^#')"   # strip comment lines
```

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
  - warning: '$status =~ "^overlap:"'     # regex match
  - info: '$family == "debian"'           # string equality
```

Supported operators: `>`, `>=`, `<`, `<=`, `==`, `!=`, `=~`. When no operator is present, the
expression is treated as a `non_empty` check on the pipeline result. Quoted RHS with `==`
produces a string equality check; unquoted RHS produces a numeric comparison.

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
  id: boot-space-low
  title: "/boot has only {free_mb} MB free"
  description: "The /boot partition is nearly full ({free_mb} MB free, threshold: {threshold_boot_space_mb} MB)."
  remediation:
    description: "Remove unused kernels to free space."
    commands:
      - "sudo apt autoremove --purge"
```

Use `{variable}` placeholders in `title`, `description`, and remediation `description`. All
`values:` and trigger names are available for substitution.

### Per-item iteration (`for_each`)

When a condition fires on a list, produce one finding per item instead of a single finding:

```yaml
conditions:
  - warning: "$duplicates"

outcome:
  for_each:
    list: "$duplicates"
    as: pkg
  id: "snap-apt-dup-{pkg}"
  title: "'{pkg}' is installed via both APT and Snap"
  description: "Having '{pkg}' installed twice wastes space."
  remediation:
    description: Remove the APT version if the Snap is preferred.
    commands:
      - "sudo apt remove --purge {pkg}"
```

The `{item_var}` placeholder (here `{pkg}`) is available in all outcome template fields.
Without `for_each`, a single finding is emitted when the condition fires.

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
      id: residual-config
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
| `ntp-conflict.yaml` | Pipeline trigger (`systemctl is-active`), `grep`, `count` |
| `snap-apt-duplicate.yaml` | `intersect`, `reject_in`, `for_each` multi-finding |
| `resolved-config.yaml` | `symlink_target` probe, `contains` condition |
| `old-crash-dumps.yaml` | `find` pipeline, `for_each` per-item findings |
| `journal-size.yaml` | `journalctl` pipeline, `field` / `to_bytes` / `bytes_to_mb` |
| `sysctl-ordering.yaml` | `grep -rH` pipeline, `conflicts` aggregation filter |
| `unused-kernels.yaml` | `dpkg-query` pipeline, `reject_contains` against `uname` |
| `broken-symlinks.yaml` | `find -xtype l` pipeline |
| `initramfs-size.yaml` | `find -size` pipeline, `for_each` per-item findings |
| `legacy-apt-sources.yaml` | `grep -rl` pipeline, `for_each` |
| `user-denylist.yaml` | `dpkg-query` pipeline, `intersect` with config denylist |
| `legacy-network-interfaces.yaml` | Pipeline + probe decomposition, nested `all`/`any` |
| `initramfs-compression.yaml` | File trigger, `require_files` guard, `starts_with` |
| `dkms-status.yaml` | `icontains` filter, `require_commands` guard |
| `snap-health.yaml` | `group_count`, `where_gt`, aggregation pattern |
| `apt-key.yaml` | `file_size` probe, `numeric_threshold` |
| `dpkg-state.yaml` | Simple command + `non_empty` condition |
| `legacy-dhcp-client.yaml` | Multi-probe, `all`/`any` nested conditions |
| `dmesg-errors.yaml` | `dmesg` pipeline + `grep`, two-severity split |
| `syslog-errors.yaml` | `tail -c` pipeline + `grep` |
| `kernel-log-errors.yaml` | `tail -c` pipeline + `grep`, `require_files` guard |

---

## Validating Rule Files

Use `hah validate` to check rule file syntax without running any checks:

```bash
hah validate                          # validates all rule search dirs
hah validate rules/boot-space.yaml    # validate a specific file
hah validate my-rules/                # validate all YAML files in a directory
```

This catches YAML parse errors, unknown condition types, and duplicate rule IDs early.
