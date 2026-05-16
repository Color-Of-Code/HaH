# Roadmap

Planned features that are not yet implemented. Items are roughly ordered by priority but the order is not a commitment.

---

## CLI & UX

| Feature | Notes |
| ------- | ----- |
| `hah report` | Audit report in HTML, Markdown, or JSON |
| Profiles (`desktop`, `server`, `vm`, `container`) | Activate or skip check sets based on the declared system role |

---

## New Checks

| Feature | Notes |
| ------- | ----- |
| Flatpak duplicate check | Flag software installed via both APT/Snap and Flatpak; only when `flatpak` is present |
| SMART / fsck integration | Surface `smartctl` and filesystem check results |
| EOL release check | Compare distro version against a bundled end-of-life date database |
| Orphaned package check | Packages installed from repositories that are no longer in any active source |
| Stale systemd units | Units referencing binaries that no longer exist |
| Legacy config drift | Config files that differ significantly from current package defaults |
| Snap preferred check | Flag packages where the Snap version is preferred over APT |

---

## DSL Extensions

| Feature | Notes |
| ------- | ----- |
| `where(field, op, value)` list filter | Filter structured records returned by capabilities |
| JSON Schema for rule files (`schemars`) | Enable editor autocompletion and validation of `.yaml` rule files |
| Typed config structs | Replace `HashMap<String, u64>` thresholds with typed config structs once DSL keys stabilise |

---

## Testing & Quality

| Feature | Notes |
| ------- | ----- |
| CLI integration tests (`assert_cmd` / `predicates`) | End-to-end tests of `hah scan` exit codes and output format |
| Snapshot tests (`insta`) | Detect regressions in rendered terminal/JSON/YAML output |
