# Shipped Checks

HaH includes a set of pre-configured diagnostic rules covering boot hygiene,
package management, network configuration, and system drift.

## Listing Checks

To browse all available checks with their IDs and descriptions, run:

```bash
hah list-checks
```

This lists every rule loaded from the built-in defaults and any custom
directories configured via `rule_dirs`.

## Customising

To skip or restrict checks, see the [Configuration Reference](config.md).
To write your own rules, see the [DSL Reference](dsl.md).
