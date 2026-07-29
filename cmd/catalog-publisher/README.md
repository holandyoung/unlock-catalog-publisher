# catalog-publisher

Owner: publisher maintainers.

This directory owns the deterministic unsigned candidate CLI. It may read strict declarative content and write candidate bytes. It must not sign, deploy, execute helpers, or import platform source code.

The only implemented command is:

```text
catalog-publisher candidate --output DIR [--sources DIR]
```

`SOURCE_DATE_EPOCH` is mandatory. `DIR` must not already exist, and output is
published only after both fixed source cohorts validate and build successfully.
