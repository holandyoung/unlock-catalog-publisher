# catalog-publisher

Owner: publisher maintainers.

This directory owns the deterministic unsigned candidate CLI. It may read strict declarative content and write candidate bytes. It must not sign, deploy, execute helpers, or import platform source code.

The implemented commands are:

```text
catalog-publisher candidate --output DIR [--sources DIR]
catalog-publisher deploy --target manifest|root --release DIR --prefix PREFIX (--initial-live | --expected-live-etag ETAG)
```

`SOURCE_DATE_EPOCH` is mandatory. `DIR` must not already exist, and output is
published only after both fixed source cohorts validate and build successfully.

The deploy command accepts only an assembled release directory. It verifies the
exact release tree and deterministic package, maps bytes to immutable
digest-qualified keys, performs remote HEAD/GET/range readback, and
conditionally updates one live pointer. R2 endpoint, bucket, and prefix-scoped
deploy credential are read from environment variables; command output contains
only public release metadata and the resulting ETag.
