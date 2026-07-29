# Catalog V1 candidate fixtures

`valid/` is generated from `catalog/sources/` with
`SOURCE_DATE_EPOCH=1785312000`. It contains unsigned canonical payloads,
signing requests, and content-addressed objects only.

`invalid/` contains parser-negative source documents. Policy and filesystem
negative cases are generated from the same valid source model by the focused
tests in `internal/policy` and `internal/cohort`; those tests cover duplicate
stable IDs, permission bleed, identity/root mismatch, non-canonical paths,
digest/length mismatch, unsafe file types, executable mode, and unsupported
cohorts.
