# catalog-publisher

Owner: publisher maintainers.

This directory owns the deterministic candidate and protected release-tree
CLI. It may read strict declarative content, validate assembled public bytes,
and write those unchanged bytes into a Catalog repository worktree. It must not
sign, invoke Git, access a network, execute helpers, or import platform source
code.

The implemented commands are:

```text
catalog-publisher candidate --output DIR [--sources DIR]
catalog-publisher materialize --release DIR [--repository DIR]
catalog-publisher verify-release --base DIR [--repository DIR] [--changed-file PATH ...]
```

`SOURCE_DATE_EPOCH` is mandatory. `DIR` must not already exist, and output is
published only after both fixed source cohorts validate and build successfully.

`materialize` accepts only an assembled release directory. It verifies the
exact release tree and deterministic package before atomically replacing one
source directory while retaining immutable history. `verify-release` compares
the candidate repository with an exact base, rejects mixed changes and any
immutable deletion or mutation, prevents manifest/root/revocation rollback,
then verifies the current signed release's signatures, archives, objects, and
package. Neither command reads credentials or mutates a remote repository.
