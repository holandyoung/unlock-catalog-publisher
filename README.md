# Unlock Catalog

Standalone offline tooling for producing deterministic Unlock Catalog V1 publication artifacts.

This repository is intentionally independent from the Unlock Platform source tree. It does not import, copy, or dynamically invoke `global-k8s-infra`; compatibility is proven only through versioned bytes and fixtures consumed across the repository boundary.

## Boundaries

| Area | Owner | Responsibility |
| --- | --- | --- |
| `cmd/catalog-publisher` | Publisher maintainers | Build unsigned candidates and materialize reviewed releases into a protected Git tree |
| `cmd/catalog-signer` | Offline signing operators | Validate immutable candidate bytes and produce signature fragments |
| `cmd/catalog-assembler` | Release operators | Assemble independently produced fragments without accessing signing material |
| `internal/catalogv1` | Publisher maintainers | Canonical Catalog V1 encoding and validation |
| `catalog/definitions` | Catalog content owners | Declarative unsigned source content only |
| `catalog/sources` | Release operators | Threshold-signed public release bytes only |
| `fixtures/v1` | Test maintainers | Synthetic conformance fixtures only |
| `deploy` | Release operators | Protected repository publication policy |

CI runs only this repository's formatting, tests, vet, and secret-pattern scan. Signing material is never available to CI, online systems, or deployment automation.

## Local verification

```bash
go test ./...
go vet ./...
test -z "$(gofmt -l .)"
```

## Build unsigned candidates

Candidate builds require an explicit reproducible timestamp and a new output
directory:

```bash
workdir="$(mktemp -d)"
SOURCE_DATE_EPOCH=1785312000 \
  go run ./cmd/catalog-publisher candidate --output "$workdir/candidate"
```

The command builds exactly two independent source roots:

- `unlock-official-linux-amd64-static` grants data permissions only.
- `unlock-official-linux-amd64-static-exec` grants executable permission
  explicitly and pins executable descriptors to `linux/amd64/static`.

Each output contains only `manifest.payload.json`, `signing-request.json`, and
content-addressed `objects/`. It contains no signature, key, deploy credential,
network operation, helper invocation, or artifact execution capability.

## Inspect and sign offline

The signer revalidates the complete candidate before opening a key provider:

```bash
go run ./cmd/catalog-signer inspect --candidate /offline/candidate/source-id
go run ./cmd/catalog-signer sign \
  --candidate /offline/candidate/source-id \
  --expect-request-digest SHA256_FROM_INSPECT \
  --encrypted-key /offline/custody/key.age \
  --passphrase-file /offline/custody/passphrase \
  --output /offline/fragments/source-id-test-a.json
```

Both sensitive input files must be owner-only, non-executable regular files and
must not be symlinks. The signer emits only `requestDigest`, `keyId`, and
`signature`. It does not create keys, mutate candidates, access a network,
execute candidate content, assemble a threshold, or deploy bytes.

The signer requires Linux `openat2` no-symlink resolution. Candidate files and
directories must retain their deterministic `0644`/`0755` modes. The fragment
output must be outside the candidate directory, and the expected request digest
must be copied from a separately reviewed `inspect` result.

## Assemble a signed release

The assembler consumes only reviewed candidates, public roots, and independent
signature fragments. It has no key provider and cannot sign or modify candidate
bytes. First assemble an R1-to-R2 bridge that retains enough shared key material
to satisfy both 2-of-3 thresholds for at least 90 days:

```bash
go run ./cmd/catalog-assembler root \
  --current-root /reviewed/roots/r1.json \
  --next-root /reviewed/roots/r2.json \
  --now 2026-07-29T08:00:00Z \
  --fragment /offline/fragments/root-a.json \
  --fragment /offline/fragments/root-b.json \
  --output /release/r2.signed.json
```

Then assemble a source release with its exact identity and permissions:

```bash
go run ./cmd/catalog-assembler release \
  --candidate /reviewed/candidate/source-id \
  --current-root /reviewed/roots/r1.json \
  --signed-root /release/r2.signed.json \
  --source-id source-id \
  --permissions metadata,detection-data,routing-data \
  --now 2026-07-29T08:00:00Z \
  --fragment /offline/fragments/manifest-a.json \
  --fragment /offline/fragments/manifest-b.json \
  --output /release/source-id-v1
```

The new output directory contains `manifest.json`, `root.json`, immutable
objects, a versioned archive, and a deterministic `.ucp` package. Pass the prior
signed manifest with `--prior-manifest` when one exists so cumulative
revocations cannot be removed or downgraded. Deployment remains a separate
step.

## Materialize a protected Git release

The materializer copies the exact reviewed release into the repository's
append-only release tree. It has no GitHub credential, signing key, network
operation, or authority to alter signed bytes:

```bash
go run ./cmd/catalog-publisher materialize \
  --release /release/source-id-v1 \
  --repository /worktrees/unlock-catalog-release
```

Review the resulting `catalog/sources/<source-id>/` diff, then validate it
against an exact base checkout:

```bash
go run ./cmd/catalog-publisher verify-release \
  --base /worktrees/unlock-catalog-base \
  --repository /worktrees/unlock-catalog-release
```

The protected `main` branch is the publication pointer. Existing objects,
archives, roots, and packages cannot be removed or changed. The live manifest
and root must resolve to exact immutable archives, every referenced object must
match its digest and length, and the deterministic package must match the live
release. GitHub raw is not yet enabled or promised as a subscription origin.
