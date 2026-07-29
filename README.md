# Unlock Catalog Publisher

Standalone offline tooling for producing deterministic Unlock Catalog V1 publication artifacts.

This repository is intentionally independent from the Unlock Platform source tree. It does not import, copy, or dynamically invoke `global-k8s-infra`; compatibility is proven only through versioned bytes and fixtures consumed across the repository boundary.

## Boundaries

| Area | Owner | Responsibility |
| --- | --- | --- |
| `cmd/catalog-publisher` | Publisher maintainers | Build deterministic unsigned candidates from declarative source content |
| `cmd/catalog-signer` | Offline signing operators | Validate immutable candidate bytes and produce signature fragments |
| `cmd/catalog-assembler` | Release operators | Assemble independently produced fragments without accessing signing material |
| `internal/catalogv1` | Publisher maintainers | Canonical Catalog V1 encoding and validation |
| `catalog/sources` | Catalog content owners | Declarative source content only |
| `fixtures/v1` | Test maintainers | Synthetic conformance fixtures only |
| `deploy` | Release operators | Publication documentation and deployment-side integration |

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

Assembly and deployment remain separate later tasks.
