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

The repository currently contains the initialization boundary only. Candidate construction, signing, assembly, and deployment arrive as separately reviewed tasks.
