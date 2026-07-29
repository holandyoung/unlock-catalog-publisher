# Architecture

## Repository boundary

The publisher is a standalone producer of Unlock Catalog V1 bytes. The Unlock Platform is a black-box consumer: neither repository imports the other, and neither build or CI pipeline checks out or invokes the other repository.

Cross-repository compatibility is frozen by versioned candidate and negative fixtures. A platform binary may consume those bytes in conformance tests, but publisher correctness cannot depend on platform source code.

## Trust boundaries

1. Declarative content under `catalog/sources` is untrusted input to the candidate builder.
2. The publisher produces deterministic, canonical, unsigned candidate bytes.
3. An offline signer independently revalidates immutable candidate bytes and emits a signature fragment.
4. The assembler combines fragments and publication metadata without gaining access to signing material.
5. Deployment tooling may publish already assembled bytes; it never signs, executes Catalog artifacts, or stores signing material.

Candidate building, signing, assembly, and deployment are separate commands and separate review surfaces. The candidate builder is implemented; signing, assembly, and deployment are not.

## Candidate boundary

Each declarative source has its own directory, source identity, permission set,
object root, version, and watermark history. The default data source cannot
declare executable permission or executable artifacts. The explicit executable
source requires the complete permission set and exact `linux/amd64/static`
platform metadata.

The builder rejects unknown or duplicate YAML members, aliases, identity/root
mismatches, duplicate stable IDs, permission bleed, non-canonical
content-addressed paths, object digest or length drift, unsafe filesystem types,
executable file modes, and unsupported cohorts. It reads object bytes but never
executes them.

`SOURCE_DATE_EPOCH` supplies the only build time. A candidate is an unsigned
directory with this shape:

```text
<source-id>/
  manifest.payload.json
  signing-request.json
  objects/sha256/<first-2>/<sha256>
```

The signing request binds the canonical payload digest, publisher policy,
source identity, version, lifetime, permissions, cohort, and every object
descriptor. Candidate files are mode `0644`; directories are mode `0755`.

## Key handling

Real signing material never enters this repository, CI, logs, online services, deployment systems, or fixtures. Candidate construction has no key provider and emits no signatures.

## Directory ownership

| Path | Owner | Allowed content |
| --- | --- | --- |
| `cmd/catalog-publisher` | Publisher maintainers | Candidate CLI entry point |
| `cmd/catalog-signer` | Offline signing operators | Offline signer CLI entry point |
| `cmd/catalog-assembler` | Release operators | Fragment assembly CLI entry point |
| `internal/catalogv1` | Publisher maintainers | Canonical V1 models and encoding |
| `catalog/sources` | Catalog content owners | Strict declarative source documents |
| `fixtures/v1` | Test maintainers | Synthetic positive and negative fixtures |
| `deploy` | Release operators | Publication-side docs and integration |
