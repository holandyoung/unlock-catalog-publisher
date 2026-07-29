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

Candidate building, signing, assembly, and deployment are separate commands and
separate review surfaces. Candidate building and offline fragment signing are
implemented; assembly and deployment are not.

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

Real signing material never enters this repository, CI, logs, online services,
deployment systems, or fixtures. Candidate construction has no key provider and
emits no signatures.

The signer first revalidates canonical payload bytes, the complete signing
request, publisher policy, source identity, version, validity, permissions,
cohort, object descriptors, object bytes, and the exact candidate filesystem
shape. A failed check occurs before the provider can sign. Fragment signatures
cover the canonical manifest payload; the fragment request digest is the SHA-256
of canonical `signing-request.json`, which binds that payload to every policy and
object field.

`inspect` prepares an immutable in-memory view of the validated payload. `sign`
requires the operator-confirmed request digest, opens the provider only after
candidate and output-path preflight, and signs those pinned bytes. Candidate and
sensitive-file reads require Linux `openat2` with no-symlink resolution; there
is no less strict pathname fallback.

The implemented fallback provider decrypts an age scrypt container in a short
lived offline signer process. Its inner strict JSON identifies schema version 1,
algorithm `Ed25519`, a stable key ID, and a 32-byte seed. Provisioning and key
generation are intentionally outside this repository. The provider clears its
mutable key slices when closed; the age API accepts a Go string passphrase, so
library/runtime copies cannot be guaranteed to be deterministically cleared.
Custodians must therefore use a single-purpose offline process and remove the
temporary owner-only passphrase file after use.

PKCS#11 support is not implemented because compatible hardware-backed Ed25519
behavior has not yet been verified. This does not weaken the later 2-of-3 or
independent-custody requirements.

## Directory ownership

| Path | Owner | Allowed content |
| --- | --- | --- |
| `cmd/catalog-publisher` | Publisher maintainers | Candidate CLI entry point |
| `cmd/catalog-signer` | Offline signing operators | Offline signer CLI entry point |
| `cmd/catalog-assembler` | Release operators | Fragment assembly CLI entry point |
| `internal/catalogv1` | Publisher maintainers | Canonical V1 models and encoding |
| `internal/signing` | Offline signing operators | Candidate revalidation, provider interface, encrypted-file fallback, fragment validation |
| `catalog/sources` | Catalog content owners | Strict declarative source documents |
| `fixtures/v1` | Test maintainers | Synthetic positive and negative fixtures |
| `deploy` | Release operators | Publication-side docs and integration |
