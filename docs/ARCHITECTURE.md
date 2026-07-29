# Architecture

## Repository boundary

The publisher is a standalone producer of Unlock Catalog V1 bytes. The Unlock Platform is a black-box consumer: neither repository imports the other, and neither build or CI pipeline checks out or invokes the other repository.

Cross-repository compatibility is frozen by versioned candidate and negative fixtures. A platform binary may consume those bytes in conformance tests, but publisher correctness cannot depend on platform source code.

## Trust boundaries

1. Declarative content under `catalog/definitions` is untrusted input to the candidate builder.
2. The publisher produces deterministic, canonical, unsigned candidate bytes.
3. An offline signer independently revalidates immutable candidate bytes and emits a signature fragment.
4. The assembler combines fragments and publication metadata without gaining access to signing material.
5. The materializer may copy already assembled bytes into a protected Git worktree; it never signs, executes Catalog artifacts, invokes Git, accesses a network, or stores signing material.

Candidate building, signing, assembly, and materialization are separate commands and
separate review surfaces. Candidate building, offline fragment signing,
threshold assembly, and protected Git-tree materialization are implemented.
No online subscription origin is created or inferred by these implementations.

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

## Assembly boundary

The assembler revalidates every fragment against public Ed25519 roots and
requires exact 2-of-3 roots with unique key IDs and unique key material. A root
bridge must increase the version, remain valid for at least 90 days, retain a
threshold-compatible shared key set, and carry signatures accepted by both the
old and new roots. Replacing every key in one transition is rejected.

The same canonical manifest payload must satisfy both roots during the bridge.
Source identity and permissions are explicit operator inputs and are checked
against the reviewed candidate. Data and executable releases have different
identities, roots, and permission sets. Prior revocations are cumulative and
cannot be removed, retargeted, weakened, or version-downgraded.

Assembly writes a new directory atomically. It copies immutable object bytes,
emits signed manifest and root envelopes, archives the versioned metadata, and
builds a deterministic stored ZIP package with an exact allowlisted file tree.
The package verifier rejects traversal, duplicate, missing, extra, executable,
symlink, non-canonical metadata, length, and byte mismatches.

## Publication boundary

Publication is a protected Git transaction. The materializer accepts one exact
assembled release, validates all live and immutable bytes, and stages the full
source tree in a local worktree. Existing objects, manifest archives, root
archives, and packages are retained and cannot be overwritten.

The release verifier compares a pull request tree with its exact base. It
rejects immutable deletion, byte or mode mutation, unknown release paths, and
changes that mix release bytes with tooling or policy. It then parses every
current signed manifest and root, verifies their exact immutable archives,
checks threshold signatures and forward-only versions/revocations, checks all
referenced object digests and lengths, and verifies the deterministic package.
Root transitions and their manifests must satisfy both the prior and next
thresholds. The read-only workflow cannot push, merge, sign, or obtain
credentials.

The protected `main` branch is the release pointer. This boundary does not
enable GitHub raw as a supported origin and does not create object storage,
Cloudflare, DNS, Kubernetes, or other live infrastructure.

## Directory ownership

| Path | Owner | Allowed content |
| --- | --- | --- |
| `cmd/catalog-publisher` | Publisher maintainers | Candidate and protected release-tree CLI |
| `cmd/catalog-signer` | Offline signing operators | Offline signer CLI entry point |
| `cmd/catalog-assembler` | Release operators | Fragment assembly CLI entry point |
| `internal/catalogv1` | Publisher maintainers | Canonical V1 models and encoding |
| `internal/signing` | Offline signing operators | Candidate revalidation, provider interface, encrypted-file fallback, fragment validation |
| `catalog/definitions` | Catalog content owners | Strict declarative unsigned source documents |
| `catalog/sources` | Release operators | Threshold-signed public release tree |
| `fixtures/v1` | Test maintainers | Synthetic positive and negative fixtures |
| `deploy` | Release operators | Protected repository publication policy |
