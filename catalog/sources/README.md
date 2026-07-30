# Signed release tree

Owner: release operators.

Only already assembled, threshold-signed public bytes belong here. Declarative
unsigned content lives under `catalog/definitions`; signing keys and credentials
never belong in either tree.

Each published source has this fixed layout:

```text
<source-id>/
  manifest.json
  root.json
  objects/sha256/<first-2>/<digest>
  archive/<20-digit-version>/<manifest-digest>/manifest.json
  roots/<20-digit-root-version>/<root-digest>/root.json
  packages/<20-digit-version>/<manifest-digest>/unlock-catalog-package-v1.tar.zst
```

Objects, archives, roots, and packages are append-only. A release PR may update
live `manifest.json` and `root.json` only when the same commit adds all required
immutable bytes. Existing immutable paths may never be modified, removed, or
mode-changed. Manifest and root versions move forward only; existing
revocations cannot be removed or weakened.

`main` is the only release pointer. Repository checks validate the complete
tree and reject mixed release/tooling changes. This repository does not grant
the Unlock Platform any built-in URL, source identity, or trust root.

The default stable GitHub Raw BaseURL and the equivalent self-hosted HTTPS
contract are documented in [`../../docs/ORIGINS.md`](../../docs/ORIGINS.md).
