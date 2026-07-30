# Catalog V1 offline package

`unlock-catalog-package-v1.tar.zst` is the deterministic offline transport for one
signed Catalog release. It is intended for import, review, and disconnected transfer.
It is not an online subscription URL and does not replace the HTTPS source BaseURL.

## Archive layout

The package is one deterministic zstd frame containing a deterministic USTAR archive:

```text
package.json
repository/manifest.json
repository/root.json
repository/objects/sha256/<first-2>/<digest>
```

`repository/root.json` is optional in the format. Packages produced by the current
assembler include it. No archive history, package self-copy, executable, directory,
link, device, FIFO, sparse member, PAX record, GNU extension, or trailing data is
allowed.

`package.json` is strict canonical JSON with this shape:

```json
{
  "format": "unlock-catalog-package-v1",
  "sourceId": "source-id",
  "manifestDigest": "64-lowercase-hex",
  "manifestEnvelopeSHA256": "64-lowercase-hex",
  "rootVersion": 1,
  "files": [
    {
      "path": "repository/manifest.json",
      "length": 1,
      "sha256": "64-lowercase-hex"
    }
  ]
}
```

`rootVersion` is optional. `files` is strictly byte-sorted by path and covers every
`repository/` member exactly once. It never contains `package.json` or the package's
own digest. The immutable release tree and fixture provenance record the package
digest externally.

## Deterministic bytes

Every archive member is a regular file with mode `0644`, uid `0`, gid `0`, mtime Unix
epoch `0`, empty owner names, and USTAR format. `package.json` is first; repository
members follow in byte-sorted order. The zstd encoder uses the repository-pinned
library version, one encoder worker, the fixed default level, and frame checksum.

Verification parses the bounded zstd and tar streams, validates the metadata table,
rebuilds the canonical USTAR bytes, rebuilds the canonical zstd frame, and requires
both byte comparisons to match. This rejects alternate encodings, concatenated
frames, extension headers, padding drift, and trailing bytes even if they decode to
similar files.

## Limits

The Catalog package writer and verifier enforce:

| Boundary | Maximum |
| --- | ---: |
| Compressed package | 256 MiB |
| Uncompressed archive | 256 MiB |
| Manifest, root, or `package.json` | 4 MiB each |
| One immutable artifact | 64 MiB |
| Archive members | 4,096 including `package.json` |
| Member path | 255 bytes |

Paths must be canonical slash-separated relative paths. Absolute paths, `..`,
backslashes, duplicates, case collisions, unknown members, missing members, and
repository-prefix drift are rejected before any release is accepted.

## Trust boundary

The package table proves transport integrity only. It does not create a trust root,
verify a Catalog signature, grant permissions, interpret revocations, or activate
content. An importing platform must pass the exact extracted manifest and artifact
bytes into its own Catalog V1 parser, signature verifier, permission checks,
revocation checks, and runtime validation before changing an active pointer.

The package contains no private key, credential, platform state, source URL, or
provider configuration.
