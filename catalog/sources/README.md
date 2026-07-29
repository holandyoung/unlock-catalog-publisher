# Catalog sources

Owner: Catalog content owners.

Only strict declarative source content belongs here. Content must not contain credentials, signing material, executable build hooks, deployment configuration, or platform source code.

Every source lives in `<source-id>/source.yaml`; declared object bytes live
under that same root at `objects/sha256/<first-2>/<sha256>`. The directory name,
`sourceId`, permission policy, and object paths must match exactly.

The two accepted roots are deliberately separate:

| Source | Permissions |
| --- | --- |
| `unlock-official-linux-amd64-static` | `metadata`, `detection-data`, `routing-data` |
| `unlock-official-linux-amd64-static-exec` | the data permissions plus explicit `executable` |

The checked content is synthetic conformance data and is not deployed by the
candidate command.
