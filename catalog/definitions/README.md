# Catalog definitions

Owner: Catalog content owners.

Strict declarative unsigned inputs live under `<source-id>/source.yaml`; object
bytes live under the same root at `objects/sha256/<first-2>/<sha256>`. Inputs
must not contain credentials, signing material, executable build hooks,
deployment configuration, or platform source code.

The checked definitions are synthetic conformance content. Candidate building
does not publish them and does not write the signed release tree.
