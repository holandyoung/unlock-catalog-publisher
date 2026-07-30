# Catalog HTTPS origins

Unlock Catalog V1 online subscriptions use an ordinary, stable HTTPS directory.
The subscriber stores one source BaseURL. The publisher updates the signed files
under that directory without changing the configured URL.

The default public origin for this repository is:

```text
https://raw.githubusercontent.com/holandyoung/unlock-catalog/main/catalog/sources/<source-id>/
```

The equivalent template recorded in `deploy/repository.yaml` is public metadata,
not a platform default. Unlock Platform must receive the source URL, source ID,
and trust root through explicit operator configuration.

## Directory contract

Every source BaseURL exposes the same protected release tree:

```text
<source-base-url>/
  manifest.json
  root.json
  objects/sha256/<first-2>/<digest>
  archive/<20-digit-version>/<manifest-digest>/manifest.json
  roots/<20-digit-root-version>/<root-digest>/root.json
  packages/<20-digit-version>/<manifest-digest>/unlock-catalog-package-v1.tar.zst
```

`manifest.json` and `root.json` are live pointers. All paths below `objects/`,
`archive/`, `roots/`, and `packages/` are immutable. Protected `main` is the only
publication pointer for the default origin.

GitHub Raw is transport, not trust. A client must still parse the signed manifest,
verify the configured source identity and trust root, enforce threshold signatures,
permissions, expiry, revocations, object digest and length, and activate only a
complete verified snapshot. HTTP success alone never makes bytes trusted.

## Stable URL updates

Publishers advance a source by merging one protected release transaction. The
configured BaseURL remains unchanged. Clients fetch the new live manifest, then
resolve its content-addressed objects and exact immutable archives below the same
BaseURL.

GitHub Raw and other static hosts can cache files independently. A refresh can
therefore observe a new manifest before every referenced object is visible, or an
old manifest after new immutable bytes are visible. The complete refresh must fail
closed on either mixed view, keep the previous active snapshot, and retry the same
BaseURL later. A partially fetched release must never become active.

## Self-hosting

A user may serve the same directory from their own HTTPS website. The platform does
not identify GitHub, a CDN, or a storage provider and does not select provider-specific
code. A self-hosted origin must:

- use a canonical HTTPS BaseURL ending in `/`;
- serve exact bytes without content transformation;
- avoid cross-origin or path-changing redirects;
- preserve immutable object, archive, root, and package paths permanently;
- expose live `manifest.json` and `root.json` at stable paths;
- return bounded responses and support ordinary anonymous GET requests.

Authentication headers, cookies, embedded URL credentials, URL query credentials,
and secret-bearing publication workflows are outside the Catalog V1 origin contract.

## Repository verification

`catalog-publisher verify-origin` compares an anonymous HTTPS origin with the exact
protected local release tree:

```bash
go run ./cmd/catalog-publisher verify-origin \
  --repository . \
  --base-url https://raw.githubusercontent.com/holandyoung/unlock-catalog/main/catalog/sources/
```

The verifier rejects HTTP, non-canonical or credential-bearing URLs, redirects,
content encoding drift, timeouts, missing files, length mismatches, and byte
mismatches. It reads only; it cannot sign, write Git, publish, or obtain credentials.

The `raw-origin` push-main workflow retries the complete comparison for at most six
minutes to allow bounded CDN convergence. It also checks the repository sentinel at
both `main` and the immutable commit URL, including no-redirect, identity encoding,
and byte-range behavior. Failure blocks a release-ready claim but never writes back
to `main`.

## Recovery

If an origin exposes a mixed or incomplete view, retain the prior active snapshot
and retry. Do not mutate an immutable path to repair a published release. Correct a
non-security error with a higher protected release; correct a security error with a
higher signed root or manifest version and cumulative revocation.

No object-storage bucket, custom Catalog domain, DNS record, edge worker, production
prefix, or publication principal is required by this origin model.
