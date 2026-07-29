# Conditional publication policy

Release operators may publish only an already assembled, reviewed Catalog V1
release. The deploy process has a prefix-scoped R2 credential and public release
bytes; it has no candidate builder, key provider, or authority to change signed
content.

## Object layout and order

For each source under the configured prefix, deploy maps assembled bytes to:

    objects/sha256/<first-2>/<digest>
    archive/<20-digit-version>/<manifest-digest>/manifest.json
    roots/<20-digit-root-version>/<root-digest>/root.json
    packages/<20-digit-version>/<manifest-digest>/<package>.ucp
    manifest.json
    root.json

Every immutable key is created with If-None-Match: *. A pre-existing key is
accepted only when HEAD, full GET, and a bytes=0-0 range readback prove the same
ETag, length, SHA256 metadata, Content-Type, Cache-Control, identity encoding,
and bytes. Uploads bind the body with Content-MD5 and requests force
Accept-Encoding: identity.

The manifest transaction uploads and verifies every immutable object before it
updates live manifest.json. Existing live bytes require the exact current ETag
in If-Match; initial publication uses If-None-Match: *. Collision, partial
upload, readback drift, or ETag drift stops before the live write, so the old
live pointer remains unchanged. Retrying after a crash revalidates identical
immutable bytes instead of overwriting them.

Root publication is a separate transaction. It verifies the immutable root
archive before conditionally updating live root.json. Operators publish all
required bridge manifests before this operation. The tool does not claim that
two independent live object writes are one atomic transaction.

## Authority and recovery

The credential must be restricted to the exact bucket prefix and only the
PutObject, HeadObject, and GetObject operations needed by this workflow.
Deployment must not use delete or copy operations to imitate a transaction.
Automatic rollback is forbidden for revocation or root security transitions;
publish a higher valid version after review.

The reusable workflow downloads only an assembled artifact from its calling
workflow run. It does not build candidates or perform assembly. A protected
caller must review the artifact digest before invoking deploy.

No real bucket, prefix, endpoint, principal, or synthetic live publish may be
created or exercised until Task 10 records explicit authorization for the exact
external operations. Fake-S3 tests are the only Task 9 smoke.

The adapter follows Cloudflare's documented
[S3 compatibility](https://developers.cloudflare.com/r2/api/s3/api/) and
[strong consistency](https://developers.cloudflare.com/r2/reference/consistency/)
contracts. Those documents are design inputs, not evidence that production
resources already exist or satisfy the contract.
