# Protected Git release policy

Release operators materialize only an already assembled and reviewed Catalog
V1 release. The materializer has public signed bytes and the current repository
tree; it has no key provider, GitHub credential, network operation, or authority
to change signed content.

## Transaction

1. Start a feature worktree from the latest `origin/main`.
2. Run `catalog-publisher materialize` with one exact assembled release.
3. Review the complete diff and run `catalog-publisher verify-release` against
   the base checkout.
4. Commit the live manifest/root and every new immutable object, archive, root,
   and package in one release commit.
5. Push the feature branch and merge only after all required checks pass and
   every conversation is resolved.

The protected `main` tree is the release pointer. Existing paths under
`objects/`, `archive/`, `roots/`, and `packages/` are immutable: deletion,
byte changes, or mode changes fail verification. Live `manifest.json` and
`root.json` must have exact immutable archive copies in the same tree. Release
PRs cannot mix tooling, policy, or unrelated file changes. Manifest and root
versions must move forward, and existing revocations cannot be removed or
weakened. A root transition and its live manifest must satisfy both the prior
and next thresholds.

The materializer validates the complete assembled input before writing the
worktree. It never invokes Git, signs, rebuilds, pretty-prints, or downloads
bytes. The release workflow has read-only repository permission and no secrets;
it compares the PR tree with its exact base and cannot push or merge.

## Recovery

Before merge, abandon the feature branch. After a non-security release error,
use another protected PR to restore live bytes from a verified immutable
archive while retaining all history. Root rotations and revocations never roll
back; recover with a higher signed version or keep clients fail closed.

GitHub Raw exposes protected `main` through the anonymous, stable HTTPS contract
in [`../docs/ORIGINS.md`](../docs/ORIGINS.md). The push-main verifier may only
read and compare those public bytes; it cannot publish or write back.

No object-storage bucket, custom Catalog domain, DNS record, publication
principal, production prefix, Kubernetes Service, HTTPRoute, or edge worker is
part of this release boundary.
