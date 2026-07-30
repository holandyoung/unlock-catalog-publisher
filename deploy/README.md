# Release boundary

Owner: release operators.

This directory records the public repository boundary and protected release
policy. It must not contain credentials, signing material, private account
identifiers, or platform runtime dependencies.

`policy.md` defines the protected Git transaction. `repository.yaml` records
only public repository metadata, including the anonymous GitHub Raw BaseURL
template. `mirrors.yaml` records the provider-neutral exact-byte replication
policy and the reviewed public mirror inventory; an empty inventory authorizes
no live destination. The full transport contract is in
[`../docs/ORIGINS.md`](../docs/ORIGINS.md).
