# Release boundary

Owner: release operators.

This directory records the public repository boundary and protected release
policy. It must not contain credentials, signing material, private account
identifiers, online origin configuration, or platform runtime dependencies.

`policy.md` defines the protected Git transaction. `repository.yaml` records
only public repository metadata; it does not enable GitHub raw as a supported
subscription origin.
