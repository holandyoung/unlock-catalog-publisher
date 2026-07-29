# Synthetic signature fragments

Owner: test maintainers.

T07 tests independently produce three fragments from clearly labeled,
deterministic test providers in temporary directories. This directory records
the fixture boundary only: no seed, encrypted provider, passphrase, recovery
material, or production key is checked in.

Generated fragments contain public test output only and have exactly three
fields: `requestDigest`, `keyId`, and `signature`. The focused signing tests
verify that fragments for different request digests or duplicate public key
material cannot be combined.
