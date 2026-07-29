# catalog-signer

Owner: offline signing operators.

This directory owns offline candidate revalidation and signature-fragment
production. Its only allowlisted commands are:

- `inspect --candidate DIR`
- `sign --candidate DIR --expect-request-digest SHA256 --encrypted-key FILE --passphrase-file FILE --output FILE`

`inspect` returns source ID, version, request digest, payload digest, and object
count. `sign` repeats the same validation, decrypts one age scrypt provider, and
creates a new fragment containing exactly:

```json
{"requestDigest":"...","keyId":"...","signature":"..."}
```

The encrypted provider and passphrase files must be owner-only,
non-executable regular files with no symlink in their path. Candidate files and
directories must be `0644`/`0755`. Secure access requires Linux `openat2` with
no-symlink resolution. The output path must be outside the candidate and must
not exist; publication is atomic and never overwrites an existing fragment.

The operator obtains the expected request digest from a separately reviewed
`inspect` run. `sign` prepares one immutable in-memory candidate, compares the
expected digest, then opens the provider and signs only the pinned canonical
payload.

This command must run as a short-lived process in a network-denied offline
environment. It does not build or mutate candidates, generate keys, invoke a
shell, execute helpers or artifacts, assemble fragments, access a network, or
deploy bytes. Real signing material and passphrases must never enter this
repository, CI, logs, fixtures, or command arguments.
