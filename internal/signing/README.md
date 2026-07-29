# signing

Owner: offline signing operators.

This package owns complete read-only candidate validation, the `KeyProvider`
interface, the encrypted-file fallback, and pre-assembly fragment guards. It has
no network, shell, helper-execution, assembly, deployment, or key-generation
capability.

Tests create clearly labeled deterministic Ed25519 material only inside Go test
processes and temporary directories. They do not print or commit seed,
passphrase, or decrypted provider bytes.
