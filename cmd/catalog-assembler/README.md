# catalog-assembler

Owner: release operators.

This directory owns assembly of independently produced signature fragments. It must not access signing material, alter canonical candidate payloads, or publish live resources.

`catalog-assembler root` creates a public R1-to-R2 signed bridge only after the
old and new 2-of-3 thresholds and the 90-day compatibility window pass.
`catalog-assembler release` revalidates the candidate, exact source identity,
permissions, public roots, manifest fragments, and prior revocations before it
atomically writes the release tree and deterministic package.

Both commands accept file paths only. They expose no signing command, key
provider, network operation, deploy credential, or overwrite mode.
