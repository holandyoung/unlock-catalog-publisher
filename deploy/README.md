# Deployment boundary

Owner: release operators.

This directory owns publication-side policy and public production-boundary
configuration. It must not contain live credentials, signing material, private
account identifiers, or platform runtime dependencies.

policy.md defines the implemented conditional object-store transaction.
Production resource facts remain absent until they are independently observed
and recorded by the external ownership gate.
