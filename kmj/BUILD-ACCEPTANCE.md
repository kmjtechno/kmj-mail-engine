# KMJ Community candidate acceptance

The read-only GitHub Actions build job compiles the exact PR head in a disposable standard Linux runner. No repository write token, secrets, publication, signing, production installation or deployment are involved. It verifies real executable output for both version switches and records compiler and binary SHA-256. It uses the current stable Rust toolchain and is not yet a reproducibility attestation. Signing and deployment are reserved for the owner-approved release host.

The build must use locked dependency versions and the explicit postgres,rocks feature set with no defaults. Failure, cancellation or timeout means the candidate is not qualified. Do not infer compile success from a source-contract or scanner pass.

Additional acceptance remains: license and dependency audit, isolated database bootstrap, protocol session and mailbox access, security and delivery, backup and restore, and guarded rollout. Public-facing branding audit must review inherited Community UI/help/log/banner surfaces without bypassing any Enterprise licensing controls. Original attribution remains in legal notices and source.

No unsigned CI artifact is published. No public mail settings or secrets are included.

## Preliminary dependency inventory (not a license approval)

In a disposable unprivileged checkout using the same reviewed target and locked Community feature set, collect Cargo metadata as a local file. Run `python3 kmj/dependency-inventory.py <metadata.json>` against that file. Only use metadata from the exact candidate and record the Cargo invocation, target, source SHA, lockfile hash and inventory hash together. Do not treat metadata resolved for unrelated workspace feature sets as candidate-specific evidence. The helper traverses the engine's reachable normal/build dependencies, excludes exclusively dev edges, rejects known restricted features, flags missing license expressions, and omits source URLs and local paths. Cargo feature unification can conservatively include additional dependencies; investigate any mismatch instead of suppressing it. The output is preliminary inventory, not a standard SBOM, vulnerability result, license compatibility decision or authorization to ship. Inspect the actual distribution and notices separately. Keep local metadata and any private URLs off public logs.

Offline synthetic regressions: `python3 -B -m unittest discover -s kmj -p 'test_dependency_inventory.py'`.
