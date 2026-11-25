# KMJ Community candidate acceptance

The read-only GitHub Actions build job compiles the exact PR head in a disposable standard Linux runner. No repository write token, secrets, publication, signing, production installation or deployment are involved. It verifies real executable output for both version switches and records compiler and binary SHA-256. It uses the current stable Rust toolchain and is not yet a reproducibility attestation. Signing and deployment are reserved for the owner-approved release host.

The build must use locked dependency versions and the explicit postgres,rocks feature set with no defaults. Failure, cancellation or timeout means the candidate is not qualified. Do not infer compile success from a source-contract or scanner pass.

Additional acceptance remains: license and dependency audit, isolated database bootstrap, protocol session and mailbox access, security and delivery, backup and restore, and guarded rollout. Public-facing branding audit must review inherited Community UI/help/log/banner surfaces without bypassing any Enterprise licensing controls. Original attribution remains in legal notices and source.

No unsigned CI artifact is published. No public mail settings or secrets are included.
