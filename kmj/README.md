# KMJ Mail Engine — Community build foundation

This downstream fork of Stalwart preserves upstream authorship, notices, license files and history. It is not an upstream contribution. Initial pinned baseline: upstream v1.2.0 commit b2d3df9a9b1c3e0cd1d5ccccc16acd6f44381afa. The upstream release archive used for initial qualification has SHA-256 ee79b1552acc3c89e4354405c7a716874826e4db7537a4b32c7b1677e08688c8.

## Build policy

The upstream main crate's default features include enterprise. Downstream builds must explicitly disable defaults and select only reviewed Community features. The first candidate uses PostgreSQL and RocksDB (the latter for isolated qualification/fallback); no enterprise, exchange, or dev_mode feature is requested. The build helper checks Cargo's resolved feature tree as a preliminary gate, not a substitute for license/SBOM review or binary acceptance.

From an unprivileged development account in a disposable checkout, run `bash kmj/build-community.sh`. Rust and system build dependencies must already be available; this command does not install packages or start a service. Locked dependencies may require network downloads. No release publishing, signing, service configuration or deployment is performed. Do not build on the production service account.

## Release gates

- Record upstream commit, exact downstream source and dependency lock hashes; review every upstream update and security advisory.
- Review AGPL-3.0-only and SEL boundaries and dependency licenses; preserve all notices and offer corresponding source to network users of modified AGPL engine. No enterprise-only feature bypass. Product-specific frontend communicates over standard protocols.
- Reproducible build evidence, software bill of materials, vulnerability review, artifact hashes and owner-authorized signing.
- Isolated PostgreSQL and JMAP/SMTP/IMAP acceptance, two-account authorization, spam/relay denial, quota, recovery, and duplicate handling.
- Separate guarded production deployment with rollback and independent external delivery verification.

No organization-specific configuration, mailbox data, credentials, internal URLs or private integration source may be committed to this public repository. Report verified issues through appropriate upstream channels in accordance with upstream policies; do not automatically send LLM-generated upstream reports. Existing upstream source and branding are unchanged in this first foundation.

Status: source only; build and protocol acceptance are not yet executed.
