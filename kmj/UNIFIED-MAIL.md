# One authoritative KMJ Mail Engine

Use one authoritative SMTP submission/receiving engine and one mailbox store with a single product dashboard. This downstream Stalwart Community candidate is the intended replacement only after qualification. Do not deploy it alongside another authoritative production mail server, dual-write mail, or forward to third-party consumer accounts. Existing production delivery remains authoritative until a separately approved migration. Do not copy private integration configuration, user addresses, credentials, or operational details into this repository.

## Upstream reference choices

- Stalwart Community is the engine baseline: SMTP, IMAP, JMAP, filtering and authentication. Preserve AGPL corresponding source obligations and third-party notices; do not enable SEL-only features.
- Rspamd (Apache-2.0), Mailu (MIT for project configuration), and docker-mailserver are reference projects for filtering, administration and deployment acceptance, not additional production engines. Respect each file's license if importing anything. No third-party code is copied in this change.

## Isolated acceptance

Provision a disposable loopback-only Community instance with no external egress, a private test CA and a TLS server certificate containing IP SAN 127.0.0.1. Bind distinct high SMTP STARTTLS and IMAP TLS ports; enable unauthenticated inbound only for the synthetic domain kmj-qualification.test and prohibit relay. Provision alpha@kmj-qualification.test and beta@kmj-qualification.test with distinct random test credentials. The unknown recipient must be absent. Run as an unprivileged test user, with a private mode-0600 JSON file containing exactly smtp_port, imap_port, alpha_password, beta_password, ca_file. No production config or credentials. The fixture instance must be isolated from all production storage.

Run python3 kmj/qualify-unified.py /path/to/private-fixture.json --confirm DISPOSABLE_KMJ_TEST_ACCOUNTS_ONLY. It sends one distinct synthetic message to each account over verified TLS, rejects unknown RCPT and external relay, verifies each mailbox's own message and body, checks absence of the other account's message in both directions, and requires cross-account password rejection before positive login. This is scoped Inbox isolation evidence, not comprehensive ACL or brute-force qualification. The disposable fixture must return tagged authentication failure for invalid passwords and allow the subsequent legitimate login. The runner refuses root execution before TLS/network access, rejects duplicate JSON fixture fields, and requires explicit IMAP authentication-failure evidence (not a generic NO or disconnect). The script does not delete or purge mail; destroy the disposable instance separately. Offline unit tests exercise input validation and negative checks, not real delivery. A successful run is synthetic protocol evidence only, not a production readiness verdict.

## Mandatory remaining gates

Exact signed candidate and build reproducibility; license/SBOM and vulnerability review; isolated PostgreSQL, JMAP read/write and submission acceptance; MIME/attachment limits, malware/spam and phishing handling, authentication and tenant ACLs, quota and queue retry/bounce; import/export reconciliation and restore drill; private connector and one UI; test signed-link transactional mail and external delivery/TLS/SPF/DKIM/DMARC. Migration must reconcile message identity, folders, flags, sender/recipient, attachments, queue and counts; prevent dual delivery; retain rollback evidence and require separate owner-approved cutover. No production install or DNS action by this repository's CI.

Merged main pushes also execute the Community build and offline contracts on the exact merge SHA. Green PR-head results alone are not evidence for a different combined source tree. No binary is published or signed by CI.
