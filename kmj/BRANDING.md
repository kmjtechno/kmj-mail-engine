# KMJ downstream product identity

The product name is **KMJ Mail Engine**, vendor **KMJ TECHNO**, edition **Community**. The downstream package executable is `kmj-mail-engine`; `--version`, `-V`, and `--kmj-version` report only the KMJ product name and version offline. Other CLI behavior and the internal upstream executable target remain unchanged. Upstream attribution is separated into `UPSTREAM-NOTICES.md` and original license files. The proposed systemd service name is reserved in the product manifest, not installed. No logo assets are substituted in this change. Other inherited visible surfaces (help, logs, bootstrap, web administration and protocol banners) are not yet audited or rebranded; review Community-licensed surfaces independently, never override Enterprise entitlements.

This is an independently maintained downstream build. Do not imply Stalwart Labs endorses or supports it. Preserve upstream copyright, license texts and attribution. Do not modify Enterprise branding entitlement or license checks, and do not distribute SEL-only code as AGPL. Any future package must include appropriate license notices and corresponding source availability; a binary filename is not a complete license-compliance mechanism.

Customer-facing webmail and control-center branding will be implemented in the separate KMJ application through standard APIs. Do not import private platform source or secrets into this public fork. Do not rebrand protocol identifiers, cryptographic formats, storage schemas, telemetry or standard API names merely for appearance.

Status: downstream identity source and package naming only. Build/runtime verification and deployment are separate gates.
