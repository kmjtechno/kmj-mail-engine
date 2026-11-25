#!/usr/bin/env bash
# Build the explicit Community candidate only. No installation or service changes.
set -euo pipefail

if [[ $# -ne 0 || $EUID -eq 0 ]]; then
  echo 'KMJ_COMMUNITY_BUILD=REFUSED_EXPECT_UNPRIVILEGED_NO_ARGS' >&2
  exit 2
fi

cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
test -f Cargo.lock
test -f crates/main/Cargo.toml
command -v cargo >/dev/null
command -v git >/dev/null

if [[ -n "$(git status --porcelain --untracked-files=no)" ]]; then
  echo 'KMJ_COMMUNITY_BUILD=REFUSED_DIRTY_TRACKED_SOURCE' >&2
  exit 2
fi

features="$(mktemp)"
trap 'rm -f -- "$features"' EXIT
cargo tree --locked -p stalwart --no-default-features \
  --features postgres,rocks -e features --prefix none > "$features"

if grep -Eq 'feature "(enterprise|exchange|dev_mode)"' "$features"; then
  echo 'KMJ_COMMUNITY_BUILD=REFUSED_RESTRICTED_FEATURE' >&2
  exit 2
fi

printf 'SOURCE_SHA=%s\n' "$(git rev-parse HEAD)"
sha256sum Cargo.lock
cargo build --locked --release -p stalwart --no-default-features \
  --features postgres,rocks
test -x target/release/stalwart
version="$(target/release/stalwart --version)"
[[ "$version" =~ ^KMJ\ Mail\ Engine\ [0-9]+\.[0-9]+\.[0-9]+$ ]]
test "$(target/release/stalwart --kmj-version)" = "$version"
test "$(target/release/stalwart -V)" = "$version"
# Separate downstream package name; upstream executable remains intact.
install -d -m 0755 target/kmj-community
install -m 0755 target/release/stalwart target/kmj-community/kmj-mail-engine
test "$(target/kmj-community/kmj-mail-engine --version)" = "$version"
target/kmj-community/kmj-mail-engine --version
sha256sum target/kmj-community/kmj-mail-engine
echo 'KMJ_COMMUNITY_BUILD=COMPLETE_NOT_DEPLOYED'
