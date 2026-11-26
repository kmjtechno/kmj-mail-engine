# PostgreSQL bootstrap fixture — implementation candidate

This opt-in helper targets the pinned upstream v1.2.0 registry bootstrap contract (`crates/jmap/src/registry/mapping/bootstrap.rs`, `crates/registry/src/schema/structs.rs`, `crates/store/src/registry/local.rs`). It provisions a fresh local PostgreSQL instance and updates the bootstrap singleton via the actual registry API. It asserts the private PostgreSQL config readback and real table creation, stops both processes, and destroys the temporary fixture. It deliberately does not claim configured restart, TLS, accounts, SMTP/IMAP/JMAP delivery or production readiness.

Run only on a disposable Linux runner, after reviewed Community build and bootstrap smoke. PostgreSQL binaries must already be installed. Supply the exact independently recorded Community executable SHA-256 and PostgreSQL binary directory. Create a fresh network namespace with only loopback, drop to an unprivileged disposable user before running. The fixture uses local PostgreSQL trust only within that namespace; never replicate it for production. All logs and generated recovery/admin credentials remain inside the fixture. Example (replace placeholders with actual reviewed paths and hash):

    sudo unshare --net --fork bash -c '
      set -euo pipefail
      ip link set lo up
      exec runuser -u "$1" -- env -i PATH=/usr/bin:/bin /usr/bin/python3 -B "$2" "$3" "$4" --sha256 "$5" --confirm FRESH_ISOLATED_POSTGRES_FIXTURE_ONLY
    ' kmj "$USER" "$PWD/kmj/bootstrap-postgres.py" "$PWD/target/kmj-community/kmj-mail-engine" "$(pg_config --bindir)" REVIEWED_SHA256

Status: source candidate only. Do not execute on Elite production. First validate the bootstrap API and database lifecycle in isolated CI; then qualify configured restart, test account provisioning, listeners and the existing protocol probes. No deployment or production changes.
