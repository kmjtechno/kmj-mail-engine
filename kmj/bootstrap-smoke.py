#!/usr/bin/env python3
"""Actual Community binary startup in a disposable Linux network namespace."""
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import time


class SmokeFailure(Exception):
    """Only fixed public stage labels, never arbitrary exception text."""


def require(value, stage):
    if not value:
        raise SmokeFailure(stage)


def isolated():
    require(os.geteuid() != 0, "UNPRIVILEGED")
    # /proc/net reflects the current network namespace, not host interfaces.
    interfaces = {line.split(":", 1)[0].strip()
                  for line in Path("/proc/net/dev").read_text().splitlines()[2:]}
    require(interfaces == {"lo"}, "LOOPBACK_INTERFACES")
    routes = Path("/proc/net/route").read_text().splitlines()
    require(all(row.split()[0] == "lo" for row in routes[1:] if row.strip()), "IPV4_ROUTES")
    require(not any(line.split()[-1] != "lo"
                    for line in Path("/proc/net/ipv6_route").read_text().splitlines()
                    if line.strip()), "IPV6_ROUTES")


def http_get(port, path):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
    try:
        conn.request("GET", path)
        response = conn.getresponse()
        body = response.read(131073)
        require(len(body) <= 131072, "HTTP_RESPONSE_BOUND")
        return response.status, response.getheader("Location"), body
    finally:
        conn.close()


def run(binary):
    isolated()
    binary = binary.resolve(strict=True)
    require(binary.is_file() and os.access(binary, os.X_OK), "BINARY_EXECUTABLE")
    with binary.open("rb") as f:
        digest = hashlib.file_digest(f, "sha256").hexdigest()
    with tempfile.TemporaryDirectory(prefix="kmj-bootstrap-") as tmp:
        root = Path(tmp)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        require(port >= 1024, "HIGH_PORT")
        # Fresh absent config enters the pinned upstream bootstrap mode.
        # Never inherit production env, credentials, HOME or config.
        env = {"PATH": "/usr/bin:/bin", "HOME": str(root), "TMPDIR": str(root),
               "STALWART_HOSTNAME": "kmj-bootstrap.test",
               "STALWART_RECOVERY_MODE_BIND": "127.0.0.1",
               "STALWART_RECOVERY_MODE_PORT": str(port),
               "STALWART_RECOVERY_ADMIN": "admin:" + secrets.token_urlsafe(32)}
        config = root / "config.json"
        require(not config.exists(), "FRESH_CONFIG")
        print("KMJ_BOOTSTRAP_PREFLIGHT=PASS", flush=True)
        log_path = root / "private-startup.log"
        with log_path.open("xb") as log:
            proc = subprocess.Popen([str(binary), "--config", str(config)],
                                    cwd=root, env=env, stdout=log, stderr=log,
                                    stdin=subprocess.DEVNULL, start_new_session=True)
            try:
                deadline = time.monotonic() + 45
                while True:
                    if proc.poll() is not None:
                        # Fixed classification only; log lines may contain credentials.
                        log.flush()
                        with log_path.open("rb") as private_log:
                            raw = private_log.read(65536).lower()
                        for marker, category in (
                            (b"unsupported database schema version", "SCHEMA_VERSION"),
                            (b"permission denied", "PERMISSION"),
                            (b"address already in use", "ADDRESS_IN_USE"),
                            (b"startup failed", "STARTUP_FAILED"),
                            (b"panicked at", "PANIC"),
                        ):
                            if marker in raw:
                                raise SmokeFailure("PROCESS_EXIT_" + category)
                        raise SmokeFailure("PROCESS_EXIT_UNCLASSIFIED")
                    try:
                        status, location, _ = http_get(port, "/.well-known/jmap")
                    except (OSError, http.client.HTTPException):
                        require(time.monotonic() < deadline, "LISTENER_TIMEOUT")
                        time.sleep(0.5)
                        continue
                    require(status == 307, "DISCOVERY_HTTP_" + str(status))
                    require(location == "/jmap/session", "DISCOVERY_LOCATION")
                    break
                status, _, body = http_get(port, "/jmap/session")
                require(status == 200, "SESSION_HTTP_" + str(status))
                try:
                    session = json.loads(body)
                except (ValueError, UnicodeError):
                    raise SmokeFailure("SESSION_JSON") from None
                require(isinstance(session, dict), "SESSION_OBJECT")
                require(isinstance(session.get("accounts"), dict) and not session["accounts"], "ANONYMOUS_ACCOUNTS")
                require(isinstance(session.get("capabilities"), dict), "SESSION_CAPABILITIES")
                require("urn:ietf:params:jmap:core" in session["capabilities"], "CORE_CAPABILITY")
                require(proc.poll() is None, "PROCESS_ALIVE")
                proc.send_signal(signal.SIGTERM)
                require(proc.wait(timeout=15) == 0, "GRACEFUL_SHUTDOWN")
            finally:
                if proc.poll() is None:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait(timeout=5)
        # Never emit bootstrap log, generated credential or fixture state.
    return {"binary_sha256": digest, "bootstrap_listener": "PASS",
            "jmap_discovery": "PASS", "anonymous_account_disclosure": "PASS",
            "graceful_shutdown": "PASS", "scope": "ISOLATED_BOOTSTRAP_ONLY",
            "mailbox_delivery_verified": False, "production_ready": False}


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser()
    p.add_argument("binary", type=Path)
    args = p.parse_args()
    try:
        print(json.dumps(run(args.binary), sort_keys=True))
        return 0
    except SmokeFailure as exc:
        print("KMJ_BOOTSTRAP_SMOKE=FAIL:" + str(exc), file=sys.stderr)
        return 1
    except Exception:
        print("KMJ_BOOTSTRAP_SMOKE=FAIL:UNCLASSIFIED_EXCEPTION", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
