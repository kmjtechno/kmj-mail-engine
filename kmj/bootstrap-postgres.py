#!/usr/bin/env python3
"""Provision a fresh PostgreSQL-backed Community bootstrap in a private netns.

No production data, persistent service, external network, or published credentials.
Run only after compiling the reviewed Community candidate.
"""
import argparse
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time

CORE = "urn:ietf:params:jmap:core"
REGISTRY = "urn:stalwart:jmap"
DOMAIN = "kmj-qualification.test"
DB = "kmj_fixture"
ROLE = "kmj_fixture"


def require(condition):
    if not condition:
        raise ValueError("isolated PostgreSQL bootstrap assertion")


def check_namespace():
    require(os.geteuid() != 0)
    dev = Path("/proc/net/dev").read_text().splitlines()[2:]
    require({x.split(":", 1)[0].strip() for x in dev} == {"lo"})
    routes = Path("/proc/net/route").read_text().splitlines()[1:]
    require(all(x.split()[0] == "lo" for x in routes if x.strip()))
    require(all(x.split()[-1] == "lo" for x in
                Path("/proc/net/ipv6_route").read_text().splitlines() if x.strip()))


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    require(port >= 1024)
    return port


def private_run(argv, env, cwd, log, timeout=45):
    return subprocess.run(argv, env=env, cwd=cwd, stdin=subprocess.DEVNULL,
                          stdout=log, stderr=log, check=True, timeout=timeout)


def strict_object(pairs):
    result = {}
    for k, v in pairs:
        require(k not in result)
        result[k] = v
    return result


def reject_constant(_):
    raise ValueError("non-JSON numeric constant")


def parse_response(raw, method):
    result = json.loads(raw, object_pairs_hook=strict_object,
                        parse_constant=reject_constant)
    require(isinstance(result, dict))
    calls = result.get("methodResponses")
    require(isinstance(calls, list) and len(calls) == 1
            and isinstance(calls[0], list) and len(calls[0]) == 3
            and calls[0][0] == method and calls[0][2] == "bootstrap"
            and isinstance(calls[0][1], dict))
    return calls[0][1]


def rpc(port, token, method, args):
    require(type(port) is int and 1024 <= port <= 65535)
    require(method in ("x:Bootstrap/get", "x:Bootstrap/set"))
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=40)
    try:
        payload = {"using": [CORE, REGISTRY],
                   "methodCalls": [[method, args, "bootstrap"]]}
        conn.request("POST", "/jmap/", json.dumps(payload).encode(),
                     {"Authorization": "Basic " + token,
                      "Content-Type": "application/json", "Accept-Encoding": "identity"})
        response = conn.getresponse()
        require(response.status == 200)
        require(response.getheader("Content-Type", "").split(";", 1)[0].strip().lower()
                == "application/json")
        require(response.getheader("Content-Encoding", "identity").lower() == "identity")
        raw = response.read(262145)
        require(len(raw) <= 262144)
        return parse_response(raw, method)
    finally:
        conn.close()


def bootstrap(port, token, pg_port, root):
    current = rpc(port, token, "x:Bootstrap/get", {})
    rows = current.get("list")
    require(isinstance(rows, list) and len(rows) == 1
            and isinstance(rows[0], dict) and not current.get("notFound"))
    sid = rows[0].get("id")
    require(isinstance(sid, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,255}", sid))
    # Explicitly avoid upstream default ACME/DKIM work and /var/log paths.
    patch = {
        "defaultHostname": "mail." + DOMAIN,
        "defaultDomain": DOMAIN,
        "requestTlsCertificate": False,
        "generateDkimKeys": False,
        "dataStore": {"@type": "PostgreSql", "host": "127.0.0.1", "port": pg_port,
                      "database": DB, "authUsername": ROLE, "useTls": False,
                      "allowInvalidCerts": False, "poolMaxConnections": 4},
        "directory": {"@type": "Internal"},
        "dnsServer": {"@type": "Manual"},
        "tracer": {"@type": "Log", "path": str(root), "prefix": "fixture.log",
                   "enable": False},
    }
    result = rpc(port, token, "x:Bootstrap/set", {"update": {sid: patch}})
    for key in ("notUpdated", "notCreated", "notDestroyed", "created", "destroyed"):
        require(key not in result or result[key] in ({}, [], None))
    updated = result.get("updated")
    require(isinstance(updated, dict) and set(updated) == {sid})
    # The upstream bootstrap response may contain the generated administrator
    # secret. Never print, store, or return the response.
    admin = updated[sid]
    require(isinstance(admin, dict) and admin.get("username") == "admin@" + DOMAIN
            and isinstance(admin.get("secret"), str) and len(admin["secret"]) >= 16)


def run(binary, pgdir, expected_sha):
    check_namespace()
    binary = binary.resolve(strict=True)
    pgdir = pgdir.resolve(strict=True)
    require(binary.is_file() and os.access(binary, os.X_OK))
    with binary.open("rb") as f:
        require(hashlib.file_digest(f, "sha256").hexdigest() == expected_sha)
    for name in ("initdb", "pg_ctl", "createdb", "psql"):
        require((pgdir / name).is_file() and os.access(pgdir / name, os.X_OK))
    with tempfile.TemporaryDirectory(prefix="kmj-pg-bootstrap-") as tmp:
        root = Path(tmp)
        pgdata, conf = root / "pgdata", root / "config.json"
        pg_port, http_port = free_port(), free_port()
        require(pg_port != http_port)
        recovery_password = secrets.token_urlsafe(32)
        token = base64.b64encode(("admin:" + recovery_password).encode()).decode()
        env = {"PATH": "/usr/bin:/bin", "HOME": str(root), "TMPDIR": str(root),
               "LC_ALL": "C"}
        engine_env = {**env, "STALWART_HOSTNAME": "mail." + DOMAIN,
                      "STALWART_RECOVERY_MODE_BIND": "127.0.0.1",
                      "STALWART_RECOVERY_MODE_PORT": str(http_port),
                      "STALWART_RECOVERY_ADMIN": "admin:" + recovery_password}
        with (root / "private-pg.log").open("xb") as log, \
                (root / "private-engine.log").open("xb") as engine_log:
            private_run([str(pgdir / "initdb"), "-D", str(pgdata), "-U", ROLE,
                         "--auth-local=trust", "--auth-host=trust", "--no-locale",
                         "--encoding=UTF8"], env, root, log, 90)
            # Trust authentication is confined to this ephemeral loopback-only
            # namespace, with no production filesystem paths or credentials.
            options = f"-h 127.0.0.1 -p {pg_port} -k {root}"
            started, proc = False, None
            try:
                private_run([str(pgdir / "pg_ctl"), "-D", str(pgdata), "-l",
                             str(root / "postgres.log"), "-o", options, "-w", "start"],
                            env, root, log, 60)
                started = True
                db_args = ["-h", "127.0.0.1", "-p", str(pg_port), "-U", ROLE]
                private_run([str(pgdir / "createdb"), *db_args, DB], env, root, log)
                proc = subprocess.Popen([str(binary), "--config", str(conf)], cwd=root,
                                        env=engine_env, stdin=subprocess.DEVNULL,
                                        stdout=engine_log, stderr=engine_log,
                                        start_new_session=True)
                deadline = time.monotonic() + 45
                while True:
                    require(proc.poll() is None)
                    try:
                        with socket.create_connection(("127.0.0.1", http_port), timeout=1):
                            break
                    except OSError:
                        require(time.monotonic() < deadline)
                        time.sleep(0.5)
                bootstrap(http_port, token, pg_port, root)
                st = conf.stat()
                require(stat.S_ISREG(st.st_mode) and st.st_uid == os.getuid()
                        and stat.S_IMODE(st.st_mode) == 0o600)
                raw_config = conf.read_bytes()
                require(len(raw_config) <= 16384)
                config = json.loads(raw_config, object_pairs_hook=strict_object,
                                    parse_constant=reject_constant)
                require(isinstance(config, dict))
                require(config.get("@type") == "PostgreSql"
                        and config.get("host") == "127.0.0.1"
                        and config.get("port") == pg_port
                        and config.get("database") == DB)
                p = subprocess.run([str(pgdir / "psql"), *db_args, "-d", DB,
                                    "-X", "-A", "-t", "-v", "ON_ERROR_STOP=1",
                                    "-c", "SELECT count(*) FROM pg_catalog.pg_tables WHERE schemaname='public'"],
                                   cwd=root, env=env, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=log, timeout=20, check=True)
                require(p.stdout.strip().isdigit() and int(p.stdout.strip()) > 0)
                proc.send_signal(signal.SIGTERM)
                require(proc.wait(timeout=15) == 0)
            finally:
                if proc is not None and proc.poll() is None:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait(timeout=5)
                if started or (pgdata / "postmaster.pid").exists():
                    private_run([str(pgdir / "pg_ctl"), "-D", str(pgdata), "-m",
                                 "immediate", "-w", "stop"], env, root, log, 30)
    return {"postgres_bootstrap": "PASS", "config_readback": "PASS",
            "postgres_tables_present": "PASS", "scope": "DISPOSABLE_BOOTSTRAP_ONLY",
            "configured_restart_verified": False, "mail_delivery_verified": False,
            "production_ready": False}


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser()
    p.add_argument("binary", type=Path)
    p.add_argument("pg_bindir", type=Path)
    p.add_argument("--sha256", required=True)
    p.add_argument("--confirm", required=True,
                   choices=["FRESH_ISOLATED_POSTGRES_FIXTURE_ONLY"])
    a = p.parse_args()
    try:
        require(len(a.sha256) == 64 and all(c in "0123456789abcdef" for c in a.sha256))
        print(json.dumps(run(a.binary, a.pg_bindir, a.sha256), sort_keys=True))
    except Exception:
        print("KMJ_POSTGRES_BOOTSTRAP=FAIL", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
