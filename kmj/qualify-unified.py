#!/usr/bin/env python3
"""Opt-in isolated two-account SMTP/IMAP acceptance. Never targets production."""
import argparse
import email
import imaplib
import json
import os
import re
import secrets
import smtplib
import ssl
import stat
import sys
import time
from email.message import EmailMessage
from email.policy import SMTP

DOMAIN = "kmj-qualification.test"
PRIMARY = "alpha@" + DOMAIN
SECONDARY = "beta@" + DOMAIN
UNKNOWN = "unknown@" + DOMAIN
SENDER = "sender@example.test"
RELAY = "relay@example.invalid"


def config(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as f:
        s = os.fstat(f.fileno())
        if not stat.S_ISREG(s.st_mode) or s.st_uid != os.getuid() or s.st_nlink != 1 or stat.S_IMODE(s.st_mode) != 0o600:
            raise ValueError("private fixture required")
        raw = f.read(8193)
    if len(raw) > 8192:
        raise ValueError("fixture too large")
    d = json.loads(raw)
    if not isinstance(d, dict) or set(d) != {"smtp_port", "imap_port", "alpha_password", "beta_password", "ca_file"}:
        raise ValueError("fixture schema")
    for name in ("smtp_port", "imap_port"):
        if type(d[name]) is not int or not 1024 <= d[name] <= 65535:
            raise ValueError("high test ports only")
    if d["smtp_port"] == d["imap_port"]:
        raise ValueError("distinct listeners required")
    for name in ("alpha_password", "beta_password"):
        if not isinstance(d[name], str) or not 16 <= len(d[name]) <= 256 or any(ord(c) < 32 or ord(c) > 126 for c in d[name]):
            raise ValueError("test password format")
    if d["alpha_password"] == d["beta_password"]:
        raise ValueError("separate account credentials required")
    if not isinstance(d["ca_file"], str) or not os.path.isfile(d["ca_file"]):
        raise ValueError("fixture CA required")
    return d


def require(condition):
    if not condition:
        raise ValueError("qualification assertion")


def rejected(smtp, address):
    require(smtp.mail(SENDER)[0] == 250)
    code, _ = smtp.rcpt(address)
    require(500 <= code <= 599)
    require(smtp.rset()[0] == 250)


def locate(client, message_id):
    status, data = client.uid("SEARCH", None, "HEADER", "Message-ID", '"'+message_id+'"')
    require(status == "OK" and isinstance(data, list) and len(data) == 1 and isinstance(data[0], bytes))
    uids = data[0].split()
    require(all(re.fullmatch(rb"[1-9][0-9]*", uid) for uid in uids))
    return uids


def check_message(client, uid, marker, message_id):
    status, data = client.uid("FETCH", uid, "(BODY.PEEK[])")
    require(status == "OK")
    payloads = [p[1] for p in data if isinstance(p, tuple) and len(p) == 2 and isinstance(p[1], bytes)]
    require(len(payloads) == 1 and len(payloads[0]) <= 65536)
    msg = email.message_from_bytes(payloads[0], policy=SMTP)
    require(msg["Message-ID"] == message_id and msg["To"] == PRIMARY and msg["From"] == SENDER)
    body = msg.get_body(preferencelist=("plain",))
    require(body is not None and body.get_content().strip() == marker)


def run(d):
    ctx = ssl.create_default_context(cafile=d["ca_file"])
    marker = "KMJ-qualification-" + secrets.token_hex(16)
    message_id = "<" + marker + "@example.test>"
    msg = EmailMessage(policy=SMTP)
    msg["From"], msg["To"], msg["Subject"], msg["Message-ID"] = SENDER, PRIMARY, marker, message_id
    msg.set_content(marker)
    # Literal loopback only. Fixture TLS certificate must contain IP SAN 127.0.0.1.
    with smtplib.SMTP("127.0.0.1", d["smtp_port"], timeout=10) as smtp:
        require(smtp.ehlo()[0] == 250)
        require(smtp.starttls(context=ctx)[0] == 220)
        require(smtp.ehlo()[0] == 250)
        rejected(smtp, UNKNOWN)
        rejected(smtp, RELAY)
        require(not smtp.sendmail(SENDER, [PRIMARY], msg.as_bytes()))
    with imaplib.IMAP4_SSL("127.0.0.1", d["imap_port"], ssl_context=ctx, timeout=10) as a:
        require(a.login(PRIMARY, d["alpha_password"])[0] == "OK")
        require(a.select("INBOX", readonly=True)[0] == "OK")
        deadline = time.monotonic() + 20
        while True:
            a.noop()
            uids = locate(a, message_id)
            if uids or time.monotonic() >= deadline:
                break
            time.sleep(1)
        require(len(uids) == 1)
        check_message(a, uids[0], marker, message_id)
    with imaplib.IMAP4_SSL("127.0.0.1", d["imap_port"], ssl_context=ctx, timeout=10) as b:
        require(b.login(SECONDARY, d["beta_password"])[0] == "OK")
        require(b.select("INBOX", readonly=True)[0] == "OK")
        require(locate(b, message_id) == [])
    return {"smtp_tls": "PASS", "unknown_recipient": "PASS", "unauthorized_relay": "PASS",
            "smtp_to_imap": "PASS", "recipient_identity": "PASS", "second_account_inbox_absence": "PASS",
            "scope": "ISOLATED_SYNTHETIC_ONLY", "production_ready": False}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("fixture")
    parser.add_argument("--confirm", required=True, choices=["DISPOSABLE_KMJ_TEST_ACCOUNTS_ONLY"])
    args = parser.parse_args()
    try:
        print(json.dumps(run(config(args.fixture)), sort_keys=True))
    except Exception:
        print("ISOLATED_PROTOCOL_QUALIFICATION=FAIL", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
