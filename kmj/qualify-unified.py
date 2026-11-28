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


def strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate fixture field")
        result[key] = value
    return result


def reject_constant(_):
    raise ValueError("invalid JSON constant")


def config(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as f:
        s = os.fstat(f.fileno())
        if not stat.S_ISREG(s.st_mode) or s.st_uid != os.getuid() or s.st_nlink != 1 or stat.S_IMODE(s.st_mode) != 0o600:
            raise ValueError("private fixture required")
        raw = f.read(8193)
    if len(raw) > 8192:
        raise ValueError("fixture too large")
    d = json.loads(raw, object_pairs_hook=strict_object,
                   parse_constant=reject_constant)
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


def check_message(client, uid, marker, message_id, recipient):
    status, data = client.uid("FETCH", uid, "(BODY.PEEK[])")
    require(status == "OK")
    payloads = [p[1] for p in data if isinstance(p, tuple) and len(p) == 2 and isinstance(p[1], bytes)]
    require(len(payloads) == 1 and len(payloads[0]) <= 65536)
    msg = email.message_from_bytes(payloads[0], policy=SMTP)
    require(msg["Message-ID"] == message_id and msg["To"] == recipient and msg["From"] == SENDER)
    body = msg.get_body(preferencelist=("plain",))
    require(body is not None and body.get_content().strip() == marker)


def witness(recipient):
    marker = "KMJ-qualification-" + secrets.token_hex(16)
    message_id = "<" + marker + "@example.test>"
    msg = EmailMessage(policy=SMTP)
    msg["From"], msg["To"], msg["Subject"], msg["Message-ID"] = SENDER, recipient, marker, message_id
    msg.set_content(marker)
    return marker, message_id, msg.as_bytes()


def deny_cross_credentials(client, recipient, other_password):
    try:
        status, _ = client.login(recipient, other_password)
    except imaplib.IMAP4.abort:
        # Disconnection is not proof of an authentication rejection.
        raise
    except imaplib.IMAP4.error as exc:
        # IMAP4.login raises error on tagged NO. Require an auth failure
        # response code, not a malformed command or unrelated error.
        require("[AUTHENTICATIONFAILED]" in str(exc).upper())
        return
    # Real imaplib raises on tagged NO. A bare return is not explicit
    # authentication-failure evidence; fail closed for unexpected adapters.
    raise ValueError("missing explicit authentication failure")


def check_mailbox(client, recipient, password, own, other):
    require(client.login(recipient, password)[0] == "OK")
    require(client.select("INBOX", readonly=True)[0] == "OK")
    marker, message_id, _ = own
    deadline = time.monotonic() + 20
    while True:
        require(client.noop()[0] == "OK")
        uids = locate(client, message_id)
        if uids or time.monotonic() >= deadline:
            break
        time.sleep(1)
    require(len(uids) == 1)
    check_message(client, uids[0], marker, message_id, recipient)
    require(locate(client, other[1]) == [])


def run(d):
    require(os.geteuid() != 0)
    ctx = ssl.create_default_context(cafile=d["ca_file"])
    a, b = witness(PRIMARY), witness(SECONDARY)
    # Literal loopback only. Fixture TLS certificate must contain IP SAN 127.0.0.1.
    with smtplib.SMTP("127.0.0.1", d["smtp_port"], timeout=10) as smtp:
        require(smtp.ehlo()[0] == 250)
        require(smtp.starttls(context=ctx)[0] == 220)
        require(smtp.ehlo()[0] == 250)
        rejected(smtp, UNKNOWN)
        rejected(smtp, RELAY)
        require(not smtp.sendmail(SENDER, [PRIMARY], a[2]))
        require(not smtp.sendmail(SENDER, [SECONDARY], b[2]))
    for recipient, password, other_password, own, other in (
        (PRIMARY, d["alpha_password"], d["beta_password"], a, b),
        (SECONDARY, d["beta_password"], d["alpha_password"], b, a),
    ):
        with imaplib.IMAP4_SSL("127.0.0.1", d["imap_port"], ssl_context=ctx, timeout=10) as client:
            deny_cross_credentials(client, recipient, other_password)
        with imaplib.IMAP4_SSL("127.0.0.1", d["imap_port"], ssl_context=ctx, timeout=10) as client:
            check_mailbox(client, recipient, password, own, other)
    return {"smtp_tls": "PASS", "unknown_recipient": "PASS", "unauthorized_relay": "PASS",
            "smtp_to_imap": "PASS", "recipient_identity": "PASS",
            "two_account_delivery": "PASS", "cross_account_inbox_absence": "PASS",
            "cross_account_password_rejection": "PASS",
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
