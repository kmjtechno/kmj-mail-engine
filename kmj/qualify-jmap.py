#!/usr/bin/env python3
"""Read-only JMAP mailbox ACL qualification against a disposable TLS fixture."""
import argparse
import base64
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import smtplib
import ssl
import stat
import sys
import time
from email.message import EmailMessage
from email.policy import SMTP

CORE = "urn:ietf:params:jmap:core"
MAIL = "urn:ietf:params:jmap:mail"
ALPHA = "alpha@kmj-qualification.test"
BETA = "beta@kmj-qualification.test"
SENDER = "sender@example.test"
MAX_RESPONSE = 262144
OPAQUE_ID = re.compile(r"[A-Za-z0-9_-]{1,255}\Z")


def require(value):
    if not value:
        raise ValueError("JMAP qualification assertion")


def strict_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def parse_json(raw):
    return json.loads(raw, object_pairs_hook=strict_object,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid constant")))


def config(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as f:
        s = os.fstat(f.fileno())
        require(stat.S_ISREG(s.st_mode) and s.st_uid == os.getuid()
                and s.st_nlink == 1 and stat.S_IMODE(s.st_mode) == 0o600)
        raw = f.read(8193)
    require(len(raw) <= 8192)
    d = parse_json(raw)
    require(isinstance(d, dict) and set(d) == {
        "smtp_port", "jmap_port", "alpha_password", "beta_password", "ca_file"})
    for k in ("smtp_port", "jmap_port"):
        require(type(d[k]) is int and 1024 <= d[k] <= 65535)
    require(d["smtp_port"] != d["jmap_port"])
    for k in ("alpha_password", "beta_password"):
        require(isinstance(d[k], str) and 16 <= len(d[k]) <= 256
                and all(32 <= ord(c) <= 126 for c in d[k]))
    require(d["alpha_password"] != d["beta_password"])
    require(isinstance(d["ca_file"], str) and Path(d["ca_file"]).is_file())
    return d


def request(ctx, port, username, password, method, path, payload=None):
    require(username in (ALPHA, BETA))
    require((method, path) in (("GET", "/jmap/session"), ("POST", "/jmap/")))
    token = base64.b64encode((username + ":" + password).encode("ascii")).decode("ascii")
    conn = http.client.HTTPSConnection("127.0.0.1", port, context=ctx, timeout=10)
    try:
        conn.request(method, path, body=None if payload is None else
                     json.dumps(payload).encode("utf-8"), headers={
                         "Authorization": "Basic " + token,
                         "Accept": "application/json",
                         "Content-Type": "application/json",
                         "Accept-Encoding": "identity"})
        resp = conn.getresponse()
        # No redirects, compression, unbounded reads or discovered external URLs.
        require(resp.status == 200)
        require(resp.getheader("Content-Type", "").split(";", 1)[0].strip().lower()
                == "application/json")
        require(resp.getheader("Content-Encoding", "identity").lower() == "identity")
        raw = resp.read(MAX_RESPONSE + 1)
        require(len(raw) <= MAX_RESPONSE)
        data = parse_json(raw)
        require(isinstance(data, dict))
        return data
    finally:
        conn.close()


def account(session):
    caps = session.get("capabilities")
    require(isinstance(caps, dict) and CORE in caps and MAIL in caps)
    primary, accounts = session.get("primaryAccounts"), session.get("accounts")
    require(isinstance(primary, dict) and isinstance(accounts, dict))
    aid = primary.get(MAIL)
    require(isinstance(aid, str) and OPAQUE_ID.fullmatch(aid))
    require(set(accounts) == {aid})
    own = accounts[aid]
    require(isinstance(own, dict) and own.get("isPersonal") is True)
    require(isinstance(own.get("accountCapabilities"), dict)
            and MAIL in own["accountCapabilities"])
    return aid


def call(client, name, args):
    response = client("POST", "/jmap/", {
        "using": [CORE, MAIL], "methodCalls": [[name, args, "witness"]]})
    methods = response.get("methodResponses")
    require(isinstance(methods, list) and len(methods) == 1)
    row = methods[0]
    require(isinstance(row, list) and len(row) == 3 and row[2] == "witness"
            and isinstance(row[1], dict))
    return row[0], row[1]


def get_ids(client, aid, subject):
    method, data = call(client, "Email/query", {
        "accountId": aid, "filter": {"subject": subject}, "limit": 2})
    require(method == "Email/query" and data.get("accountId") == aid)
    ids = data.get("ids")
    require(isinstance(ids, list) and len(ids) <= 2
            and all(isinstance(x, str) and OPAQUE_ID.fullmatch(x) for x in ids))
    return ids


def own_message(client, aid, subject, recipient, msg_id):
    deadline = time.monotonic() + 30
    while True:
        ids = get_ids(client, aid, subject)
        if ids or time.monotonic() >= deadline:
            break
        time.sleep(1)
    require(len(ids) == 1)
    method, data = call(client, "Email/get", {
        "accountId": aid, "ids": ids,
        "properties": ["id", "subject", "messageId", "from", "to"]})
    require(method == "Email/get" and data.get("accountId") == aid)
    require(data.get("notFound") == [] and isinstance(data.get("list"), list)
            and len(data["list"]) == 1)
    item = data["list"][0]
    require(isinstance(item, dict) and item.get("id") == ids[0]
            and item.get("subject") == subject and item.get("messageId") == [msg_id])
    for field, address in (("from", SENDER), ("to", recipient)):
        values = item.get(field)
        require(isinstance(values, list) and len(values) == 1
                and isinstance(values[0], dict) and values[0].get("email") == address)
    return ids[0]


def deny_cross_account(client, other_aid, other_id):
    method, data = call(client, "Email/get", {
        "accountId": other_aid, "ids": [other_id], "properties": ["id", "subject"]})
    # Do not mistake a transport error, malformed response, unrelated method
    # error or successful empty result for explicit account-access denial.
    require(method == "error" and data.get("type") in ("forbidden", "accountNotFound"))
    require(not any(k in data for k in ("list", "ids", "notFound")))


def run(d):
    require(os.geteuid() != 0)
    ctx = ssl.create_default_context(cafile=d["ca_file"])
    # Only synthetic recipients and literal loopback, never discovered URLs.
    subjects, msg_ids = {}, {}
    with smtplib.SMTP("127.0.0.1", d["smtp_port"], timeout=10) as smtp:
        require(smtp.ehlo()[0] == 250)
        require(smtp.starttls(context=ctx)[0] == 220)
        require(smtp.ehlo()[0] == 250)
        for recipient in (ALPHA, BETA):
            nonce = secrets.token_hex(16)
            subjects[recipient] = "KMJ JMAP " + nonce
            msg_ids[recipient] = nonce + "@example.test"
            msg = EmailMessage(policy=SMTP)
            msg["From"], msg["To"], msg["Subject"] = SENDER, recipient, subjects[recipient]
            msg["Message-ID"] = "<" + msg_ids[recipient] + ">"
            msg.set_content("Synthetic isolated mailbox test " + nonce)
            require(not smtp.sendmail(SENDER, [recipient], msg.as_bytes()))
    clients, accounts, messages = {}, {}, {}
    for user, password in ((ALPHA, d["alpha_password"]), (BETA, d["beta_password"])):
        def client(method, path, payload=None, user=user, password=password):
            return request(ctx, d["jmap_port"], user, password, method, path, payload)
        clients[user] = client
        accounts[user] = account(client("GET", "/jmap/session"))
    require(accounts[ALPHA] != accounts[BETA])
    for user, other in ((ALPHA, BETA), (BETA, ALPHA)):
        messages[user] = own_message(clients[user], accounts[user], subjects[user],
                                     user, msg_ids[user])
        require(get_ids(clients[user], accounts[user], subjects[other]) == [])
    for user, other in ((ALPHA, BETA), (BETA, ALPHA)):
        deny_cross_account(clients[user], accounts[other], messages[other])
    return {"jmap_tls": "PASS", "two_account_session_isolation": "PASS",
            "smtp_to_jmap": "PASS", "recipient_and_message_identity": "PASS",
            "cross_account_query_absence": "PASS", "cross_account_get_denial": "PASS",
            "scope": "ISOLATED_SYNTHETIC_ONLY", "production_ready": False}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("fixture", type=Path)
    parser.add_argument("--confirm", required=True, choices=["DISPOSABLE_KMJ_TEST_ACCOUNTS_ONLY"])
    args = parser.parse_args()
    try:
        print(json.dumps(run(config(args.fixture)), sort_keys=True))
        return 0
    except Exception:
        print("JMAP_MAILBOX_QUALIFICATION=FAIL", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
