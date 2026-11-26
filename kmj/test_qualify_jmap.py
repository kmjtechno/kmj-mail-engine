import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

spec = importlib.util.spec_from_file_location("q", Path(__file__).with_name("qualify-jmap.py"))
q = importlib.util.module_from_spec(spec)
spec.loader.exec_module(q)


def session(aid="A"):
    return {"capabilities": {q.CORE: {}, q.MAIL: {}},
            "primaryAccounts": {q.MAIL: aid},
            "accounts": {aid: {"isPersonal": True, "accountCapabilities": {q.MAIL: {}}}}}


def response(name, body, tag="witness"):
    return {"methodResponses": [[name, body, tag]]}


class JmapQualification(unittest.TestCase):
    def test_config_and_duplicate_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "fixture.json"
            ca = Path(tmp) / "ca.pem"
            ca.touch()
            d = {"smtp_port": 2525, "jmap_port": 28443, "alpha_password": "a"*20,
                 "beta_password": "b"*20, "ca_file": str(ca)}
            path.write_text(json.dumps(d))
            path.chmod(0o600)
            self.assertEqual(q.config(path), d)
            for patch in [{"jmap_port": 443}, {"smtp_port": True}, {"host": "example.com"},
                          {"beta_password": "a"*20}, {"jmap_port": 2525}]:
                path.write_text(json.dumps({**d, **patch}))
                with self.assertRaises(ValueError):
                    q.config(path)
            path.write_text(json.dumps(d))
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                q.config(path)
            with self.assertRaises(ValueError):
                q.parse_json(b'{"accounts":{},"accounts":{"B":{}}}')

    def test_account_isolation(self):
        self.assertEqual(q.account(session()), "A")
        s = session()
        s["accounts"]["B"] = {}
        with self.assertRaises(ValueError):
            q.account(s)
        s = session()
        s["accounts"]["A"]["isPersonal"] = False
        with self.assertRaises(ValueError):
            q.account(s)

    def test_cross_account_deny_is_explicit(self):
        for typ in ("forbidden", "accountNotFound"):
            q.deny_cross_account(Mock(return_value=response("error", {"type": typ})), "B", "M")
        for result in [response("Email/get", {"list": [], "notFound": ["M"]}),
                       response("error", {"type": "serverFail"}),
                       response("error", {"type": "forbidden", "list": ["secret"]}),
                       response("error", {"type": "forbidden"}, "wrong")]:
            with self.assertRaises(ValueError):
                q.deny_cross_account(Mock(return_value=result), "B", "M")

    def test_own_message_identity(self):
        item = {"id": "M", "subject": "marker", "messageId": ["id@example.test"],
                "from": [{"email": q.SENDER}], "to": [{"email": q.ALPHA}]}
        query = response("Email/query", {"accountId": "A", "ids": ["M"]})
        get = response("Email/get", {"accountId": "A", "notFound": [], "list": [item]})
        self.assertEqual(q.own_message(Mock(side_effect=[query, get]), "A",
                                      "marker", q.ALPHA, "id@example.test"), "M")
        with self.assertRaises(ValueError):
            q.own_message(Mock(side_effect=[query, get]), "A", "marker",
                          q.BETA, "id@example.test")

    def test_query_must_match_account(self):
        with self.assertRaises(ValueError):
            q.get_ids(Mock(return_value=response("Email/query", {"accountId": "B", "ids": []})),
                      "A", "marker")


if __name__ == "__main__":
    unittest.main()
