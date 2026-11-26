import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("pgbootstrap", Path(__file__).with_name("bootstrap-postgres.py"))
q = importlib.util.module_from_spec(spec)
spec.loader.exec_module(q)


def response(method, data, tag="bootstrap"):
    return json.dumps({"methodResponses": [[method, data, tag]]}).encode()


class BootstrapContract(unittest.TestCase):
    def test_response_must_match_method_and_tag(self):
        method = "x:Bootstrap/get"
        self.assertEqual(q.parse_response(response(method, {"list": []}), method), {"list": []})
        for raw in [response("error", {"type": "forbidden"}),
                    response(method, {}, "different"),
                    b'{"methodResponses":[]}',
                    b'{"methodResponses":[],"methodResponses":[]}',
                    b'{"methodResponses":[["x:Bootstrap/get",{"n":NaN},"bootstrap"]]}']:
            with self.assertRaises(ValueError):
                q.parse_response(raw, method)

    def test_bootstrap_patch_is_local_and_no_automatic_dns(self):
        read = {"list": [{"id": "A"}], "notFound": []}
        success = {"updated": {"A": {"username": "admin@" + q.DOMAIN, "secret": "x"*16}}}
        with patch.object(q, "rpc", side_effect=[read, success]) as rpc:
            q.bootstrap(20000, "synthetic-token", 20001, Path("/tmp/fixture"))
        args = rpc.call_args.args
        self.assertEqual(args[2], "x:Bootstrap/set")
        data = args[3]["update"]["A"]
        self.assertEqual(data["dataStore"]["host"], "127.0.0.1")
        self.assertEqual(data["dataStore"]["port"], 20001)
        self.assertFalse(data["requestTlsCertificate"])
        self.assertFalse(data["generateDkimKeys"])
        self.assertEqual(data["dnsServer"], {"@type": "Manual"})

    def test_bootstrap_fails_on_conflicting_or_missing_receipt(self):
        read = {"list": [{"id": "A"}]}
        good = {"username": "admin@" + q.DOMAIN, "secret": "x"*16}
        for result in [{"updated": {"A": good}, "notUpdated": {"A": {"type": "invalidProperties"}}},
                       {"updated": {"B": good}},
                       {"updated": {"A": None}},
                       {"updated": {"A": {"username": "wrong", "secret": "x"*16}}},
                       {"updated": {"A": good}, "created": {"B": {}}}]:
            with patch.object(q, "rpc", side_effect=[read, result]):
                with self.assertRaises(ValueError):
                    q.bootstrap(20000, "synthetic-token", 20001, Path("/tmp/fixture"))

    def test_reject_invalid_rpc_scope_before_network(self):
        with patch.object(q.http.client, "HTTPConnection") as conn:
            for port, method in [(443, "x:Bootstrap/get"), (True, "x:Bootstrap/get"),
                                 (20000, "x:Account/set")]:
                with self.assertRaises(ValueError):
                    q.rpc(port, "token", method, {})
            conn.assert_not_called()


if __name__ == "__main__":
    unittest.main()
