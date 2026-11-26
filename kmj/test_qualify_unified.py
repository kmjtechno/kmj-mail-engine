import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

spec = importlib.util.spec_from_file_location("qualify", Path(__file__).with_name("qualify-unified.py"))
q = importlib.util.module_from_spec(spec)
spec.loader.exec_module(q)


class QualificationContract(unittest.TestCase):
    def test_fixture_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "fixture.json"
            ca = Path(tmp) / "ca.pem"
            ca.touch()
            valid = {"smtp_port": 2525, "imap_port": 2993,
                     "alpha_password": "alpha-test-secret-long",
                     "beta_password": "beta-test-secret-long", "ca_file": str(ca)}
            p.write_text(json.dumps(valid))
            p.chmod(0o600)
            self.assertEqual(q.config(p), valid)
            for patch in [{"smtp_port": 25}, {"imap_port": 993}, {"host": "external.example"},
                          {"beta_password": valid["alpha_password"]}, {"smtp_port": True}]:
                p.write_text(json.dumps({**valid, **patch}))
                with self.assertRaises(ValueError):
                    q.config(p)
            p.write_text(json.dumps(valid))
            p.chmod(0o644)
            with self.assertRaises(ValueError):
                q.config(p)
            p.chmod(0o600)
            alias = Path(tmp) / "alias"
            alias.symlink_to(p)
            with self.assertRaises(OSError):
                q.config(alias)

    def test_relay_must_be_permanently_rejected(self):
        s = Mock()
        s.mail.return_value = (250, b"ok")
        s.rset.return_value = (250, b"ok")
        for code in [250, 451]:
            s.rcpt.return_value = (code, b"test")
            with self.assertRaises(ValueError):
                q.rejected(s, q.RELAY)
        s.rcpt.return_value = (554, b"test")
        q.rejected(s, q.RELAY)

    def test_search_malformed_data_never_passes(self):
        c = Mock()
        c.uid.return_value = ("OK", [b"1 2"])
        self.assertEqual(q.locate(c, "<fixture@example.test>"), [b"1", b"2"])
        for result in [("NO", [b""]), ("OK", [b"bad"]), ("OK", [None])]:
            c.uid.return_value = result
            with self.assertRaises(ValueError):
                q.locate(c, "<fixture@example.test>")


if __name__ == "__main__":
    unittest.main()
