import importlib.util
import imaplib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

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

    def test_duplicate_fixture_fields_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "fixture.json"
            ca = Path(tmp) / "ca.pem"
            ca.touch()
            valid = {"smtp_port": 2525, "imap_port": 2993,
                     "alpha_password": "alpha-test-secret-long",
                     "beta_password": "beta-test-secret-long", "ca_file": str(ca)}
            p.write_text(json.dumps(valid)[:-1] + ', "smtp_port": 2526}')
            p.chmod(0o600)
            with self.assertRaises(ValueError):
                q.config(p)

    def test_root_refused_before_network(self):
        with patch.object(q.os, "geteuid", return_value=0), \
                patch.object(q.ssl, "create_default_context") as tls, \
                patch.object(q.smtplib, "SMTP") as smtp:
            with self.assertRaises(ValueError):
                q.run({})
            tls.assert_not_called()
            smtp.assert_not_called()

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

    def test_cross_credentials_fail_closed(self):
        c = Mock()
        c.login.return_value = ("OK", [b"unexpected"])
        with self.assertRaises(ValueError):
            q.deny_cross_credentials(c, q.PRIMARY, "wrong-password")
        c.login.return_value = ("NO", [b"unspecified"])
        with self.assertRaises(ValueError):
            q.deny_cross_credentials(c, q.PRIMARY, "wrong-password")
        c.login.side_effect = imaplib.IMAP4.abort("connection lost")
        with self.assertRaises(imaplib.IMAP4.abort):
            q.deny_cross_credentials(c, q.PRIMARY, "wrong-password")
        c.login.side_effect = imaplib.IMAP4.error("BAD command")
        with self.assertRaises(ValueError):
            q.deny_cross_credentials(c, q.PRIMARY, "wrong-password")
        c.login.side_effect = imaplib.IMAP4.error("[AUTHENTICATIONFAILED] Invalid credentials")
        q.deny_cross_credentials(c, q.PRIMARY, "wrong-password")

    def test_message_recipient_and_content(self):
        marker, message_id, raw = q.witness(q.SECONDARY)
        c = Mock()
        c.uid.return_value = ("OK", [(b"1 BODY[]", raw)])
        q.check_message(c, b"1", marker, message_id, q.SECONDARY)
        with self.assertRaises(ValueError):
            q.check_message(c, b"1", marker, message_id, q.PRIMARY)
        with self.assertRaises(ValueError):
            q.check_message(c, b"1", "wrong marker", message_id, q.SECONDARY)

    def test_mailbox_rejects_cross_account_message(self):
        own = q.witness(q.PRIMARY)
        other = q.witness(q.SECONDARY)
        c = Mock()
        c.login.return_value = ("OK", [b"ok"])
        c.select.return_value = ("OK", [b"2"])
        c.noop.return_value = ("OK", [b"ok"])
        c.uid.side_effect = [
            ("OK", [b"1"]),
            ("OK", [(b"1 BODY[]", own[2])]),
            ("OK", [b"2"]),
        ]
        with self.assertRaises(ValueError):
            q.check_mailbox(c, q.PRIMARY, "test-password", own, other)


if __name__ == "__main__":
    unittest.main()
