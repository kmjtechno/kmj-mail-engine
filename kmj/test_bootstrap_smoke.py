"""Exercise the actual HTTP helper on loopback before expensive Rust compilation."""
import importlib.util
import http.client
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import threading
import unittest

spec = importlib.util.spec_from_file_location("smoke", Path(__file__).with_name("bootstrap-smoke.py"))
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/.well-known/jmap":
            self.send_response(307)
            self.send_header("Location", "/jmap/session")
            self.end_headers()
        elif self.path == "/jmap/session":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"accounts":{},"capabilities":{"urn:ietf:params:jmap:core":{}}}')
        else:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"x" * 131073)

    def log_message(self, *args):
        pass


class HttpHelperTests(unittest.TestCase):
    def setUp(self):
        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.worker = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.worker.start()
        self.port = self.server.server_address[1]

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.worker.join(timeout=2)

    def test_real_loopback_http_discovery(self):
        self.assertIs(smoke.http.client, http.client)
        self.assertEqual(smoke.http_get(self.port, "/.well-known/jmap"), (307, "/jmap/session", b""))
        status, _, body = smoke.http_get(self.port, "/jmap/session")
        self.assertEqual(status, 200)
        self.assertIn(b'"accounts":{}', body)

    def test_response_bound(self):
        with self.assertRaisesRegex(smoke.SmokeFailure, "HTTP_RESPONSE_BOUND"):
            smoke.http_get(self.port, "/oversized")


if __name__ == "__main__":
    unittest.main()
