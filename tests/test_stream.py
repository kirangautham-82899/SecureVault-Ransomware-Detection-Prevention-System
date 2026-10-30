import os
import sys
import json
import unittest
import urllib.error
import urllib.request

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import Event, CRITICAL
from stream import LiveStreamServer


def read_sse(response, wanted):
    """Read Server-Sent Events until one named ``wanted`` arrives; return its data."""
    name = None
    for raw in response:
        line = raw.decode("utf-8").rstrip("\n")
        if line.startswith("event: "):
            name = line[7:]
        elif line.startswith("data: ") and name == wanted:
            return json.loads(line[6:])


class TestLiveStream(unittest.TestCase):
    def setUp(self):
        self.server = LiveStreamServer(port=18765)
        self.url = self.server.start()
        self.base = self.url.split("?")[0].rstrip("/")

    def tearDown(self):
        self.server.stop()

    def test_requires_token(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(self.base + "/?token=wrong", timeout=5)
        self.assertEqual(ctx.exception.code, 403)

    def test_serves_viewer_with_token(self):
        with urllib.request.urlopen(self.url, timeout=5) as r:
            self.assertEqual(r.status, 200)
            self.assertIn(b"SecureVault Live", r.read())
            self.assertEqual(r.headers["X-Frame-Options"], "DENY")

    def test_streams_snapshot_and_live_events(self):
        self.server.update_state(status="protected", alerts=0)
        with urllib.request.urlopen(f"{self.base}/stream?token={self.server.token}", timeout=5) as r:
            snapshot = read_sse(r, "snapshot")
            self.assertEqual(snapshot["state"]["status"], "protected")
            self.server.publish(Event(CRITICAL, "Honeypot deleted!", "honeypot"))
            event = read_sse(r, "event")
            self.assertEqual(event["level"], CRITICAL)
            self.assertEqual(event["message"], "Honeypot deleted!")

    def test_stop_revokes_link(self):
        old_token = self.server.token
        self.server.stop()
        self.url = self.server.start()
        self.assertNotEqual(old_token, self.server.token)
        with self.assertRaises(urllib.error.HTTPError):
            urllib.request.urlopen(f"{self.base.rsplit(':', 1)[0]}:{self.server.port}/?token={old_token}", timeout=5)


if __name__ == "__main__":
    unittest.main()
