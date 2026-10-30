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

    def test_polling_returns_only_new_events(self):
        self.server.publish(Event(CRITICAL, "first", "file"))
        poll = f"{self.base}/api/poll?token={self.server.token}&client=abc&since="
        with urllib.request.urlopen(poll + "0", timeout=5) as r:
            body = json.loads(r.read())
        last = body["events"][-1]["id"]
        self.assertEqual(body["events"][-1]["message"], "first")
        self.assertEqual(body["viewers"], 1, "polling viewers are counted")
        self.server.publish(Event(CRITICAL, "second", "file"))
        with urllib.request.urlopen(poll + str(last), timeout=5) as r:
            self.assertEqual([e["message"] for e in json.loads(r.read())["events"]], ["second"])

    def test_public_tunnel_requires_running_stream(self):
        self.server.stop()
        with self.assertRaises(RuntimeError):
            self.server.start_public()
        self.url = self.server.start()

    def test_stop_revokes_link(self):
        old_token = self.server.token
        self.server.stop()
        self.url = self.server.start()
        self.assertNotEqual(old_token, self.server.token)
        with self.assertRaises(urllib.error.HTTPError):
            urllib.request.urlopen(f"{self.base.rsplit(':', 1)[0]}:{self.server.port}/?token={old_token}", timeout=5)


if __name__ == "__main__":
    unittest.main()


class TestStreamSafety(unittest.TestCase):
    """Safety-first guarantees of the live stream."""

    def setUp(self):
        self.server = LiveStreamServer(port=18780)
        self.server.start()
        self.base = f"http://127.0.0.1:{self.server.port}"
        self.notices = []
        self.server.on_notice = self.notices.append

    def tearDown(self):
        self.server.stop()

    def get(self, path, headers=None):
        req = urllib.request.Request(self.base + path, headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def test_token_is_128_bit(self):
        self.assertGreaterEqual(len(self.server.token), 22)

    def test_privacy_mode_hides_folders_and_user_name(self):
        from stream import redact_paths
        self.assertEqual(redact_paths(r"File modified: C:\Users\alice\My Docs\Notes.txt"), "File modified: Notes.txt")
        self.assertEqual(redact_paths(r"Renamed: C:\Users\alice\a.docx -> C:\Users\alice\a.docx.locked"),
                         "Renamed: a.docx -> a.docx.locked")
        self.assertEqual(redact_paths("Found: " + "\\\\" + r"nas\share\alice\x.exe"), "Found: x.exe")
        self.server.publish(Event(CRITICAL, r"Malware detected: C:\Users\alice\Downloads\bad.exe", "scanner",
                                  r"C:\Users\alice\Downloads\bad.exe"))
        self.server.update_state(subline=r"Watching C:\Users\alice\Documents")
        status, body = self.get(f"/api/snapshot?token={self.server.token}")
        self.assertEqual(status, 200)
        self.assertNotIn("alice", body.decode())
        self.assertIn("bad.exe", body.decode())

    def test_private_mode_can_be_turned_off(self):
        self.server.private = False
        self.server.publish(Event(CRITICAL, r"C:\Users\alice\bad.exe", "scanner", r"C:\Users\alice\bad.exe"))
        self.assertIn("alice", self.get(f"/api/snapshot?token={self.server.token}")[1].decode())

    def test_rejects_unknown_host_header(self):
        status, _ = self.get(f"/?token={self.server.token}", {"Host": "evil.example:80"})
        self.assertEqual(status, 421)

    def test_locks_out_token_guessing(self):
        from stream import LOCKOUT_FAILURES
        for _ in range(LOCKOUT_FAILURES):
            self.assertEqual(self.get("/?token=guess")[0], 403)
        self.assertEqual(self.get(f"/?token={self.server.token}")[0], 429, "even the right token is refused now")
        self.assertTrue(any("Blocked" in n for n in self.notices))

    def test_host_is_told_about_new_viewers(self):
        self.get(f"/api/poll?token={self.server.token}&since=0&client=viewer1")
        self.get(f"/api/poll?token={self.server.token}&since=0&client=viewer1")
        self.assertEqual(sum("opened your live stream" in n for n in self.notices), 1)

    def test_viewer_limit(self):
        import stream
        old = stream.MAX_VIEWERS
        stream.MAX_VIEWERS = 1
        try:
            self.assertEqual(self.get(f"/api/poll?token={self.server.token}&client=a")[0], 200)
            self.assertEqual(self.get(f"/api/poll?token={self.server.token}&client=b")[0], 503)
        finally:
            stream.MAX_VIEWERS = old

    def test_public_link_expires(self):
        import subprocess
        import time as _time
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        self.server._tunnel = proc
        self.server.public_base = "https://demo.trycloudflare.com"
        self.server._expire_public(proc)
        self.assertIsNone(self.server.public_url)
        _time.sleep(0.2)
        self.assertIsNotNone(proc.poll(), "the tunnel process is stopped")
        self.assertTrue(any("expired" in n for n in self.notices))
