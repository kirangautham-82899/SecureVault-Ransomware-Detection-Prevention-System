# stream.py
"""SecureVault Live: stream status, events and system load to web browsers.

A tiny standard-library HTTP server pushes updates with Server-Sent Events.
The viewer is read-only and every request must carry the random access token
that is generated each time streaming starts, so stopping the stream revokes
every link that was shared.
"""
import os
import hmac
import json
import time
import queue
import socket
import secrets
import sys
import threading
from collections import deque
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

import psutil

WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")
DEFAULT_PORT = 8765

SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; "
                               "style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'",
}

DENIED_PAGE = b"""<!doctype html><meta charset="utf-8"><title>SecureVault Live</title>
<body style="font-family:Segoe UI,system-ui,sans-serif;background:#eef3fb;color:#1d2b4f;
display:grid;place-items:center;height:100vh;margin:0;text-align:center">
<div><h2>Access link required</h2><p style="color:#6b7a9c">Open the live-stream link shown in SecureVault.
<br>Links stop working when streaming is stopped.</p></div></body>"""


def event_payload(event):
    return {
        "level": event.level,
        "message": event.message,
        "category": event.category,
        "path": event.path,
        "ts": event.timestamp,
    }


def local_ip():
    """Best-effort LAN address of this machine (no packets are sent)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False  # On Windows reuse would let two servers share a port

    def handle_error(self, request, client_address):
        # Browsers routinely drop idle keep-alive connections; that is not an error
        if isinstance(sys.exc_info()[1], ConnectionError):
            return
        super().handle_error(request, client_address)


class LiveStreamServer:
    def __init__(self, port=DEFAULT_PORT, history=300):
        self.port_hint = port
        self.port = None
        self.lan = False
        self.token = None
        self._httpd = None
        self._clients = set()
        self._lock = threading.Lock()
        self._history = deque(maxlen=history)
        self._metrics = deque(maxlen=60)
        self._state = {}
        self._stop = threading.Event()

    # ----------------------------------------------------------- control

    @property
    def running(self):
        return self._httpd is not None

    @property
    def url(self):
        if not self.running:
            return None
        host = local_ip() if self.lan else "127.0.0.1"
        return f"http://{host}:{self.port}/?token={self.token}"

    @property
    def viewers(self):
        with self._lock:
            return len(self._clients)

    def start(self, lan=False):
        """Start serving and return the shareable URL."""
        self.stop()
        self.lan = lan
        self.token = secrets.token_urlsafe(12)
        self._stop.clear()
        host = "0.0.0.0" if lan else "127.0.0.1"
        handler = _make_handler(self)
        for port in range(self.port_hint, self.port_hint + 20):
            try:
                httpd = _Server((host, port), handler)
                break
            except OSError:
                continue
        else:
            raise OSError("No free port available for the live stream")
        self._httpd = httpd
        self.port = httpd.server_address[1]
        threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.5},
                         name="securevault-live", daemon=True).start()
        threading.Thread(target=self._sample_metrics, name="securevault-live-metrics", daemon=True).start()
        return self.url

    def stop(self):
        httpd, self._httpd = self._httpd, None
        if httpd is None:
            return
        self._stop.set()
        with self._lock:
            clients = list(self._clients)
            self._clients.clear()
        for q in clients:
            try:
                q.put_nowait(None)
            except queue.Full:
                pass
        httpd.shutdown()
        httpd.server_close()
        self.token = None

    # ---------------------------------------------------------- publishing

    def publish(self, event):
        payload = event_payload(event)
        self._history.append(payload)
        self._broadcast("event", payload)

    def seed(self, events):
        """Pre-fill the history new viewers receive when they connect."""
        self._history.clear()
        self._history.extend(event_payload(e) for e in events)

    def update_state(self, **state):
        self._state.update(state)
        self._broadcast("state", self._state)

    def snapshot(self):
        return {
            "state": self._state,
            "events": list(self._history),
            "metrics": list(self._metrics),
            "viewers": self.viewers,
        }

    def _broadcast(self, name, data):
        message = f"event: {name}\ndata: {json.dumps(data)}\n\n".encode("utf-8")
        with self._lock:
            for q in list(self._clients):
                try:
                    q.put_nowait(message)
                except queue.Full:  # A stalled viewer must not hold up everyone else
                    self._clients.discard(q)

    def _register(self, q):
        with self._lock:
            self._clients.add(q)
        self._broadcast("viewers", {"count": self.viewers})

    def _unregister(self, q):
        with self._lock:
            self._clients.discard(q)
        self._broadcast("viewers", {"count": self.viewers})

    def _sample_metrics(self):
        psutil.cpu_percent(None)
        while not self._stop.wait(1.0):
            sample = {"cpu": psutil.cpu_percent(None), "mem": psutil.virtual_memory().percent, "ts": time.time()}
            self._metrics.append(sample)
            self._broadcast("metrics", sample)


def _make_handler(live):
    class Handler(BaseHTTPRequestHandler):
        server_version = "SecureVaultLive/1.0"
        sys_version = ""

        def log_message(self, *args):
            pass

        def _headers(self, code, content_type, length=None):
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            if length is not None:
                self.send_header("Content-Length", str(length))
            for key, value in SECURITY_HEADERS.items():
                self.send_header(key, value)

        def _send(self, code, body, content_type):
            self._headers(code, content_type, len(body))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            url = urlparse(self.path)
            token = parse_qs(url.query).get("token", [""])[0]
            if not (live.token and hmac.compare_digest(token, live.token)):
                self._send(403, DENIED_PAGE, "text/html; charset=utf-8")
                return
            if url.path in ("/", "/index.html"):
                with open(os.path.join(WEB_DIR, "index.html"), "rb") as f:
                    self._send(200, f.read(), "text/html; charset=utf-8")
            elif url.path == "/api/snapshot":
                self._send(200, json.dumps(live.snapshot()).encode("utf-8"), "application/json")
            elif url.path == "/stream":
                self._stream()
            else:
                self._send(404, b"Not found", "text/plain")

        def _stream(self):
            self._headers(200, "text/event-stream; charset=utf-8")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            q = queue.Queue(maxsize=500)
            try:
                snapshot = json.dumps(live.snapshot())
                self.wfile.write(f"retry: 3000\nevent: snapshot\ndata: {snapshot}\n\n".encode("utf-8"))
                self.wfile.flush()
                live._register(q)
                while True:
                    try:
                        message = q.get(timeout=15)
                    except queue.Empty:
                        with live._lock:
                            dropped = q not in live._clients
                        if dropped or not live.running:
                            break
                        message = b": keep-alive\n\n"
                    if message is None:
                        break
                    self.wfile.write(message)
                    self.wfile.flush()
            except OSError:  # Viewer closed the tab
                pass
            finally:
                live._unregister(q)

    return Handler
