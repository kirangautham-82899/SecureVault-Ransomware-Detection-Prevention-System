# stream.py
"""SecureVault Live: stream status, events and system load to web browsers.

A tiny standard-library HTTP server pushes updates with Server-Sent Events.
For viewing from anywhere, ``start_public`` opens a Cloudflare quick tunnel
(``cloudflared``, no account needed) to the local server. Quick tunnels do not
reliably pass Server-Sent Events, so the viewer falls back to polling
``/api/poll`` when the live connection does not come up.

Safety first:

* Read-only: viewers can look, never change anything.
* Every request needs a 128-bit random token that is regenerated each time
  streaming starts, so stopping the stream revokes every shared link.
* Privacy mode (on by default) strips folder paths, and with them your user
  name, from everything viewers receive; only file names remain.
* Only this computer can connect unless the network or internet is allowed
  explicitly; internet links expire automatically.
* Repeated wrong tokens get the sender locked out, unexpected Host headers are
  rejected (DNS-rebinding protection), and viewers/connections are capped.
* The host is told whenever a new viewer opens the stream.
"""
import os
import re
import hmac
import json
import time
import queue
import socket
import secrets
import shutil
import subprocess
import sys
import threading
from collections import deque
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

import psutil

TUNNEL_URL = re.compile(r"https://[a-z0-9-]+\.trycloudflare\.com")
CLOUDFLARED_PATHS = [
    r"C:\Program Files (x86)\cloudflared\cloudflared.exe",
    r"C:\Program Files\cloudflared\cloudflared.exe",
    os.path.join(os.environ.get("LOCALAPPDATA", ""), "Microsoft", "WinGet", "Links", "cloudflared.exe"),
]
WEB_DIR = os.path.join(getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__))), "web")
DEFAULT_PORT = 8765

TOKEN_BYTES = 16                 # 128-bit access tokens
PUBLIC_LINK_HOURS = 2            # internet links close themselves after this long
MAX_VIEWERS = 25
MAX_CONCURRENT_REQUESTS = 64
LOCKOUT_FAILURES = 10            # wrong tokens allowed per sender...
LOCKOUT_WINDOW = 10 * 60         # ...within this many seconds...
LOCKOUT_SECONDS = 15 * 60        # ...before the sender is blocked for this long

SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; "
                               "style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; "
                               "frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
}


def _page(title, text):
    return (f"""<!doctype html><meta charset="utf-8"><title>SecureVault Live</title>
<body style="font-family:Segoe UI,system-ui,sans-serif;background:#eef3fb;color:#1d2b4f;
display:grid;place-items:center;height:100vh;margin:0;text-align:center">
<div><h2>{title}</h2><p style="color:#6b7a9c">{text}</p></div></body>""").encode("utf-8")


DENIED_PAGE = _page("Access link required", "Open the live-stream link shown in SecureVault.<br>"
                                            "Links stop working when streaming is stopped.")
LOCKED_PAGE = _page("Too many attempts", "This device tried too many wrong links. Try again later.")
BUSY_PAGE = _page("Stream is busy", "Too many people are watching right now. Try again later.")

# A Windows folder path (drive or network share) up to its last backslash.
# File names can't contain : < > | " ? * so the match never runs into the next path.
_FOLDER_PART = re.compile(r'(?:[A-Za-z]:\\|\\\\)(?:[^\\\n:<>|"?*]*\\)*')


def redact_paths(text):
    """Drop folder paths (which include the user name) and keep only file names."""
    return _FOLDER_PART.sub("", text) if text else text


def event_payload(event, private=True):
    payload = {
        "level": event.level,
        "message": event.message,
        "category": event.category,
        "path": event.path,
        "ts": event.timestamp,
    }
    if private:
        payload["message"] = redact_paths(event.message)
        payload["path"] = None  # viewers never get full paths in privacy mode
    return payload


def find_cloudflared():
    found = shutil.which("cloudflared")
    return found or next((p for p in CLOUDFLARED_PATHS if os.path.isfile(p)), None)


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
        self.private = True           # hide folder paths from viewers
        self.token = None
        self.on_notice = None         # callable(str): tells the host about viewers and expiry
        self.public_expires_at = None
        self.public_base = None
        self._httpd = None
        self._clients = set()
        self._lock = threading.Lock()
        self._history = deque(maxlen=history)
        self._metrics = deque(maxlen=60)
        self._state = {}
        self._stop = threading.Event()
        self._seq = 0
        self._pollers = {}            # polling viewer id -> last seen
        self._failures = {}           # sender -> deque of failure times
        self._locked = {}             # sender -> locked until
        self._slots = threading.BoundedSemaphore(MAX_CONCURRENT_REQUESTS)
        self._tunnel = None
        self._expiry_timer = None

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
    def public_url(self):
        if not (self.running and self.public_base):
            return None
        return f"{self.public_base}/?token={self.token}"

    @property
    def viewers(self):
        now = time.time()
        with self._lock:
            pollers = sum(1 for seen in self._pollers.values() if now - seen < 10)
            return len(self._clients) + pollers

    def start(self, lan=False):
        """Start serving and return the shareable URL."""
        self.stop()
        self.lan = lan
        self.token = secrets.token_urlsafe(TOKEN_BYTES)
        self._stop.clear()
        with self._lock:
            self._failures.clear()
            self._locked.clear()
            self._pollers.clear()
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
        self.stop_public()
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

    def _notice(self, message):
        if self.on_notice:
            try:
                self.on_notice(message)
            except Exception:
                pass

    # ------------------------------------------------------- public tunnel

    @staticmethod
    def tunnel_available():
        return find_cloudflared() is not None

    def start_public(self, timeout=45, attempts=2, expires_in=PUBLIC_LINK_HOURS * 3600):
        """Expose the running stream on the internet. Returns the public viewer URL.

        The link closes itself after ``expires_in`` seconds. Free quick tunnels
        occasionally fail to come up, so one retry is built in.
        """
        if not self.running:
            raise RuntimeError("Start streaming first")
        exe = find_cloudflared()
        if not exe:
            raise RuntimeError("cloudflared is not installed (winget install Cloudflare.cloudflared)")
        reason = "no response from Cloudflare"
        for _ in range(attempts):
            url, reason = self._open_tunnel(exe, timeout)
            if url:
                if expires_in:
                    self.public_expires_at = time.time() + expires_in
                    timer = threading.Timer(expires_in, self._expire_public, args=(self._tunnel,))
                    timer.daemon = True
                    timer.start()
                    self._expiry_timer = timer
                return url
        raise RuntimeError(f"Cloudflare tunnel did not start: {reason}")

    def _expire_public(self, proc):
        if self._tunnel is proc:
            self.stop_public()
            self._notice("Public live link expired and was closed automatically")

    def _open_tunnel(self, exe, timeout):
        self.stop_public()
        proc = subprocess.Popen(
            [exe, "tunnel", "--no-autoupdate", "--url", f"http://127.0.0.1:{self.port}"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace",
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        self._tunnel = proc
        done = threading.Event()
        errors = deque(maxlen=3)

        def read_output():
            for line in proc.stdout:  # keep draining so cloudflared never blocks on a full pipe
                m = TUNNEL_URL.search(line)
                if m and not done.is_set():
                    self.public_base = m.group(0)
                    done.set()
                elif " ERR " in line or "error" in line.lower():
                    errors.append(line.split("ERR", 1)[-1].strip()[:160])
            done.set()  # cloudflared exited: stop waiting

        threading.Thread(target=read_output, name="securevault-tunnel", daemon=True).start()
        done.wait(timeout)
        if self.public_base and proc.poll() is None and self._tunnel is proc:
            return self.public_url, None
        if self._tunnel is proc:
            self.stop_public()
        return None, (errors[-1] if errors else "check your internet connection")

    def stop_public(self):
        proc, self._tunnel = self._tunnel, None
        self.public_base = None
        self.public_expires_at = None
        if self._expiry_timer:
            self._expiry_timer.cancel()
            self._expiry_timer = None
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(5)
            except subprocess.TimeoutExpired:
                proc.kill()

    # --------------------------------------------------- access control

    def allowed_hosts(self):
        hosts = {f"127.0.0.1:{self.port}", f"localhost:{self.port}"}
        if self.lan:
            hosts.add(f"{local_ip()}:{self.port}")
        if self.public_base:
            hosts.add(urlparse(self.public_base).netloc)
        return hosts

    def check_token(self, sender, token):
        """Returns "ok", "denied" or "locked", and counts failures per sender."""
        now = time.time()
        with self._lock:
            if self._locked.get(sender, 0) > now:
                return "locked"
            if self.token and token and hmac.compare_digest(token, self.token):
                return "ok"
            failures = self._failures.setdefault(sender, deque())
            failures.append(now)
            while failures and now - failures[0] > LOCKOUT_WINDOW:
                failures.popleft()
            if len(failures) >= LOCKOUT_FAILURES:
                self._locked[sender] = now + LOCKOUT_SECONDS
                failures.clear()
                locked = True
            else:
                locked = False
            if len(self._failures) > 1000:
                self._failures.clear()
        if locked:
            self._notice("Blocked a device that kept trying wrong live-stream links")
        return "denied"

    # ---------------------------------------------------------- publishing

    def _payload(self, event):
        self._seq += 1
        payload = event_payload(event, self.private)
        payload["id"] = self._seq
        return payload

    def publish(self, event):
        with self._lock:
            payload = self._payload(event)
            self._history.append(payload)
        self._broadcast("event", payload)

    def seed(self, events):
        """Pre-fill the history new viewers receive when they connect."""
        with self._lock:
            self._history.clear()
            self._history.extend(self._payload(e) for e in events)

    def update_state(self, **state):
        if self.private:
            state = {k: redact_paths(v) if isinstance(v, str) else v for k, v in state.items()}
        self._state.update(state)
        self._broadcast("state", self._state)

    def snapshot(self):
        with self._lock:
            events, metrics = list(self._history), list(self._metrics)
        return {"state": self._state, "events": events, "metrics": metrics, "viewers": self.viewers}

    def poll(self, since, client, origin="this computer"):
        """Updates for viewers that cannot hold a live connection open."""
        new_viewer = False
        with self._lock:
            if client:
                client = client[:40]
                new_viewer = client not in self._pollers
                self._pollers[client] = time.time()
                if len(self._pollers) > 500:
                    self._pollers.clear()
            events = [e for e in self._history if e["id"] > since]
            metrics = list(self._metrics)
        if new_viewer:
            self._notice(f"Someone opened your live stream ({origin})")
        return {"state": self._state, "events": events, "metrics": metrics, "viewers": self.viewers}

    def _broadcast(self, name, data):
        message = f"event: {name}\ndata: {json.dumps(data)}\n\n".encode("utf-8")
        with self._lock:
            for q in list(self._clients):
                try:
                    q.put_nowait(message)
                except queue.Full:  # A stalled viewer must not hold up everyone else
                    self._clients.discard(q)

    def _register(self, q, origin="this computer"):
        with self._lock:
            self._clients.add(q)
        self._broadcast("viewers", {"count": self.viewers})
        self._notice(f"Someone opened your live stream ({origin})")

    def _unregister(self, q):
        with self._lock:
            self._clients.discard(q)
        self._broadcast("viewers", {"count": self.viewers})

    def _sample_metrics(self):
        psutil.cpu_percent(None)
        while not self._stop.wait(1.0):
            sample = {"cpu": psutil.cpu_percent(None), "mem": psutil.virtual_memory().percent, "ts": time.time()}
            with self._lock:
                self._metrics.append(sample)
            self._broadcast("metrics", sample)


def _make_handler(live):
    class Handler(BaseHTTPRequestHandler):
        server_version = "SecureVaultLive"
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

        def _sender(self):
            """Who is asking: the real visitor for tunnelled requests, else the socket peer."""
            peer = self.client_address[0]
            if peer in ("127.0.0.1", "::1") and live.public_base:
                return self.headers.get("CF-Connecting-IP", peer)[:64]
            return peer

        def _origin(self):
            peer = self.client_address[0]
            if peer in ("127.0.0.1", "::1"):
                return "via the internet" if self.headers.get("CF-Connecting-IP") else "this computer"
            return "your local network"

        def do_GET(self):
            if not live._slots.acquire(blocking=False):
                self._send(503, BUSY_PAGE, "text/html; charset=utf-8")
                return
            try:
                self._handle()
            finally:
                live._slots.release()

        def _handle(self):
            host = (self.headers.get("Host") or "").lower()
            if host not in live.allowed_hosts():  # DNS-rebinding protection
                self._send(421, b"Unknown host", "text/plain")
                return
            url = urlparse(self.path)
            query = parse_qs(url.query)
            verdict = live.check_token(self._sender(), query.get("token", [""])[0])
            if verdict == "locked":
                self._send(429, LOCKED_PAGE, "text/html; charset=utf-8")
                return
            if verdict != "ok":
                self._send(403, DENIED_PAGE, "text/html; charset=utf-8")
                return
            if url.path in ("/", "/index.html"):
                with open(os.path.join(WEB_DIR, "index.html"), "rb") as f:
                    self._send(200, f.read(), "text/html; charset=utf-8")
            elif url.path == "/api/snapshot":
                self._send(200, json.dumps(live.snapshot()).encode("utf-8"), "application/json")
            elif url.path == "/api/poll":
                try:
                    since = int(query.get("since", ["0"])[0])
                except ValueError:
                    since = 0
                client = query.get("client", [""])[0]
                if client and live.viewers >= MAX_VIEWERS and client[:40] not in live._pollers:
                    self._send(503, BUSY_PAGE, "text/html; charset=utf-8")
                    return
                body = live.poll(since, client, self._origin())
                self._send(200, json.dumps(body).encode("utf-8"), "application/json")
            elif url.path == "/stream":
                if live.viewers >= MAX_VIEWERS:
                    self._send(503, BUSY_PAGE, "text/html; charset=utf-8")
                    return
                self._stream()
            else:
                self._send(404, b"Not found", "text/plain")

        def _stream(self):
            self._headers(200, "text/event-stream; charset=utf-8")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            q = queue.Queue(maxsize=500)
            registered = False
            try:
                snapshot = json.dumps(live.snapshot())
                self.wfile.write(f"retry: 3000\nevent: snapshot\ndata: {snapshot}\n\n".encode("utf-8"))
                self.wfile.flush()
                live._register(q, self._origin())
                registered = True
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
                if registered:
                    live._unregister(q)

    return Handler
