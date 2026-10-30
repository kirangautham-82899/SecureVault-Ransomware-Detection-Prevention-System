# main.py
"""SecureVault core engine and command-line interface.

The engine exposes plain functions that report what they find as ``Event``
objects. Every function accepts an optional ``sink`` (or ``alert_queue``):
either a callable, an object with a ``put`` method (e.g. ``queue.Queue``),
or ``None`` to print to the console.
"""
import os
import re
import sys
import json
import time
import hashlib
import datetime
import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field

import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

APP_NAME = "SecureVault"
APP_VERSION = "2.0.0"

# Runtime data lives next to the application, not in whatever folder it was launched from
APP_DIR = os.path.dirname(os.path.abspath(__file__))
HASH_DB_FILE = os.path.join(APP_DIR, "hash_db.json")
LOG_FILE = os.path.join(APP_DIR, "suspicious_activity.log")
HONEYPOT_FILE = "honeypot_fake_sensitive.txt"

# Default exclusions to reduce noise
EXCLUDED_DIRS = {"AppData", ".gemini", ".git", ".vscode", "__pycache__", "node_modules"}
EXCLUDED_FILES = {"ntuser.dat", "NTUSER.DAT", "pagefile.sys", "swapfile.sys", "dumpstack.log.tmp"}
EXCLUDED_EXTENSIONS = {".tmp", ".log", ".pyc", ".pyd", ".ldb", ".vscdb-journal"}

# Extensions commonly appended by ransomware families after encrypting a file
RANSOMWARE_EXTENSIONS = {
    ".locked", ".encrypted", ".enc", ".crypt", ".crypted", ".cry", ".crypto",
    ".locky", ".zepto", ".cerber", ".wannacry", ".wncry", ".wcry", ".ryuk",
    ".lockbit", ".conti", ".petya", ".djvu", ".pay", ".ransom", ".kraken",
}

_EXCLUDED_DIRS_LOWER = {d.lower() for d in EXCLUDED_DIRS}
_EXCLUDED_FILES_LOWER = {f.lower() for f in EXCLUDED_FILES}
_APP_FILES = {os.path.normcase(os.path.normpath(p)) for p in (HASH_DB_FILE, LOG_FILE)}

INFO, SUCCESS, WARNING, CRITICAL = "info", "success", "warning", "critical"


@dataclass
class Event:
    """A single thing SecureVault noticed or did."""
    level: str
    message: str
    category: str = "system"
    path: str = None
    timestamp: float = field(default_factory=time.time)

    @property
    def time_str(self):
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.timestamp))


_log_lock = threading.Lock()


def log_suspicious_activity(message, level=INFO):
    try:
        with _log_lock, open(LOG_FILE, "a", encoding="utf-8") as f:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{timestamp}] [{level.upper()}] {message}\n")
    except OSError:
        pass


def emit(sink, level, message, category="system", path=None, log=True):
    """Deliver an event to the sink and record it in the activity log."""
    event = Event(level, message, category, path)
    if log:
        log_suspicious_activity(message, level)
    if sink is None:
        print(f"[{event.time_str}] {level.upper():8} {message}")
    elif callable(sink):
        sink(event)
    else:
        sink.put(event)
    return event


def should_ignore(file_path, root=None):
    """Check if file should be ignored based on global exclusions.

    When ``root`` is given, only the part of the path below it is checked, so
    a protected folder that itself lives inside e.g. AppData still works.
    """
    if root:
        try:
            rel = os.path.relpath(file_path, root)
            if not rel.startswith(".."):
                file_path = rel
        except ValueError:  # Different drive on Windows
            pass
    path_parts = re.split(r"[\\/]", file_path)
    filename = path_parts[-1]

    # Check for excluded directories in the path
    if any(part.lower() in _EXCLUDED_DIRS_LOWER for part in path_parts):
        return True

    # Check for specific filenames
    if filename.lower() in _EXCLUDED_FILES_LOWER:
        return True

    # Check extensions
    _, ext = os.path.splitext(filename)
    if ext.lower() in EXCLUDED_EXTENSIONS:
        return True

    # Check system/temp files
    if filename.startswith("~") or filename.startswith("$"):
        return True

    return False


def is_app_file(file_path):
    """True for SecureVault's own data files, which must never raise alerts."""
    return os.path.normcase(os.path.normpath(file_path)) in _APP_FILES


def is_honeypot(file_path):
    return os.path.basename(file_path).lower() == HONEYPOT_FILE.lower()


def has_ransomware_extension(file_path):
    return os.path.splitext(file_path)[1].lower() in RANSOMWARE_EXTENSIONS


def calculate_hash(file_path):
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except OSError:
        # Locked, missing or unreadable files are skipped silently to reduce noise
        return None


def normalize_path(file_path):
    return os.path.normpath(file_path)


def iter_monitored_files(folder):
    """Yield every file under ``folder`` that SecureVault should track."""
    for root, dirs, files in os.walk(folder):
        # Modify dirs in-place to skip excluded directories (case-insensitive)
        dirs[:] = [d for d in dirs if d.lower() not in _EXCLUDED_DIRS_LOWER]
        for name in files:
            full_path = normalize_path(os.path.join(root, name))
            if is_honeypot(full_path) or is_app_file(full_path) or should_ignore(full_path, folder):
                continue
            yield full_path


# ---------------------------------------------------------------------------
# Baseline
# ---------------------------------------------------------------------------

def load_baseline(db_file=HASH_DB_FILE):
    """Return ``{"folder", "created", "files"}`` or ``None`` if no baseline exists."""
    try:
        with open(db_file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return None
    if isinstance(data, dict) and "files" in data:
        return data
    # Legacy v1 format: a flat {path: hash} mapping
    return {"folder": None, "created": None, "files": data}


def create_baseline(folder_to_monitor, sink=None, db_file=HASH_DB_FILE, stop_event=None):
    if not os.path.isdir(folder_to_monitor):
        emit(sink, WARNING, f"Folder not found: {folder_to_monitor}", "baseline")
        return None
    emit(sink, INFO, f"Indexing files in {folder_to_monitor}...", "baseline", log=False)

    hash_data = {}
    for path in iter_monitored_files(folder_to_monitor):
        if stop_event and stop_event.is_set():
            emit(sink, WARNING, "Baseline creation cancelled", "baseline")
            return None
        file_hash = calculate_hash(path)
        if file_hash:
            hash_data[path] = file_hash

    data = {
        "version": 2,
        "folder": normalize_path(os.path.abspath(folder_to_monitor)),
        "created": datetime.datetime.now().isoformat(timespec="seconds"),
        "files": hash_data,
    }
    tmp_file = db_file + ".part"
    with open(tmp_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp_file, db_file)

    emit(sink, SUCCESS, f"Baseline created: {len(hash_data):,} files indexed", "baseline")
    return data


def check_for_changes(folder=None, sink=None, db_file=HASH_DB_FILE):
    """Compare the folder against the baseline.

    Returns ``{"modified", "deleted", "new", "checked"}`` or ``None`` when no
    baseline exists. New files are only reported when ``folder`` matches the
    folder the baseline was made from.
    """
    baseline = load_baseline(db_file)
    if baseline is None:
        emit(sink, WARNING, "No baseline found. Create a baseline first.", "scan")
        return None

    saved_hashes = baseline["files"]
    baseline_folder = baseline.get("folder")
    if folder and baseline_folder and os.path.normcase(normalize_path(os.path.abspath(folder))) != os.path.normcase(baseline_folder):
        emit(sink, WARNING, f"Baseline was created for {baseline_folder}, not the selected folder. "
                            "Only baseline files will be checked.", "scan")
        folder = None

    result = {"modified": [], "deleted": [], "new": [], "checked": len(saved_hashes)}
    for file_path, old_hash in saved_hashes.items():
        if os.path.exists(file_path):
            current_hash = calculate_hash(file_path)
            if current_hash is not None and current_hash != old_hash:
                result["modified"].append(file_path)
        else:
            result["deleted"].append(file_path)

    if folder:
        known = set(saved_hashes)
        result["new"] = [p for p in iter_monitored_files(folder) if p not in known]

    for path in result["modified"]:
        emit(sink, WARNING, f"Modified since baseline: {path}", "scan", path)
    for path in result["deleted"]:
        emit(sink, WARNING, f"Deleted since baseline: {path}", "scan", path)
    for path in result["new"]:
        if has_ransomware_extension(path):
            emit(sink, CRITICAL, f"New file with ransomware extension: {path}", "scan", path)
        else:
            emit(sink, INFO, f"New since baseline: {path}", "scan", path)

    changed = len(result["modified"]) + len(result["deleted"])
    if changed:
        emit(sink, WARNING, f"Scan complete: {len(result['modified'])} modified, "
                            f"{len(result['deleted'])} deleted, {len(result['new'])} new "
                            f"({result['checked']:,} files checked)", "scan")
    else:
        emit(sink, SUCCESS, f"Scan complete: all {result['checked']:,} baseline files intact"
                            + (f", {len(result['new'])} new" if result["new"] else ""), "scan")
    return result


# ---------------------------------------------------------------------------
# Honeypot
# ---------------------------------------------------------------------------

HONEYPOT_CONTENT = """CONFIDENTIAL - Account Recovery Codes
=====================================
This file is a SecureVault honeypot. It contains no real data.
Any process that modifies, renames or deletes it is treated as hostile.
"""


def honeypot_path(folder):
    return normalize_path(os.path.join(folder, HONEYPOT_FILE))


def create_honeypot(folder=None, sink=None):
    path = honeypot_path(folder or os.getcwd())
    if os.path.exists(path):
        emit(sink, INFO, f"Honeypot already deployed: {path}", "honeypot", path)
        return path
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(HONEYPOT_CONTENT)
    except OSError as e:
        emit(sink, WARNING, f"Honeypot creation failed: {e}", "honeypot", path)
        return None
    emit(sink, SUCCESS, f"Honeypot deployed: {path}", "honeypot", path)
    return path


# ---------------------------------------------------------------------------
# Real-time file monitoring
# ---------------------------------------------------------------------------

class RealTimeMonitor(FileSystemEventHandler):
    def __init__(self, baseline_hashes, alert_queue=None, mass_threshold=5, mass_window=10, cooldown=15, root=None):
        super().__init__()
        self.baseline_hashes = baseline_hashes
        self.root = root
        self.sink = alert_queue
        self.mass_threshold = mass_threshold
        self.mass_window = mass_window
        self.cooldown = cooldown
        self.change_times = deque()
        self._last_mass_alert = 0.0

    def _skip(self, path):
        return is_app_file(path) or should_ignore(path, self.root)

    def _honeypot_alert(self, action, path):
        emit(self.sink, CRITICAL, f"Honeypot {action}! A process touched the decoy file: {path}", "honeypot", path)
        self._record_change()

    def on_created(self, event):
        if event.is_directory:
            return
        path = normalize_path(event.src_path)
        if is_honeypot(path) or self._skip(path):
            return
        if has_ransomware_extension(path):
            emit(self.sink, CRITICAL, f"File with ransomware extension created: {path}", "file", path)
        else:
            emit(self.sink, INFO, f"New file created: {path}", "file", path)
        file_hash = calculate_hash(path)
        if file_hash:
            self.baseline_hashes[path] = file_hash
        self._record_change()

    def on_modified(self, event):
        if event.is_directory:
            return
        path = normalize_path(event.src_path)
        if is_honeypot(path):
            self._honeypot_alert("modified", path)
            return
        if self._skip(path):
            return
        new_hash = calculate_hash(path)
        if new_hash is None:
            return
        old_hash = self.baseline_hashes.get(path)
        self.baseline_hashes[path] = new_hash
        if old_hash and new_hash != old_hash:
            emit(self.sink, WARNING, f"File modified: {path}", "file", path)
            self._record_change()

    def on_deleted(self, event):
        if event.is_directory:
            return
        path = normalize_path(event.src_path)
        if is_honeypot(path):
            self._honeypot_alert("deleted", path)
            return
        if self._skip(path):
            return
        self.baseline_hashes.pop(path, None)
        emit(self.sink, WARNING, f"File deleted: {path}", "file", path)
        self._record_change()

    def on_moved(self, event):
        if event.is_directory:
            return
        src = normalize_path(event.src_path)
        dest = normalize_path(event.dest_path)
        if is_honeypot(src):
            self._honeypot_alert("renamed", f"{src} -> {dest}")
            return
        if self._skip(src) and self._skip(dest):
            return
        if src in self.baseline_hashes:
            self.baseline_hashes[dest] = self.baseline_hashes.pop(src)
        if has_ransomware_extension(dest) and not has_ransomware_extension(src):
            emit(self.sink, CRITICAL, f"File renamed to ransomware extension: {src} -> {dest}", "file", dest)
        else:
            emit(self.sink, WARNING, f"File renamed: {src} -> {os.path.basename(dest)}", "file", dest)
        self._record_change()

    def _record_change(self):
        now = time.time()
        self.change_times.append(now)
        while self.change_times and now - self.change_times[0] > self.mass_window:
            self.change_times.popleft()
        if len(self.change_times) > self.mass_threshold and now - self._last_mass_alert > self.cooldown:
            self._last_mass_alert = now
            emit(self.sink, CRITICAL,
                 f"MASS FILE CHANGES DETECTED! {len(self.change_times)} changes in "
                 f"{self.mass_window}s - possible ransomware activity!", "file")

    # Kept for backwards compatibility with the v1 API
    def detect_mass_changes(self):
        self._record_change()


def start_real_time_monitor(path, alert_queue=None, stop_event=None, db_file=HASH_DB_FILE):
    """Watch ``path`` until ``stop_event`` is set (or Ctrl+C in the console)."""
    sink = alert_queue
    if not os.path.isdir(path):
        emit(sink, WARNING, f"Cannot monitor missing folder: {path}", "monitor")
        return

    baseline = load_baseline(db_file)
    if baseline is None:
        emit(sink, WARNING, "No baseline found: modifications to existing files are only "
                            "detected after a baseline is created.", "monitor")
        baseline_hashes = {}
    else:
        baseline_hashes = dict(baseline["files"])

    event_handler = RealTimeMonitor(baseline_hashes, sink, root=path)
    observer = Observer()
    try:
        observer.schedule(event_handler, path=path, recursive=True)
        observer.start()
    except OSError as e:
        emit(sink, WARNING, f"Could not start file monitor: {e}", "monitor")
        return

    emit(sink, SUCCESS, f"Real-time monitoring started on {path}", "monitor")
    try:
        while not (stop_event and stop_event.is_set()):
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        observer.stop()
        observer.join()
        emit(sink, INFO, "Real-time monitoring stopped", "monitor")


# ---------------------------------------------------------------------------
# Process (CPU) heuristics
# ---------------------------------------------------------------------------

IGNORED_PROCESSES = {"system idle process", "idle", "system", "registry", "memory compression"}


def monitor_processes_sustained(threshold=30, window_seconds=30, repeat_limit=3, check_interval=3,
                                alert_queue=None, stop_event=None, cooldown=120):
    """Alert on processes using more than ``threshold`` % of total CPU in
    ``repeat_limit`` samples within ``window_seconds``.

    CPU usage is normalised by core count, so 100% means every core is busy.
    """
    sink = alert_queue
    emit(sink, SUCCESS, f"Process monitoring started (alert on sustained CPU > {threshold}%)", "process")
    cpu_count = psutil.cpu_count() or 1
    own_pid = os.getpid()
    high_cpu_times = defaultdict(deque)
    last_alert = {}

    # The first cpu_percent() call per process always returns 0; prime them
    for proc in psutil.process_iter():
        try:
            proc.cpu_percent(interval=None)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    try:
        while True:
            # Event.wait returns early (True) as soon as a stop is requested
            if stop_event:
                if stop_event.wait(check_interval):
                    break
            else:
                time.sleep(check_interval)
            now = time.time()
            alive = set()
            for proc in psutil.process_iter(["pid", "name"]):
                try:
                    pid = proc.info["pid"]
                    name = proc.info["name"] or "?"
                    alive.add(pid)
                    cpu = proc.cpu_percent(interval=None) / cpu_count
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                if pid in (0, own_pid) or name.lower() in IGNORED_PROCESSES or cpu <= threshold:
                    continue
                times = high_cpu_times[pid]
                times.append(now)
                while times and now - times[0] > window_seconds:
                    times.popleft()
                if len(times) >= repeat_limit and now - last_alert.get(pid, 0) > cooldown:
                    last_alert[pid] = now
                    times.clear()
                    emit(sink, WARNING, f"High sustained CPU: {name} (PID {pid}) at {cpu:.1f}%", "process")
            for pid in list(high_cpu_times):
                if pid not in alive:
                    del high_cpu_times[pid]
                    last_alert.pop(pid, None)
    except KeyboardInterrupt:
        pass
    emit(sink, INFO, "Process monitoring stopped", "process")


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------

def launch_gui():
    from gui.main_gui import run_gui
    run_gui()


def main_menu():
    folder_to_monitor = os.getcwd()

    while True:
        print(f"\n===== {APP_NAME} v{APP_VERSION}: Ransomware Detection System =====")
        print(f"Folder: {folder_to_monitor}")
        print("1. Create Baseline Hashes")
        print("2. Check for Changes (Manual Scan)")
        print("3. Create Honeypot File")
        print("4. Start Real-Time File Monitoring")
        print("5. Start Suspicious Process Monitoring (CPU)")
        print("6. Launch GUI Dashboard")
        print("7. Change Folder")
        print("0. Exit")
        try:
            choice = input("Choose an option: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if choice == "1":
            create_baseline(folder_to_monitor)
        elif choice == "2":
            check_for_changes(folder_to_monitor)
        elif choice == "3":
            create_honeypot(folder_to_monitor)
        elif choice == "4":
            print("Starting real-time monitor (press Ctrl+C to stop)...")
            start_real_time_monitor(folder_to_monitor)
        elif choice == "5":
            print("Starting suspicious process monitor (press Ctrl+C to stop)...")
            monitor_processes_sustained()
        elif choice == "6":
            print("Launching GUI Dashboard...")
            launch_gui()
        elif choice == "7":
            new_folder = input("Folder to protect: ").strip().strip('"')
            if os.path.isdir(new_folder):
                folder_to_monitor = os.path.abspath(new_folder)
            else:
                print("Folder not found.")
        elif choice == "0":
            print(f"Exiting {APP_NAME}.")
            break
        else:
            print("Invalid option.")


if __name__ == "__main__":
    if "--gui" in sys.argv[1:]:
        launch_gui()
    else:
        main_menu()
