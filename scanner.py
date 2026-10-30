# scanner.py
"""SecureVault antivirus engine: on-demand scans, on-access scans and quarantine.

Detection layers, from most to least certain:

1. Hash signatures: SHA-256 lists in ``signatures/`` (you can import more,
   e.g. the free MalwareBazaar hash exports).
2. The EICAR anti-virus test file.
3. Optional YARA rules from ``signatures/yara`` when ``yara-python`` is installed.
4. Heuristics: disguised executables, ransomware commands in scripts,
   auto-running Office macros, ransom notes and more. Each match adds to a
   0-100 score; 40+ is suspicious and 70+ is malicious.
5. Optional Microsoft Defender engine (``MpCmdRun.exe``) for deep scans.
"""
import os
import re
import glob
import json
import math
import uuid
import queue
import shutil
import hashlib
import zipfile
import datetime
import threading
import subprocess
import time
from dataclasses import dataclass, field, asdict

from main import (
    APP_DIR, RANSOMWARE_EXTENSIONS, emit, normalize_path, INFO, SUCCESS, WARNING, CRITICAL,
)

SIGNATURE_DIR = os.path.join(APP_DIR, "signatures")
HASH_SIGNATURES = os.path.join(SIGNATURE_DIR, "hashes.txt")
USER_SIGNATURES = os.path.join(SIGNATURE_DIR, "user_hashes.txt")
YARA_DIR = os.path.join(SIGNATURE_DIR, "yara")
QUARANTINE_DIR = os.path.join(APP_DIR, "quarantine")

CLEAN, SUSPICIOUS, MALICIOUS = "clean", "suspicious", "malicious"
SUSPICIOUS_SCORE, MALICIOUS_SCORE = 40, 70

HEAD_BYTES = 4 * 1024 * 1024        # content inspected by heuristics
MAX_HASH_BYTES = 512 * 1024 * 1024  # larger files are skipped for hashing

# Built from pieces so this source file is never itself flagged as the test file
_EICAR = ("X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-" + "TEST-FILE!$H+H*").encode("ascii")
EICAR_SHA256 = hashlib.sha256(_EICAR).hexdigest()

EXECUTABLE_EXTS = {".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
                   ".wsf", ".wsh", ".ps1", ".hta", ".msi", ".jar", ".lnk", ".dll", ".cpl"}
DECOY_EXTS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".rtf", ".jpg",
              ".jpeg", ".png", ".gif", ".mp3", ".mp4", ".avi", ".zip", ".rar", ".csv"}
SCRIPT_EXTS = {".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".bat", ".cmd"}
OFFICE_EXTS = {".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm", ".ppt", ".pptx", ".pptm", ".dotm"}
SKIP_DIRS = {".git", "node_modules", "__pycache__", "$recycle.bin", "system volume information"}

SCRIPT_RULES = [
    (r"vssadmin(\.exe)?\s+delete\s+shadows", 70, "Deletes Windows shadow copies (classic ransomware step)"),
    (r"wmic(\.exe)?\s+shadowcopy\s+delete", 70, "Deletes Windows shadow copies (classic ransomware step)"),
    (r"bcdedit(\.exe)?.{0,40}recoveryenabled\s+no", 60, "Disables Windows recovery"),
    (r"wbadmin(\.exe)?\s+delete\s+(catalog|backup|systemstatebackup)", 60, "Deletes backups"),
    (r"set-mppreference.{0,80}disable", 60, "Tries to switch off Microsoft Defender"),
    (r"add-mppreference\s+-exclusion", 50, "Adds Microsoft Defender exclusions"),
    (r"cipher(\.exe)?\s+/w", 40, "Wipes deleted data from the disk"),
    (r"\s-(e|en|enc|encodedcommand)\s+[a-z0-9+/=]{40,}", 45, "Runs an encoded (hidden) PowerShell command"),
    (r"frombase64string", 15, "Decodes hidden Base64 data"),
    (r"(downloadstring|downloadfile|downloaddata|invoke-webrequest|\biwr\s|net\.webclient|"
     r"bitsadmin(\.exe)?\s+/transfer|urldownloadtofile|msxml2\.xmlhttp)", 20, "Downloads content from the internet"),
    (r"\b(iex|invoke-expression)\b", 25, "Executes dynamically built code"),
    (r"(-windowstyle\s+hidden|\s-w\s+hidden|-nop\s.*-w\s+1)", 20, "Runs in a hidden window"),
    (r"reg(\.exe)?\s+add\s.{0,80}\\currentversion\\run", 30, "Adds itself to Windows startup"),
    (r"schtasks(\.exe)?\s+/create", 20, "Creates a scheduled task"),
    (r"wscript\.shell|shell\.application", 15, "Launches programs through Windows Script Host"),
]
_SCRIPT_RULES = [(re.compile(p, re.IGNORECASE), s, d) for p, s, d in SCRIPT_RULES]

MACRO_AUTORUN = (b"autoopen", b"auto_open", b"document_open", b"workbook_open", b"autoexec")
MACRO_DANGEROUS = (b"shell", b"wscript", b"createobject", b"urldownloadtofile", b"powershell", b"cmd.exe")

RANSOM_NOTE = re.compile(r"(how|help|read|restore|decrypt|recover)[\s_\-!]*(to[\s_\-]*)?"
                         r"(decrypt|recover|restore|unlock|files|instructions?)|_readme\.txt$|ransom",
                         re.IGNORECASE)
RANSOM_WORDS = (b"bitcoin", b"btc", b".onion", b"tor browser", b"decrypt", b"private key", b"your files")


@dataclass
class Finding:
    path: str
    verdict: str
    score: int
    threat: str
    reasons: list = field(default_factory=list)
    engine: str = "SecureVault"
    sha256: str = None

    @property
    def name(self):
        return os.path.basename(self.path)

    def to_dict(self):
        return asdict(self)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def entropy(data):
    if not data:
        return 0.0
    counts = [data.count(i) for i in range(256)]
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


def _office_macro(data):
    """Lower-cased macro code of an Office document, or None if it has no macros."""
    if data[:2] == b"PK":  # Office Open XML (zip)
        try:
            import io
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                parts = [n for n in z.namelist() if n.lower().endswith("vbaproject.bin")]
                return b"".join(z.read(n) for n in parts).lower() if parts else None
        except (zipfile.BadZipFile, OSError, RuntimeError):
            return None
    if data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":  # Legacy OLE .doc/.xls
        lowered = data.lower()
        return lowered if b"_vba_project" in lowered or b"vba" in lowered and b"attribut" in lowered else None
    return None


def find_defender():
    """Path of Microsoft Defender's command-line scanner, if installed."""
    candidates = sorted(glob.glob(r"C:\ProgramData\Microsoft\Windows Defender\Platform\*\MpCmdRun.exe"),
                        reverse=True)
    candidates.append(r"C:\Program Files\Windows Defender\MpCmdRun.exe")
    return next((c for c in candidates if os.path.isfile(c)), None)


def quick_scan_targets():
    """Places malware usually lands: downloads, desktop, temp and startup folders."""
    home = os.path.expanduser("~")
    paths = [
        os.path.join(home, "Downloads"),
        os.path.join(home, "Desktop"),
        os.environ.get("TEMP", ""),
        os.path.join(os.environ.get("APPDATA", ""), "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
        os.path.join(os.environ.get("PUBLIC", r"C:\Users\Public"), "Downloads"),
    ]
    return [normalize_path(p) for p in paths if p and os.path.isdir(p)]


def full_scan_targets():
    return [normalize_path(os.path.expanduser("~"))]


class Scanner:
    def __init__(self, signature_files=None, yara_dir=YARA_DIR):
        self.signature_files = signature_files or [HASH_SIGNATURES, USER_SIGNATURES]
        self.yara_dir = yara_dir
        self.defender = find_defender()
        self.reload()

    # ----------------------------------------------------------- signatures

    def reload(self):
        self.signatures = {EICAR_SHA256: "EICAR-Test-File"}
        for path in self.signature_files:
            self.signatures.update(load_hash_file(path))
        self.yara_rules = None
        try:
            import yara
            files = {os.path.basename(p): p for p in glob.glob(os.path.join(self.yara_dir, "*.yar*"))}
            if files:
                self.yara_rules = yara.compile(filepaths=files)
        except Exception:  # yara-python not installed or rules invalid: skip this layer
            self.yara_rules = None

    @property
    def signature_count(self):
        return len(self.signatures)

    @property
    def engines(self):
        return {"SecureVault": True, "YARA": self.yara_rules is not None, "Microsoft Defender": bool(self.defender)}

    # -------------------------------------------------------------- scanning

    def scan_content(self, name, data, sha256=None, path=None):
        """Classify ``data`` (the start of a file called ``name``). Returns a Finding or None."""
        path = path or name
        sha256 = sha256 or hashlib.sha256(data).hexdigest()
        if sha256 in self.signatures:
            return Finding(path, MALICIOUS, 100, self.signatures[sha256], ["Matches a known malware signature"], sha256=sha256)
        if _EICAR in data[:4096]:
            return Finding(path, MALICIOUS, 100, "EICAR-Test-File", ["Anti-virus test file"], sha256=sha256)
        if self.yara_rules is not None:
            try:
                matches = self.yara_rules.match(data=data)
            except Exception:
                matches = []
            if matches:
                return Finding(path, MALICIOUS, 90, f"YARA:{matches[0].rule}",
                               [f"Matches YARA rule {m.rule}" for m in matches], engine="YARA", sha256=sha256)

        score, reasons = 0, []

        def hit(points, reason):
            nonlocal score
            score += points
            if reason not in reasons:
                reasons.append(reason)

        lower_name = os.path.basename(name).lower()
        stem, ext = os.path.splitext(lower_name)
        inner_ext = os.path.splitext(stem.rstrip(" ."))[1]
        is_pe = data[:2] == b"MZ"

        if "\u202e" in name:
            hit(80, "File name uses a hidden right-to-left character to fake its extension")
        if ext in EXECUTABLE_EXTS and inner_ext in DECOY_EXTS:
            hit(75, f"Executable disguised with a double extension ({inner_ext}{ext})")
        elif ext in EXECUTABLE_EXTS and re.search(r"\s{5,}\.\w+$", lower_name):
            hit(60, "Executable hides its extension behind spaces")
        if is_pe and ext in DECOY_EXTS:
            hit(80, f"Windows program pretending to be a {ext} file")
        if ext in RANSOMWARE_EXTENSIONS:
            hit(50, f"Has a ransomware extension ({ext}); the file may have been encrypted")

        if ext in SCRIPT_EXTS or ext == ".lnk":
            text = data.decode("utf-8", errors="ignore")
            if "\x00" in text[:200]:  # UTF-16 scripts
                text = data.decode("utf-16", errors="ignore")
            for rule, points, reason in _SCRIPT_RULES:
                if rule.search(text):
                    hit(points, reason)
            if ext == ".lnk" and re.search(r"powershell|cmd(\.exe)?\s*/c|mshta|wscript", text, re.IGNORECASE):
                hit(50, "Shortcut secretly runs a command")

        if ext in OFFICE_EXTS:
            macro = _office_macro(data)
            if macro is not None:
                hit(15, "Document contains macros")
                if any(k in macro for k in MACRO_AUTORUN):
                    hit(25, "Macro runs automatically when the document opens")
                if any(k in macro for k in MACRO_DANGEROUS):
                    hit(30, "Macro can launch programs or download files")

        if ext in (".txt", ".html", ".htm", ".hta", ".url") and RANSOM_NOTE.search(stem):
            lowered = data[:20000].lower()
            words = sum(1 for w in RANSOM_WORDS if w in lowered)
            if words >= 2:
                hit(70, "Ransom note asking for payment to decrypt files")
            elif words:
                hit(30, "Looks like a ransom note")

        if is_pe and ext in EXECUTABLE_EXTS and entropy(data[:256 * 1024]) > 7.4:
            hit(15, "Executable is packed or encrypted (common in malware)")
        if path and (ext in EXECUTABLE_EXTS or is_pe):
            lowered_path = path.lower()
            if "\\start menu\\programs\\startup\\" in lowered_path:
                hit(25, "Starts automatically with Windows")

        score = min(score, 99)
        if score < SUSPICIOUS_SCORE:
            return None
        verdict = MALICIOUS if score >= MALICIOUS_SCORE else SUSPICIOUS
        threat = "Heur." + ("Ransom" if "ransom" in " ".join(reasons).lower() or "shadow" in " ".join(reasons).lower()
                            else "Trojan" if verdict == MALICIOUS else "Suspicious")
        return Finding(path, verdict, score, threat, reasons, sha256=sha256)

    def scan_file(self, path):
        """Scan one file. Returns a Finding, or None if clean or unreadable."""
        try:
            size = os.path.getsize(path)
            with open(path, "rb") as f:
                head = f.read(HEAD_BYTES)
            sha = hashlib.sha256(head).hexdigest() if size <= HEAD_BYTES else (
                sha256_file(path) if size <= MAX_HASH_BYTES else "")
        except OSError:
            return None
        return self.scan_content(os.path.basename(path), head, sha256=sha, path=normalize_path(path))

    def scan(self, targets, sink=None, stop_event=None, progress=None, use_defender=False, label="Scan"):
        """Scan files and folders. Reports findings to ``sink`` and returns a summary dict."""
        started = time.time()
        targets = [normalize_path(t) for t in targets if os.path.exists(t)]
        emit(sink, INFO, f"{label} started: {', '.join(targets) or 'nothing to scan'}", "scanner", log=False)
        files = []
        for target in targets:
            files.extend(iter_scan_files(target))
            if stop_event and stop_event.is_set():
                break

        findings, scanned = {}, 0
        for i, path in enumerate(files):
            if stop_event and stop_event.is_set():
                break
            if progress:
                progress(i, len(files), path)
            finding = self.scan_file(path)
            scanned += 1
            if finding:
                findings[os.path.normcase(finding.path)] = finding
                self._report(sink, finding)

        cancelled = bool(stop_event and stop_event.is_set())
        if use_defender and self.defender and not cancelled:
            if progress:
                progress(len(files), len(files), "Microsoft Defender deep scan...")
            for finding in self.defender_scan(targets, stop_event):
                key = os.path.normcase(finding.path)
                if key in findings:
                    findings[key].engine += " + Microsoft Defender"
                    findings[key].threat = finding.threat
                    findings[key].verdict, findings[key].score = MALICIOUS, 100
                else:
                    findings[key] = finding
                    self._report(sink, finding)
        if progress:
            progress(len(files), len(files), "")

        result = {
            "targets": targets,
            "scanned": scanned,
            "findings": list(findings.values()),
            "malicious": sum(1 for f in findings.values() if f.verdict == MALICIOUS),
            "suspicious": sum(1 for f in findings.values() if f.verdict == SUSPICIOUS),
            "duration": time.time() - started,
            "cancelled": cancelled,
        }
        word = "cancelled" if cancelled else "complete"
        if result["malicious"]:
            emit(sink, CRITICAL, f"{label} {word}: {result['malicious']} threat(s) and {result['suspicious']} "
                                 f"suspicious file(s) in {scanned:,} files", "scanner")
        elif result["suspicious"]:
            emit(sink, WARNING, f"{label} {word}: {result['suspicious']} suspicious file(s) in {scanned:,} files",
                 "scanner")
        else:
            emit(sink, SUCCESS, f"{label} {word}: no threats in {scanned:,} files", "scanner")
        return result

    @staticmethod
    def _report(sink, finding):
        level = CRITICAL if finding.verdict == MALICIOUS else WARNING
        word = "Malware detected" if finding.verdict == MALICIOUS else "Suspicious file"
        emit(sink, level, f"{word} ({finding.threat}): {finding.path}", "scanner", finding.path,
             data=finding.to_dict())

    def defender_scan(self, targets, stop_event=None):
        """Run Microsoft Defender on each target without letting it remove anything."""
        found = []
        for target in targets:
            try:
                proc = subprocess.Popen(
                    [self.defender, "-Scan", "-ScanType", "3", "-File", target, "-DisableRemediation"],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace",
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            except OSError:
                continue
            while proc.poll() is None:
                if stop_event and stop_event.wait(0.5):
                    proc.kill()
                    return found
                elif not stop_event:
                    time.sleep(0.5)
            found.extend(parse_defender_output(proc.stdout.read()))
        return found


def parse_defender_output(output):
    findings, threat = [], None
    for line in output.splitlines():
        m = re.match(r"\s*Threat\s*:\s*(.+)", line)
        if m:
            threat = m.group(1).strip()
            continue
        m = re.match(r"\s*file\s*:\s*(.+)", line, re.IGNORECASE)
        if m and threat:
            path = m.group(1).strip().split("->")[0]
            findings.append(Finding(normalize_path(path), MALICIOUS, 100, threat,
                                    ["Detected by Microsoft Defender"], engine="Microsoft Defender"))
    return findings


def iter_scan_files(target):
    if os.path.isfile(target):
        yield target
        return
    quarantine = os.path.normcase(QUARANTINE_DIR)
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d.lower() not in SKIP_DIRS
                   and os.path.normcase(os.path.join(root, d)) != quarantine]
        for name in files:
            yield os.path.join(root, name)


def load_hash_file(path):
    """Read ``sha256 [name]`` lines (comments with #). Any 64-hex token counts as a hash."""
    signatures = {}
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                m = re.search(r"\b([0-9a-fA-F]{64})\b", line)
                if m:
                    rest = line.replace(m.group(1), "").strip(" ,;\t\"'")
                    signatures[m.group(1).lower()] = rest[:80] or "Malware.Generic"
    except OSError:
        pass
    return signatures


def import_signatures(source, target=USER_SIGNATURES):
    """Append the SHA-256 hashes found in ``source`` to the user signature file."""
    new = load_hash_file(source)
    existing = load_hash_file(target)
    added = {h: n for h, n in new.items() if h not in existing}
    if added:
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "a", encoding="utf-8") as f:
            for h, n in added.items():
                f.write(f"{h}  {n}\n")
    return len(added)


# ---------------------------------------------------------------------------
# Quarantine
# ---------------------------------------------------------------------------

_QKEY = 0xA5
_NEUTRALIZE = bytes(i ^ _QKEY for i in range(256))  # XOR is its own inverse


def quarantine_file(path, finding=None, quarantine_dir=QUARANTINE_DIR):
    """Move ``path`` into quarantine in a neutralized (non-runnable) form."""
    os.makedirs(quarantine_dir, exist_ok=True)
    qid = uuid.uuid4().hex
    with open(path, "rb") as f:
        data = f.read()
    blob = os.path.join(quarantine_dir, qid + ".qtn")
    with open(blob, "wb") as f:
        f.write(data.translate(_NEUTRALIZE))
    entry = {
        "id": qid,
        "name": os.path.basename(path),
        "original_path": normalize_path(os.path.abspath(path)),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "threat": finding.threat if finding else "Manual",
        "verdict": finding.verdict if finding else SUSPICIOUS,
        "reasons": finding.reasons if finding else [],
        "quarantined_at": datetime.datetime.now().isoformat(timespec="seconds"),
    }
    try:
        os.remove(path)
    except OSError:
        os.remove(blob)
        raise
    with open(os.path.join(quarantine_dir, qid + ".json"), "w", encoding="utf-8") as f:
        json.dump(entry, f, indent=2)
    return entry


def list_quarantine(quarantine_dir=QUARANTINE_DIR):
    entries = []
    for meta in glob.glob(os.path.join(quarantine_dir, "*.json")):
        try:
            with open(meta, "r", encoding="utf-8") as f:
                entries.append(json.load(f))
        except (OSError, ValueError):
            continue
    return sorted(entries, key=lambda e: e.get("quarantined_at", ""), reverse=True)


def restore_quarantined(qid, quarantine_dir=QUARANTINE_DIR):
    """Put a quarantined file back where it came from. Returns the restored path."""
    meta_path = os.path.join(quarantine_dir, qid + ".json")
    with open(meta_path, "r", encoding="utf-8") as f:
        entry = json.load(f)
    target = entry["original_path"]
    if os.path.exists(target):
        stem, ext = os.path.splitext(target)
        target = f"{stem} (restored){ext}"
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(os.path.join(quarantine_dir, qid + ".qtn"), "rb") as f:
        data = f.read().translate(_NEUTRALIZE)
    with open(target, "wb") as f:
        f.write(data)
    delete_quarantined(qid, quarantine_dir)
    return target


def delete_quarantined(qid, quarantine_dir=QUARANTINE_DIR):
    for ext in (".qtn", ".json"):
        try:
            os.remove(os.path.join(quarantine_dir, qid + ext))
        except FileNotFoundError:
            pass


# ---------------------------------------------------------------------------
# On-access scanning
# ---------------------------------------------------------------------------

class OnAccessScanner:
    """Scans files handed to it by the real-time monitor on a background thread."""
    def __init__(self, scanner, sink=None, max_size=50 * 1024 * 1024):
        self.scanner = scanner
        self.sink = sink
        self.max_size = max_size
        self._queue = queue.Queue()
        self._recent = {}
        self._thread = threading.Thread(target=self._run, name="securevault-onaccess", daemon=True)
        self._thread.start()

    def submit(self, path):
        now = time.time()
        if now - self._recent.get(path, 0) < 2:  # Editors fire several events per save
            return
        self._recent[path] = now
        if len(self._recent) > 5000:
            self._recent.clear()
        self._queue.put(path)

    def stop(self):
        self._queue.put(None)

    def _run(self):
        while True:
            path = self._queue.get()
            if path is None:
                return
            try:
                if os.path.getsize(path) > self.max_size:
                    continue
            except OSError:
                continue
            time.sleep(0.3)  # Let the writer finish
            finding = self.scanner.scan_file(path)
            if finding:
                Scanner._report(self.sink, finding)
