import unittest
import os
import sys
import hashlib
import tempfile
import shutil
from types import SimpleNamespace

# Add parent directory to path to import main
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import main
from main import (
    should_ignore, calculate_hash, normalize_path, create_baseline, load_baseline,
    check_for_changes, create_honeypot, honeypot_path, RealTimeMonitor,
    CRITICAL, WARNING, INFO,
)


class Collector(list):
    """Event sink that just records events."""
    def __call__(self, event):
        self.append(event)

    def levels(self):
        return [e.level for e in self]


def fs_event(src, dest=None):
    return SimpleNamespace(src_path=src, dest_path=dest, is_directory=False)


class TestSecureVault(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_file = os.path.join(tempfile.mkdtemp(), "hash_db.json")
        # Keep test runs out of the real activity log
        self._log = main.LOG_FILE
        main.LOG_FILE = os.path.join(os.path.dirname(self.db_file), "test.log")

    def tearDown(self):
        main.LOG_FILE = self._log
        shutil.rmtree(self.test_dir)
        shutil.rmtree(os.path.dirname(self.db_file))

    def write(self, name, content="data"):
        path = os.path.join(self.test_dir, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return normalize_path(path)

    # --- exclusions -------------------------------------------------------

    def test_should_ignore_appdata(self):
        path = os.path.join("C:", "Users", "User", "AppData", "Local", "Temp")
        self.assertTrue(should_ignore(path), "Should ignore AppData directory")

    def test_should_ignore_system_files(self):
        self.assertTrue(should_ignore("NTUSER.DAT"))
        self.assertTrue(should_ignore("ntuser.dat"))
        self.assertTrue(should_ignore("pagefile.sys"))

    def test_should_ignore_extensions(self):
        self.assertTrue(should_ignore("debug.log"))
        self.assertTrue(should_ignore("temp.tmp"))
        self.assertTrue(should_ignore("script.pyc"))
        self.assertTrue(should_ignore("state.vscdb-journal"))

    def test_should_not_ignore_normal_files(self):
        self.assertFalse(should_ignore("C:\\Users\\User\\Documents\\resume.docx"))
        self.assertFalse(should_ignore("important.txt"))
        self.assertFalse(should_ignore("project.py"))

    # --- hashing ----------------------------------------------------------

    def test_calculate_hash(self):
        content = b"Hello SecureVault"
        test_file = os.path.join(self.test_dir, "test.txt")
        with open(test_file, "wb") as f:
            f.write(content)
        self.assertEqual(calculate_hash(test_file), hashlib.sha256(content).hexdigest())

    def test_calculate_hash_missing_file(self):
        self.assertIsNone(calculate_hash(os.path.join(self.test_dir, "nope.txt")))

    def test_normalize_path(self):
        norm = normalize_path("C:/Users/User/Documents/../Downloads")
        self.assertIn(os.sep, norm)
        self.assertIn("Downloads", norm)
        self.assertNotIn("Documents", norm)

    # --- baseline & scan --------------------------------------------------

    def test_baseline_records_folder_and_files(self):
        a = self.write("a.txt")
        self.write("skip.log")
        self.write(os.path.join("node_modules", "x.js"))
        sink = Collector()
        data = create_baseline(self.test_dir, sink, db_file=self.db_file)
        self.assertEqual(list(data["files"]), [a])
        self.assertEqual(load_baseline(self.db_file)["files"], data["files"])
        self.assertEqual(sink.levels()[-1], "success")

    def test_scan_detects_modified_deleted_and_new(self):
        a = self.write("a.txt")
        b = self.write("b.txt")
        create_baseline(self.test_dir, Collector(), db_file=self.db_file)
        self.write("a.txt", "changed")
        os.remove(b)
        c = self.write("c.txt")
        result = check_for_changes(self.test_dir, Collector(), db_file=self.db_file)
        self.assertEqual(result["modified"], [a])
        self.assertEqual(result["deleted"], [b])
        self.assertEqual(result["new"], [c])

    def test_scan_clean(self):
        self.write("a.txt")
        create_baseline(self.test_dir, Collector(), db_file=self.db_file)
        sink = Collector()
        result = check_for_changes(self.test_dir, sink, db_file=self.db_file)
        self.assertEqual(result["modified"] + result["deleted"] + result["new"], [])
        self.assertEqual(sink.levels(), ["success"])

    def test_scan_without_baseline(self):
        sink = Collector()
        self.assertIsNone(check_for_changes(self.test_dir, sink, db_file=self.db_file))
        self.assertEqual(sink.levels(), [WARNING])

    def test_legacy_baseline_format(self):
        with open(self.db_file, "w") as f:
            f.write('{"C:\\\\x.txt": "abc"}')
        self.assertEqual(load_baseline(self.db_file)["files"], {"C:\\x.txt": "abc"})

    # --- honeypot & real-time monitor -------------------------------------

    def test_honeypot_created_in_folder_and_excluded_from_baseline(self):
        path = create_honeypot(self.test_dir, Collector())
        self.assertEqual(path, honeypot_path(self.test_dir))
        self.assertTrue(os.path.exists(path))
        data = create_baseline(self.test_dir, Collector(), db_file=self.db_file)
        self.assertNotIn(path, data["files"])

    def test_honeypot_tampering_is_critical(self):
        sink = Collector()
        monitor = RealTimeMonitor({}, sink, root=self.test_dir)
        path = honeypot_path(self.test_dir)
        monitor.on_modified(fs_event(path))
        monitor.on_deleted(fs_event(path))
        self.assertEqual(sink.levels(), [CRITICAL, CRITICAL])

    def test_monitor_detects_modification(self):
        a = self.write("a.txt")
        sink = Collector()
        monitor = RealTimeMonitor({a: calculate_hash(a)}, sink, root=self.test_dir)
        monitor.on_modified(fs_event(a))  # unchanged content: no alert
        self.assertEqual(sink, [])
        self.write("a.txt", "encrypted!")
        monitor.on_modified(fs_event(a))
        self.assertEqual(sink.levels(), [WARNING])

    def test_monitor_flags_ransomware_rename(self):
        a = self.write("report.docx")
        sink = Collector()
        RealTimeMonitor({}, sink, root=self.test_dir).on_moved(fs_event(a, a + ".locked"))
        self.assertEqual(sink.levels(), [CRITICAL])

    def test_mass_change_detection(self):
        sink = Collector()
        monitor = RealTimeMonitor({}, sink, mass_threshold=5, root=self.test_dir)
        for i in range(7):
            monitor.on_deleted(fs_event(os.path.join(self.test_dir, f"f{i}.txt")))
        self.assertEqual(sink.levels().count(CRITICAL), 1, "Mass alert should fire once per cooldown")

    def test_folder_inside_excluded_dir_still_monitored(self):
        root = os.path.join(self.test_dir, "AppData", "Project")
        path = normalize_path(os.path.join(root, "notes.txt"))
        self.assertTrue(should_ignore(path))
        self.assertFalse(should_ignore(path, root))

    def test_monitor_ignores_excluded_files(self):
        sink = Collector()
        RealTimeMonitor({}, sink, root=self.test_dir).on_created(fs_event(os.path.join(self.test_dir, "x.tmp")))
        self.assertEqual(sink, [])


if __name__ == '__main__':
    unittest.main()
