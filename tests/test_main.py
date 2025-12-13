import unittest
import os
import sys
import tempfile
import shutil
from pathlib import Path

# Add parent directory to path to import main
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import should_ignore, calculate_hash, normalize_path, EXCLUDED_DIRS

class TestSecureVault(unittest.TestCase):
    def setUp(self):
        # Create a temporary directory
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        # Remove the directory after the test
        shutil.rmtree(self.test_dir)

    def test_should_ignore_appdata(self):
        """Test if AppData paths are ignored"""
        path = os.path.join("C:", "Users", "User", "AppData", "Local", "Temp")
        self.assertTrue(should_ignore(path), "Should ignore AppData directory")

    def test_should_ignore_system_files(self):
        """Test if system files like NTUSER.DAT are ignored"""
        self.assertTrue(should_ignore("NTUSER.DAT"), "Should ignore NTUSER.DAT")
        self.assertTrue(should_ignore("ntuser.dat"), "Should ignore ntuser.dat (case insensitive)")
        self.assertTrue(should_ignore("pagefile.sys"), "Should ignore pagefile.sys")

    def test_should_ignore_extensions(self):
        """Test if noisy extensions are ignored"""
        self.assertTrue(should_ignore("debug.log"), "Should ignore .log files")
        self.assertTrue(should_ignore("temp.tmp"), "Should ignore .tmp files")
        self.assertTrue(should_ignore("script.pyc"), "Should ignore .pyc files")
        self.assertTrue(should_ignore("state.vscdb-journal"), "Should ignore .vscdb-journal files")

    def test_should_not_ignore_normal_files(self):
        """Test if normal user files are NOT ignored"""
        self.assertFalse(should_ignore("C:\\Users\\User\\Documents\\resume.docx"), "Should NOT ignore .docx")
        self.assertFalse(should_ignore("important.txt"), "Should NOT ignore .txt")
        self.assertFalse(should_ignore("project.py"), "Should NOT ignore .py")

    def test_calculate_hash(self):
        """Test SHA256 hashing"""
        test_file = os.path.join(self.test_dir, "test.txt")
        content = b"Hello SecureVault"
        with open(test_file, "wb") as f:
            f.write(content)
        
        calculated = calculate_hash(test_file)
        print(f"\nCalculated Hash: {calculated}")
        import hashlib
        expected_hash = hashlib.sha256(content).hexdigest()
        self.assertEqual(calculated, expected_hash, "Hash calculation incorrect")

    def test_normalize_path(self):
        """Test path normalization"""
        path = "C:/Users/User/Documents/../Downloads"
        norm = normalize_path(path)
        self.assertTrue("\\" in norm, "Should use system separator")
        self.assertTrue("Downloads" in norm, "Should resolve path")
        self.assertFalse("Documents" in norm, "Should remove .. components")

if __name__ == '__main__':
    unittest.main()
