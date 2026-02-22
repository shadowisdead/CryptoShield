"""Unit tests for file operations: secure delete and folder watcher."""
import unittest
import os
import tempfile
import shutil
import time

from core.secure_delete import secure_delete #type: ignore

try:
    from core.folder_watcher import start_folder_watch, stop_folder_watch, HAS_WATCHDOG #type: ignore
except Exception:
    HAS_WATCHDOG = False
    start_folder_watch = stop_folder_watch = None


class TestSecureDelete(unittest.TestCase):
    """Secure delete removes file completely."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        if os.path.exists(self.tmpdir):
            shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_secure_delete_removes_file_completely(self):
        path = os.path.join(self.tmpdir, "to_delete.txt")
        with open(path, "w") as f:
            f.write("content")
        self.assertTrue(os.path.isfile(path))
        result = secure_delete(path)
        self.assertTrue(result)
        self.assertFalse(os.path.exists(path))

    def test_secure_delete_nonexistent_returns_false(self):
        result = secure_delete(os.path.join(self.tmpdir, "nonexistent.txt"))
        self.assertFalse(result)


class TestFolderWatcher(unittest.TestCase):
    """Folder watcher detects new file event (if watchdog available)."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.received = []

    def tearDown(self):
        if hasattr(self, "observer") and self.observer and HAS_WATCHDOG:
            try:
                stop_folder_watch(self.observer)
            except Exception:
                pass
        if os.path.exists(self.tmpdir):
            shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_folder_watcher_detects_new_file_event(self):
        if not HAS_WATCHDOG or not start_folder_watch:
            self.skipTest("watchdog not installed")
        def on_new(p):
            self.received.append(p)
        self.observer = start_folder_watch(self.tmpdir, on_new, extensions={".txt"})
        self.assertIsNotNone(self.observer)
        new_file = os.path.join(self.tmpdir, "new_file.txt")
        with open(new_file, "w") as f:
            f.write("trigger")
        time.sleep(0.5)
        stop_folder_watch(self.observer)
        self.assertIn(new_file, self.received)


if __name__ == "__main__":
    unittest.main()
