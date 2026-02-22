"""Unit tests for integrity hashing."""
import unittest
import os
import tempfile
import shutil

from integrity.hasher import Hasher # type: ignore


class TestIntegrity(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        if os.path.exists(self.tmpdir):
            shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_hash_generation(self):
        path = os.path.join(self.tmpdir, "hash.txt")
        with open(path, "w") as f:
            f.write("abc")
        h = Hasher()
        digest = h.generate_hash(path)
        self.assertIsInstance(digest, str)
        self.assertEqual(len(digest), 64)

    def test_hash_verify_success(self):
        path = os.path.join(self.tmpdir, "hash2.txt")
        with open(path, "w") as f:
            f.write("abc")
        hasher = Hasher()
        digest = hasher.generate_hash(path)
        self.assertTrue(hasher.verify_hash(path, digest))

    def test_hash_verify_fail(self):
        path = os.path.join(self.tmpdir, "hash3.txt")
        with open(path, "w") as f:
            f.write("abc")
        hasher = Hasher()
        self.assertFalse(hasher.verify_hash(path, "wrong"))


if __name__ == "__main__":
    unittest.main()
