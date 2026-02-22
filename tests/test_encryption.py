"""Unit tests for encryption engines (AES, ChaCha) — file roundtrip and safety."""
import unittest
import os
import tempfile
import shutil

from encryption.aes_engine import AESEngine # type: ignore
from encryption.chacha_engine import ChaChaEngine # type: ignore


class TestEncryptionEngines(unittest.TestCase):
    """File encrypt -> decrypt restores identical content; wrong password fails."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.password = "TestP@ssw0rd123!"

    def tearDown(self):
        if os.path.exists(self.tmpdir):
            shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _path(self, name):
        return os.path.join(self.tmpdir, name)

    def test_aes_file_encrypt_decrypt_restores_identical(self):
        plain = self._path("plain.txt")
        with open(plain, "wb") as f:
            f.write(b"Secret data 123 \n\x00\x01")
        engine = AESEngine(self.password)
        enc = engine.encrypt_file(plain)
        dec = engine.decrypt_file(enc)
        with open(dec, "rb") as f:
            self.assertEqual(f.read(), b"Secret data 123 \n\x00\x01")

    def test_chacha_file_encrypt_decrypt_restores_identical(self):
        plain = self._path("plain.txt")
        with open(plain, "wb") as f:
            f.write(b"ChaCha secret")
        engine = ChaChaEngine(self.password)
        enc = engine.encrypt_file(plain)
        dec = engine.decrypt_file(enc)
        with open(dec, "rb") as f:
            self.assertEqual(f.read(), b"ChaCha secret")

    def test_encryption_produces_different_ciphertext_each_run(self):
        """IV/salt randomness ensures different ciphertext per encryption."""
        plain = self._path("plain.txt")
        with open(plain, "wb") as f:
            f.write(b"Same content")
        engine = AESEngine(self.password)
        enc1 = engine.encrypt_file(plain, output_path=self._path("out1.enc"))
        enc2 = engine.encrypt_file(plain, output_path=self._path("out2.enc"))
        with open(enc1, "rb") as f1, open(enc2, "rb") as f2:
            self.assertNotEqual(f1.read(), f2.read())

    def test_wrong_password_fails_safely(self):
        """Decryption with wrong password raises and does not produce valid file."""
        plain = self._path("plain.txt")
        with open(plain, "w") as f:
            f.write("content")
        engine = AESEngine(self.password)
        enc = engine.encrypt_file(plain)
        wrong = AESEngine("WrongPassword!")
        with self.assertRaises(Exception):
            wrong.decrypt_file(enc)


if __name__ == "__main__":
    unittest.main()
