"""Unit tests for RSA key generation and hybrid encryption."""
import unittest
import os
import tempfile
import shutil

from encryption.rsa_engine import ( # type: ignore
    generate_rsa_keys,
    RSAEngine,
    DEFAULT_PUBLIC_KEY,
    DEFAULT_PRIVATE_KEY,
)


class TestRSAModule(unittest.TestCase):
    """RSA keypair generation, encrypt/decrypt, and error handling."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.pub = os.path.join(self.tmpdir, "public_key.pem")
        self.priv = os.path.join(self.tmpdir, "private_key.pem")

    def tearDown(self):
        if os.path.exists(self.tmpdir):
            shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_rsa_keypair_generated_automatically_if_missing(self):
        """generate_rsa_keys creates key files in the given or default dir."""
        self.assertFalse(os.path.exists(self.pub))
        pub_path, priv_path = generate_rsa_keys(key_dir=self.tmpdir)
        self.assertTrue(os.path.exists(pub_path))
        self.assertTrue(os.path.exists(priv_path))

    def test_public_private_key_files_created(self):
        """Public and private PEM files are created."""
        pub_path, priv_path = generate_rsa_keys(key_dir=self.tmpdir)
        with open(pub_path, "rb") as f:
            self.assertTrue(f.read().startswith(b"-----BEGIN PUBLIC KEY-----"))
        with open(priv_path, "rb") as f:
            self.assertTrue(f.read().startswith(b"-----BEGIN "))

    def test_encryption_decryption_returns_original_data(self):
        """Encrypt then decrypt restores original content."""
        generate_rsa_keys(key_dir=self.tmpdir)
        engine = RSAEngine(public_key_path=self.pub, private_key_path=self.priv)
        plain = os.path.join(self.tmpdir, "plain.bin")
        with open(plain, "wb") as f:
            f.write(b"RSA hybrid test data \x00\x01\x02")
        enc_path = engine.encrypt_file(plain)
        self.assertTrue(os.path.exists(enc_path))
        dec_path = engine.decrypt_file(enc_path)
        with open(dec_path, "rb") as f:
            self.assertEqual(f.read(), b"RSA hybrid test data \x00\x01\x02")

    def test_invalid_key_loading_handled_safely(self):
        """Missing or invalid key paths do not crash; engine loads with None keys."""
        dummy = os.path.join(self.tmpdir, "dummy.txt")
        with open(dummy, "w") as f:
            f.write("x")
        engine = RSAEngine(public_key_path="nonexistent_pub.pem", private_key_path="nonexistent_priv.pem")
        self.assertIsNone(engine._public_key)
        self.assertIsNone(engine._private_key)
        with self.assertRaises((ValueError, Exception)):
            engine.encrypt_file(dummy)

    def test_key_regeneration_works_without_crash(self):
        """Regenerating keys in same dir overwrites and does not crash."""
        generate_rsa_keys(key_dir=self.tmpdir)
        pub2, priv2 = generate_rsa_keys(key_dir=self.tmpdir)
        self.assertTrue(os.path.exists(pub2))
        self.assertTrue(os.path.exists(priv2))
        engine = RSAEngine(public_key_path=pub2, private_key_path=priv2)
        plain = os.path.join(self.tmpdir, "plain2.txt")
        with open(plain, "w") as f:
            f.write("after regen")
        enc = engine.encrypt_file(plain)
        dec = engine.decrypt_file(enc)
        with open(dec) as f:
            self.assertEqual(f.read(), "after regen")


if __name__ == "__main__":
    unittest.main()