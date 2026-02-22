import unittest
import os
from encryption.rsa_engine import generate_rsa_keys, RSAEngine # type: ignore


class TestRSA(unittest.TestCase):

    def test_key_generation(self):
        pub, priv = generate_rsa_keys()
        self.assertTrue(os.path.exists(pub))
        self.assertTrue(os.path.exists(priv))

    def test_encrypt_decrypt(self):
        with open("rsa.txt", "w") as f:
            f.write("RSA test")

        engine = RSAEngine()
        enc = engine.encrypt_file("rsa.txt")
        dec = engine.decrypt_file(enc)

        with open(dec) as f:
            self.assertEqual(f.read(), "RSA test")

    def test_missing_key_handling(self):
        engine = RSAEngine(public_key_path="missing.pem")
        self.assertIsNotNone(engine)


if __name__ == "__main__":
    unittest.main()
