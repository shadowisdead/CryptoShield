import unittest
import os
from encryption.chacha_engine import ChaChaEngine #type: ignore


class TestChaCha(unittest.TestCase):

    def setUp(self):
        self.file = "chacha.txt"
        with open(self.file, "w") as f:
            f.write("ChaCha test")

        self.engine = ChaChaEngine("Password123!")

    def tearDown(self):
        for f in os.listdir():
            if f.startswith("chacha"):
                try:
                    os.remove(f)
                except:
                    pass

    def test_encrypt_decrypt(self):
        enc = self.engine.encrypt_file(self.file)
        dec = self.engine.decrypt_file(enc)

        with open(dec) as f:
            self.assertEqual(f.read(), "ChaCha test")

    def test_authentication_failure(self):
        enc = self.engine.encrypt_file(self.file)
        wrong = ChaChaEngine("badpass")

        with self.assertRaises(Exception):
            wrong.decrypt_file(enc)

    def test_output_file_created(self):
        enc = self.engine.encrypt_file(self.file)
        self.assertTrue(os.path.isfile(enc))


if __name__ == "__main__":
    unittest.main()
