import unittest
import os
from encryption.aes_engine import AESEngine #type: ignore


class TestAES(unittest.TestCase):

    def setUp(self):
        self.filename = "aes_test.txt"
        with open(self.filename, "w") as f:
            f.write("AES encryption test data")

        self.engine = AESEngine("StrongPass123!")

    def tearDown(self):
        for f in os.listdir():
            if f.startswith("aes_test"):
                try:
                    os.remove(f)
                except:
                    pass

    def test_encrypt_creates_output(self):
        enc = self.engine.encrypt_file(self.filename)
        self.assertTrue(os.path.exists(enc))

    def test_decrypt_restores_content(self):
        enc = self.engine.encrypt_file(self.filename)
        dec = self.engine.decrypt_file(enc)

        with open(dec) as f:
            self.assertEqual(f.read(), "AES encryption test data")

    def test_wrong_password_fails(self):
        enc = self.engine.encrypt_file(self.filename)
        wrong = AESEngine("WrongPass!")

        with self.assertRaises(Exception):
            wrong.decrypt_file(enc)

    def test_large_file_streaming(self):
        with open(self.filename, "w") as f:
            f.write("A" * 150000)

        enc = self.engine.encrypt_file(self.filename)
        self.assertTrue(os.path.exists(enc))


if __name__ == "__main__":
    unittest.main()
