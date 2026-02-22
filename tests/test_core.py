import unittest
import os
from core.secure_delete import secure_delete #type: ignore


class TestCore(unittest.TestCase):

    def test_secure_delete(self):
        with open("delete.txt", "w") as f:
            f.write("remove me")

        secure_delete("delete.txt")
        self.assertFalse(os.path.exists("delete.txt"))

    def test_data_directory_exists(self):
        self.assertTrue(os.path.exists("data"))


if __name__ == "__main__":
    unittest.main()
