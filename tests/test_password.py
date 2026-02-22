"""Unit tests for password generation and clipboard/display behavior."""
import unittest
import re
import string

from core.keygen import generate_random_password #type: ignore


class TestPasswordGenerator(unittest.TestCase):
    """Tests for generate_random_password and related behavior."""

    def test_generated_password_length_matches_requested(self):
        for length in (8, 12, 20, 24, 32):
            pwd = generate_random_password(length=length)
            self.assertEqual(len(pwd), length, f"Expected length {length}, got {len(pwd)}")

    def test_password_contains_mixed_characters(self):
        pwd = generate_random_password(length=64)
        self.assertTrue(any(c in string.ascii_uppercase for c in pwd), "Missing uppercase")
        self.assertTrue(any(c in string.ascii_lowercase for c in pwd), "Missing lowercase")
        self.assertTrue(any(c in string.digits for c in pwd), "Missing digits")
        symbols = "!@#$%^&*()-_=+[]{}|;:,.<>?"
        self.assertTrue(any(c in symbols for c in pwd), "Missing symbols")

    def test_password_is_not_masked(self):
        """Generated password must be real characters, not mask characters (●●●)."""
        pwd = generate_random_password(length=20)
        self.assertNotIn("●", pwd)
        self.assertTrue(all(c in (string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}|;:,.<>?") for c in pwd))

    def test_masking_only_applies_to_display(self):
        """Core generator returns plain text; masking is a GUI display concern."""
        pwd = generate_random_password(length=16)
        self.assertEqual(len(pwd), 16)
        self.assertIsInstance(pwd, str)
        self.assertFalse(pwd.startswith("●"))

    def test_multiple_generations_produce_different_passwords(self):
        seen = set()
        for _ in range(20):
            pwd = generate_random_password(length=24)
            self.assertNotIn(pwd, seen, "Password should be unique")
            seen.add(pwd)


if __name__ == "__main__":
    unittest.main()
