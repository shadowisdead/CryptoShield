"""Unit tests for GUI logic — skipped if Tkinter unavailable in test environment."""
import unittest
import sys
import os

# Detect if Tkinter is functional in this environment
HAS_TK = False
try:
    import tkinter as tk
    _r = tk.Tk.__new__(tk.Tk)
    HAS_TK = True
except Exception:
    HAS_TK = False


@unittest.skipUnless(HAS_TK, "Tkinter/TCL not available in pytest environment — skipping GUI tests")
class TestGUILogic(unittest.TestCase):

    def setUp(self):
        import tkinter as tk
        self.root = tk.Tk()
        self.root.withdraw()

    def tearDown(self):
        try:
            self.root.destroy()
        except Exception:
            pass

    def test_button_order_initialization_sequence(self):
        from gui.app import CryptoShieldApp  # type: ignore
        app = CryptoShieldApp(self.root)
        self.assertTrue(hasattr(app, "_header_frame"))
        self.assertTrue(hasattr(app, "_content_frame"))
        self.assertTrue(hasattr(app, "_actions_frame"))
        self.assertTrue(hasattr(app, "_status_frame"))
        self.assertTrue(hasattr(app, "_progress"))
        self.assertTrue(hasattr(app, "_security_notice"))
        self.assertIsInstance(app._action_buttons, list)
        self.assertGreater(len(app._action_buttons), 0)

    def test_generate_password_sets_real_password_not_masked(self):
        from gui.app import CryptoShieldApp  # type: ignore
        app = CryptoShieldApp(self.root)
        app._generate_password()
        self.assertIsInstance(app._generated_password, str)
        self.assertGreater(len(app._generated_password), 0)
        self.assertNotIn("●", app._generated_password)
        self.assertEqual(len(app._generated_password), 20)

    def test_generated_password_matches_entry_value(self):
        from gui.app import CryptoShieldApp  # type: ignore
        app = CryptoShieldApp(self.root)
        app._generate_password()
        entry_value = app._pass_entry.get()
        self.assertEqual(entry_value, app._generated_password)


if __name__ == "__main__":
    unittest.main()