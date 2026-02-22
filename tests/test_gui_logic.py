"""Unit tests for GUI logic (non-visual): callbacks and initialization."""
import unittest
import tkinter as tk

from gui.app import CryptoShieldApp # type: ignore


class TestGUILogic(unittest.TestCase):
    """Test button callbacks and init sequence without displaying GUI."""

    def setUp(self):
        self.root = tk.Tk()
        self.root.withdraw()

    def tearDown(self):
        try:
            self.root.destroy()
        except Exception:
            pass

    def test_button_order_initialization_sequence(self):
        """Setup builds menu, header, content, actions, status, progress, notice."""
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
        """Clipboard/display: _generate_password stores real password in _generated_password."""
        app = CryptoShieldApp(self.root)
        app._generate_password()
        self.assertIsInstance(app._generated_password, str)
        self.assertGreater(len(app._generated_password), 0)
        self.assertNotIn("●", app._generated_password)
        self.assertEqual(len(app._generated_password), 20)

    def test_generated_password_matches_entry_value(self):
        """The stored _generated_password equals what would be in the entry (real text)."""
        app = CryptoShieldApp(self.root)
        app._generate_password()
        entry_value = app._pass_entry.get()
        self.assertEqual(entry_value, app._generated_password)
        self.assertEqual(entry_value, app._generated_password)


if __name__ == "__main__":
    unittest.main()
