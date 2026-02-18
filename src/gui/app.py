import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from encryption.decryptor import Decryptor
from encryption.algorithms import get_algorithm, ALGORITHMS
from encryption.rsa_engine import generate_rsa_keys, DEFAULT_PUBLIC_KEY, DEFAULT_PRIVATE_KEY
from integrity.hasher import Hasher
from core.file_manager import FileManager, FileRecord
from core.keygen import generate_random_password
from .tooltip import ToolTip
from .preview import create_preview_window, can_preview_text, can_preview_image

try:
    from main import APP_VERSION
except ImportError:
    APP_VERSION = "1.0.0"

try:
    from core.folder_watcher import start_folder_watch, stop_folder_watch, HAS_WATCHDOG
except Exception:
    HAS_WATCHDOG = False
    start_folder_watch = stop_folder_watch = None
from datetime import datetime
import math
import os
import re
import tempfile
import threading
import zipfile

# ----------------------------- CATPPUCCIN MOCHA THEME (Arch Rice Aesthetic) -----------------------------
class Theme:
    # Catppuccin Mocha - the beloved rice palette
    DARK = {
        "bg": "#1e1e2e",           # base
        "bg_alt": "#181825",       # mantle
        "card": "#313244",         # surface0
        "card_hover": "#45475a",   # surface1
        "border": "#45475a",
        "text": "#cdd6f4",
        "subtext": "#a6adc8",
        "blue": "#89b4fa",
        "green": "#a6e3a1",
        "peach": "#fab387",
        "red": "#f38ba8",
        "lavender": "#b4befe",
        "mauve": "#cba6f7",
        "teal": "#94e2d5",
    }
    LIGHT = {
        "bg": "#eff1f5",           # Catppuccin Latte base
        "bg_alt": "#e6e9ef",
        "card": "#ccd0da",
        "card_hover": "#bcc0cc",
        "border": "#acb0be",
        "text": "#4c4f69",
        "subtext": "#6c6f85",
        "blue": "#1e66f5",
        "green": "#40a02b",
        "peach": "#fe640b",
        "red": "#d20f39",
        "lavender": "#7287fd",
        "mauve": "#8839ef",
        "teal": "#179299",
    }

# Font stack - mono for that rice/terminal vibe
FONT_MONO = ("Cascadia Code", "Consolas", "JetBrains Mono", "monospace")
FONT_UI = ("Segoe UI Variable", "Segoe UI", "SF Pro Display", "sans-serif")

# ----------------------------- MAIN APP -----------------------------
class CryptoShieldApp:
    def __init__(self, root):
        self.root = root
        self.root.title(f"CryptoShield v{APP_VERSION}")
        self.root.geometry("1000x720")
        self.root.minsize(900, 650)
        self.selected_files = []
        self.theme = Theme.DARK
        self._clipboard_clear_id = None
        self._generated_password = ""
        self._folder_observer = None
        self._backup_folder = ""
        self._action_buttons = []
        self._setup_root()
        self.setup_ui()

    def _setup_root(self):
        self.root.configure(bg=self.theme["bg"])
        self.root.resizable(True, True)
        # Subtle padding around entire app
        self.root.option_add("*Font", (FONT_UI[0], 10))

    # ---------------- UI SETUP ----------------
    def setup_ui(self):
        self._configure_ttk_styles()
        self._build_menu()
        self._build_header()
        self._build_main_content()
        self._build_action_grid()
        self._build_status_bar()
        self._build_progress_section()
        self._build_security_notice()

    def _configure_ttk_styles(self):
        style = ttk.Style()
        style.theme_use("clam")
        bg, card, text, blue, border = self.theme["bg"], self.theme["card"], self.theme["text"], self.theme["blue"], self.theme["border"]

        style.configure("TFrame", background=bg)
        style.configure(
            "Custom.TFrame",
            background=card,
        )
        style.configure(
            "Accent.Horizontal.TProgressbar",
            troughcolor=card,
            background=blue,
            bordercolor=border,
            lightcolor=blue,
            darkcolor=blue,
            thickness=8,
        )
        style.configure(
            "Rice.Treeview",
            background=card,
            foreground=text,
            fieldbackground=card,
            bordercolor=border,
            font=(FONT_MONO[0], 10),
        )
        style.configure(
            "Rice.Treeview.Heading",
            background=self.theme["bg_alt"],
            foreground=self.theme["subtext"],
            font=(FONT_MONO[0], 10, "bold"),
        )
        style.map(
            "Rice.Treeview",
            background=[("selected", blue)],
            foreground=[("selected", self.theme["bg"])],
        )

    def _build_menu(self):
        """Build Help menu with About dialog."""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self._show_about)

    def _show_about(self):
        """Display About dialog with application info."""
        win = tk.Toplevel(self.root)
        win.title("About CryptoShield")
        win.geometry("380x320")
        win.configure(bg=self.theme["bg"])
        win.resizable(False, False)
        win.transient(self.root)
        win.grab_set()
        tk.Label(win, text="CryptoShield", font=(FONT_MONO[0], 18, "bold"), bg=self.theme["bg"], fg=self.theme["text"]).pack(pady=(24, 4))
        tk.Label(win, text=f"Version {APP_VERSION}", font=(FONT_UI[0], 10), bg=self.theme["bg"], fg=self.theme["subtext"]).pack(pady=(0, 16))
        tk.Label(win, text="Encryption Algorithms:", font=(FONT_UI[0], 10, "bold"), bg=self.theme["bg"], fg=self.theme["subtext"]).pack(anchor="w", padx=24, pady=(0, 4))
        tk.Label(win, text="  • AES-256-GCM\n  • ChaCha20-Poly1305\n  • RSA-4096 Hybrid", font=(FONT_UI[0], 9), bg=self.theme["bg"], fg=self.theme["text"], justify="left").pack(anchor="w", padx=24, pady=(0, 12))
        tk.Label(win, text="Educational cryptography desktop application.", font=(FONT_UI[0], 9), bg=self.theme["bg"], fg=self.theme["text"], wraplength=320).pack(pady=8)
        tk.Label(win, text="Educational use only — not security audited.", font=(FONT_UI[0], 9), bg=self.theme["bg"], fg=self.theme["red"]).pack(pady=(8, 20))
        tk.Button(win, text="OK", command=win.destroy, bg=self.theme["blue"], fg=self.theme["bg"], relief="flat", font=(FONT_MONO[0], 10), padx=24, pady=6).pack(pady=(0, 16))

    # ---------------- HEADER (minimal rice style) ----------------
    def _build_header(self):
        self._header_frame = tk.Frame(self.root, bg=self.theme["bg"], height=90)
        self._header_frame.pack(fill="x", padx=40, pady=(30, 20))
        self._header_frame.pack_propagate(False)

        tk.Label(
            self._header_frame,
            text="◇ CryptoShield",
            font=(FONT_MONO[0], 26, "bold"),
            bg=self.theme["bg"],
            fg=self.theme["text"],
        ).pack(anchor="w")
        tk.Label(
            self._header_frame,
            text="encrypt · decrypt · verify integrity",
            font=(FONT_UI[0], 11),
            bg=self.theme["bg"],
            fg=self.theme["subtext"],
        ).pack(anchor="w")

    # ---------------- MAIN CONTENT CARDS ----------------
    def _build_main_content(self):
        self._content_frame = tk.Frame(self.root, bg=self.theme["bg"])
        self._content_frame.pack(fill="x", padx=40, pady=(0, 20))
        self._content_frame.columnconfigure(0, weight=1)
        self._content_frame.columnconfigure(1, weight=1)

        # File selection card
        self._file_card = self._create_card(self._content_frame, "file")
        self._file_card.grid(row=0, column=0, padx=(0, 15), pady=5, sticky="nsew")
        tk.Label(
            self._file_card,
            text="STEP 1 — File Selection",
            font=(FONT_MONO[0], 10, "bold"),
            bg=self.theme["card"],
            fg=self.theme["subtext"],
        ).pack(anchor="w", padx=20, pady=(20, 5))
        self._file_label = tk.Label(
            self._file_card,
            text="No file selected",
            font=(FONT_MONO[0], 10),
            bg=self.theme["card"],
            fg=self.theme["text"],
            wraplength=380,
            justify="left",
        )
        self._file_label.pack(anchor="w", padx=20, pady=(0, 8), fill="x")
        btn_row = tk.Frame(self._file_card, bg=self.theme["card"])
        btn_row.pack(anchor="w", padx=20, pady=(0, 20))
        self._file_btn = self._styled_btn(btn_row, "Browse File", self._select_file, self.theme["blue"])
        self._file_btn.pack(side="left", padx=(0, 8))
        self._folder_btn = self._styled_btn(btn_row, "Add Folder", self._select_folder, self.theme["teal"])
        self._folder_btn.pack(side="left", padx=(0, 8))
        self._preview_btn = self._styled_btn(btn_row, "Preview", self._preview_file, self.theme["subtext"])
        self._preview_btn.pack(side="left")
        ToolTip(self._file_btn, "Select one or more files to encrypt/decrypt")
        ToolTip(self._folder_btn, "Add all files from a folder for batch encryption")
        ToolTip(self._preview_btn, "Preview text or image files before encrypting")

        # Password card
        self._pass_card = self._create_card(self._content_frame, "pass")
        self._pass_card.grid(row=0, column=1, padx=(15, 0), pady=5, sticky="nsew")
        tk.Label(
            self._pass_card,
            text="STEP 2 — Security Setup",
            font=(FONT_MONO[0], 10, "bold"),
            bg=self.theme["card"],
            fg=self.theme["subtext"],
        ).pack(anchor="w", padx=20, pady=(20, 5))
        tk.Label(
            self._pass_card,
            text="Password",
            font=(FONT_UI[0], 10),
            bg=self.theme["card"],
            fg=self.theme["subtext"],
        ).pack(anchor="w", padx=20, pady=(5, 2))
        self._pass_entry_frame = tk.Frame(self._pass_card, bg=self.theme["border"], highlightthickness=0)
        self._pass_entry_frame.pack(fill="x", padx=20, pady=(0, 8))
        self._pass_entry = tk.Entry(
            self._pass_entry_frame,
            show="●",
            exportselection=0,
            font=(FONT_MONO[0], 11),
            bg=self.theme["bg_alt"],
            fg=self.theme["text"],
            insertbackground=self.theme["text"],
            relief="flat",
            bd=0,
        )
        self._pass_entry.pack(fill="x", ipady=8, ipadx=10, padx=1, pady=1)
        self._pass_entry.bind("<KeyRelease>", self._update_password_strength)
        self._pass_strength = tk.Label(
            self._pass_card,
            text="",
            font=(FONT_MONO[0], 9),
            bg=self.theme["card"],
            fg=self.theme["subtext"],
        )
        self._pass_strength.pack(anchor="w", padx=20, pady=(0, 8))
        opt_row = tk.Frame(self._pass_card, bg=self.theme["card"])
        opt_row.pack(anchor="w", padx=20, pady=(0, 8))
        self._gen_pass_btn = self._styled_btn(opt_row, "Generate Password", self._generate_password, self.theme["teal"])
        self._gen_pass_btn.pack(side="left", padx=(0, 8))
        ToolTip(self._gen_pass_btn, "Generate a secure random password")
        self._algo_var = tk.StringVar(value="AES-256")
        algo_frame = tk.Frame(self._pass_card, bg=self.theme["card"])
        algo_frame.pack(anchor="w", padx=20, pady=(0, 8))
        tk.Label(algo_frame, text="Algorithm:", bg=self.theme["card"], fg=self.theme["subtext"], font=(FONT_UI[0], 9)).pack(side="left", padx=(0, 8))
        self._algo_combo = ttk.Combobox(algo_frame, textvariable=self._algo_var, values=list(ALGORITHMS.keys()), state="readonly", width=12)
        self._algo_combo.pack(side="left")
        self._algo_var.trace_add("write", lambda *a: self._on_algo_changed())
        self._rsa_keys_btn = self._styled_btn(opt_row, "Generate RSA Keys", self._generate_rsa_keys, self.theme["lavender"])
        ToolTip(self._rsa_keys_btn, "Generate 4096-bit RSA keypair for hybrid encryption")
        self._secure_delete_var = tk.BooleanVar(value=False)
        sd_cb = tk.Checkbutton(self._pass_card, text="Secure delete original", variable=self._secure_delete_var, bg=self.theme["card"], fg=self.theme["subtext"], selectcolor=self.theme["bg_alt"], activebackground=self.theme["card"], activeforeground=self.theme["text"])
        sd_cb.pack(anchor="w", padx=20, pady=(0, 20))
        ToolTip(sd_cb, "Overwrite file with random data before deletion after encryption")
        self._on_algo_changed()

    def _create_card(self, parent, tag):
        f = tk.Frame(parent, bg=self.theme["card"], highlightbackground=self.theme["border"], highlightthickness=1)
        return f

    # ---------------- ACTION BUTTONS (workflow: Step 3 Actions, Step 4 Utilities) ----------------
    def _build_action_grid(self):
        self._actions_frame = tk.Frame(self.root, bg=self.theme["bg"])
        self._actions_frame.pack(pady=(10, 20))
        self._actions_frame.columnconfigure(0, weight=1)
        self._actions_frame.columnconfigure(1, weight=1)

        self._step3_frame = tk.Frame(self._actions_frame, bg=self.theme["bg"])
        self._step3_frame.grid(row=0, column=0, columnspan=2, sticky="ew", padx=40, pady=(0, 8))
        self._step3_label = tk.Label(self._step3_frame, text="STEP 3 — Actions", font=(FONT_MONO[0], 10, "bold"), bg=self.theme["bg"], fg=self.theme["subtext"])
        self._step3_label.pack(anchor="w")
        actions_row = tk.Frame(self._step3_frame, bg=self.theme["bg"])
        actions_row.pack(anchor="w", pady=4)
        action_btns = [
            ("Encrypt", self._encrypt_with_progress, self.theme["blue"], "Encrypt selected file(s)"),
            ("Decrypt", self._decrypt_with_progress, self.theme["green"], "Decrypt selected encrypted file(s)"),
            ("Folder Archive", self._encrypt_folder_archive, self.theme["blue"], "Encrypt folder into .csh archive"),
            ("Verify Hash", self._verify_file, self.theme["peach"], "Generate SHA-256 hash"),
            ("Check Tamper", self._check_file_tamper, self.theme["red"], "Verify file integrity"),
        ]
        for text, cmd, color, tip in action_btns:
            btn = self._styled_btn(actions_row, text, cmd, color)
            btn.pack(side="left", padx=(0, 8), pady=4)
            ToolTip(btn, tip)
            self._action_buttons.append(btn)

        self._step4_frame = tk.Frame(self._actions_frame, bg=self.theme["bg"])
        self._step4_frame.grid(row=1, column=0, columnspan=2, sticky="ew", padx=40, pady=(8, 0))
        self._step4_label = tk.Label(self._step4_frame, text="STEP 4 — Utilities", font=(FONT_MONO[0], 10, "bold"), bg=self.theme["bg"], fg=self.theme["subtext"])
        self._step4_label.pack(anchor="w")
        utils_row = tk.Frame(self._step4_frame, bg=self.theme["bg"])
        utils_row.pack(anchor="w", pady=4)
        self._history_btn = self._styled_btn(utils_row, "History", self._show_history, self.theme["subtext"])
        self._history_btn.pack(side="left", padx=(0, 8))
        ToolTip(self._history_btn, "View encrypted file history and export")
        self._watch_btn = self._styled_btn(utils_row, "Watch Folder", self._toggle_watch_folder, self.theme["lavender"])
        self._watch_btn.pack(side="left", padx=(0, 8))
        ToolTip(self._watch_btn, "Auto-encrypt new files (requires watchdog)")
        self._theme_btn = self._styled_btn(utils_row, "Toggle Theme", self._toggle_theme, self.theme["mauve"])
        self._theme_btn.pack(side="left")
        ToolTip(self._theme_btn, "Switch between dark and light theme")
        self._action_buttons.extend([self._history_btn, self._watch_btn, self._theme_btn])

    # ---------------- STATUS BAR (terminal prompt style) ----------------
    def _build_status_bar(self):
        self._status_frame = tk.Frame(self.root, bg=self.theme["bg_alt"], height=36)
        self._status_frame.pack(fill="x", side="bottom", padx=0, pady=0)
        self._status_frame.pack_propagate(False)
        self._status_label = tk.Label(
            self._status_frame,
            text=" λ  Ready",
            font=(FONT_MONO[0], 10),
            bg=self.theme["bg_alt"],
            fg=self.theme["subtext"],
            anchor="w",
        )
        self._status_label.pack(side="left", padx=20, pady=8, fill="x", expand=True)

    def _build_security_notice(self):
        """Add subtle security notice banner at bottom."""
        self._security_notice = tk.Label(
            self.root,
            text="Educational Use Only — Not Security Audited",
            font=(FONT_UI[0], 8),
            bg=self.theme["bg"],
            fg=self.theme["subtext"],
        )
        self._security_notice.pack(side="bottom", pady=(0, 2))

    def _build_progress_section(self):
        self._prog_frame = tk.Frame(self.root, bg=self.theme["bg"])
        self._prog_frame.pack(fill="x", padx=40, pady=(0, 15))
        self._progress = ttk.Progressbar(
            self._prog_frame,
            style="Accent.Horizontal.TProgressbar",
            orient="horizontal",
            length=400,
            mode="determinate",
        )
        self._progress.pack(fill="x", pady=2)
        self._progress_label = tk.Label(self._prog_frame, text="", font=(FONT_MONO[0], 9), bg=self.theme["bg"], fg=self.theme["subtext"])
        self._progress_label.pack(anchor="e")

    def _rsa_keys_exist(self) -> bool:
        """Check if RSA key files exist in data/keys/."""
        return os.path.exists(DEFAULT_PUBLIC_KEY) and os.path.exists(DEFAULT_PRIVATE_KEY)

    def _on_algo_changed(self):
        """Show Generate RSA Keys button only when RSA is selected."""
        try:
            self._rsa_keys_btn.pack_forget()
        except Exception:
            pass
        if self._algo_var.get() == "RSA":
            self._rsa_keys_btn.pack(side="left", padx=(8, 0))

    def _generate_rsa_keys(self):
        """Generate 4096-bit RSA keypair and save to data/keys/."""
        try:
            pub_path, priv_path = generate_rsa_keys()
            self._show_info("RSA Keys Generated", f"Keys saved to:\n{pub_path}\n{priv_path}")
            self._update_status("RSA keys generated")
        except Exception as e:
            self._show_error("RSA Key Generation Failed", str(e))

    def _set_busy_state(self, busy: bool) -> None:
        """Enable/disable primary controls while a background task is running."""
        state = "disabled" if busy else "normal"
        widgets = [
            self._file_btn,
            self._folder_btn,
            self._preview_btn,
            self._gen_pass_btn,
            self._theme_btn,
            self._rsa_keys_btn,
        ] + list(self._action_buttons)
        for w in widgets:
            try:
                w.configure(state=state)
            except Exception:
                pass
        try:
            self.root.configure(cursor="watch" if busy else "")
        except Exception:
            pass

    # ---------------- MESSAGE HELPERS (thread-safe) ----------------
    def _show_error(self, title: str, message: str) -> None:
        self.root.after(0, lambda: messagebox.showerror(title, message))

    def _show_info(self, title: str, message: str) -> None:
        self.root.after(0, lambda: messagebox.showinfo(title, message))

    def _show_warning(self, title: str, message: str) -> None:
        self.root.after(0, lambda: messagebox.showwarning(title, message))

    # ---------------- STYLED BUTTON ----------------
    def _styled_btn(self, parent, text, command, color):
        fg_color = self.theme["text"] if color == self.theme["subtext"] else self.theme["bg"]
        btn = tk.Button(
            parent,
            text=text,
            command=command,
            bg=color,
            fg=fg_color,
            activebackground=color,
            activeforeground=fg_color,
            relief="flat",
            font=(FONT_MONO[0], 10, "bold"),
            cursor="hand2",
            bd=0,
            padx=18,
            pady=10,
        )
        # Hover: slight brighten
        def on_enter(e):
            r, g, b = int(color[1:3], 16), int(color[3:5], 16), int(color[5:7], 16)
            bright = min(255, r + 25), min(255, g + 25), min(255, b + 25)
            btn["bg"] = "#{:02x}{:02x}{:02x}".format(*bright)
        def on_leave(e):
            btn["bg"] = color
        btn.bind("<Enter>", on_enter)
        btn.bind("<Leave>", on_leave)
        return btn

    # ---------------- PASSWORD STRENGTH ----------------
    def _check_password_strength(self, password):
        length = len(password)
        has_upper = bool(re.search(r"[A-Z]", password))
        has_lower = bool(re.search(r"[a-z]", password))
        has_digit = bool(re.search(r"\d", password))
        has_symbol = bool(re.search(r"[!@#$%^&*(),.?\":{}|<>]", password))

        pool = 0
        if has_upper:
            pool += 26
        if has_lower:
            pool += 26
        if has_digit:
            pool += 10
        if has_symbol:
            pool += 32

        entropy = 0.0
        if pool > 0 and length:
            entropy = length * math.log2(pool)

        policy_ok = length >= 12 and has_upper and has_lower and has_digit and has_symbol

        if entropy < 40:
            strength = "Weak"
            color = self.theme["red"]
        elif entropy < 60:
            strength = "Medium"
            color = self.theme["peach"]
        elif entropy < 80:
            strength = "Strong"
            color = self.theme["green"]
        else:
            strength = "Very Strong"
            color = self.theme["green"]

        try:
            guesses = 2 ** entropy
            seconds = guesses / 1e10
        except OverflowError:
            seconds = float("inf")
        crack_time = self._format_crack_time(seconds)

        return strength, color, entropy, crack_time, policy_ok

    def _format_crack_time(self, seconds: float) -> str:
        if seconds < 1:
            return "< 1 second"
        if seconds < 60:
            return f"{int(seconds)} seconds"
        minutes = seconds / 60
        if minutes < 60:
            return f"{int(minutes)} minutes"
        hours = minutes / 60
        if hours < 24:
            return f"{int(hours)} hours"
        days = hours / 24
        if days < 365:
            return f"{int(days)} days"
        years = days / 365
        if years < 100:
            return f"{int(years)} years"
        return "> 100 years"

    def _password_policy_ok(self, password: str) -> bool:
        _, _, _, _, ok = self._check_password_strength(password)
        return ok

    def _update_password_strength(self, event=None):
        pwd = self._pass_entry.get()
        if pwd:
            strength, color, entropy, crack_time, ok = self._check_password_strength(pwd)
            policy_note = "policy OK" if ok else "too weak for encryption"
            self._pass_strength.config(
                text=f"Strength: {strength} — {entropy:.1f} bits, est. crack: {crack_time} ({policy_note})",
                fg=color,
            )
        else:
            self._pass_strength.config(text="")

    def _generate_password(self):
        pwd = generate_random_password(20)
        self._generated_password = pwd
        self._pass_entry.delete(0, tk.END)
        self._pass_entry.insert(0, pwd)
        self._update_password_strength()
        self.root.clipboard_clear()
        self.root.clipboard_append(self._generated_password)
        self._schedule_clipboard_clear(10)

    def _schedule_clipboard_clear(self, seconds: int):
        if self._clipboard_clear_id:
            self.root.after_cancel(self._clipboard_clear_id)
        self._clipboard_clear_id = self.root.after(seconds * 1000, self._clear_clipboard)

    def _clear_clipboard(self):
        try:
            self.root.clipboard_clear()
        except tk.TclError:
            pass
        self._clipboard_clear_id = None

    def _select_file(self):
        paths = filedialog.askopenfilenames()
        if paths:
            self.selected_files = list(paths)
            self._update_file_label()
            self._update_status(f"{len(paths)} file(s) selected")

    def _select_folder(self):
        path = filedialog.askdirectory()
        if path:
            files = []
            for root, _, names in os.walk(path):
                for n in names:
                    p = os.path.join(root, n)
                    if os.path.isfile(p) and not n.startswith("."):
                        files.append(p)
            if files:
                self.selected_files = list(set(self.selected_files + files))
                self._update_file_label()
                self._update_status(f"{len(self.selected_files)} file(s) total")
            else:
                self._show_info("Info", "No files found in folder.")

    def _update_file_label(self):
        if not self.selected_files:
            self._file_label.config(text="No file selected")
            return
        if len(self.selected_files) == 1:
            p = self.selected_files[0]
            short = p if len(p) <= 50 else "…" + p[-47:]
        else:
            short = f"{len(self.selected_files)} files selected"
        self._file_label.config(text=short)

    def _preview_file(self):
        path = self.selected_files[0] if self.selected_files else None
        if not path or not os.path.isfile(path):
            self._show_info("Info", "Select a file first.")
            return
        if not (can_preview_text(path) or can_preview_image(path)):
            self._show_info("Info", "Preview not available for this file type.")
            return
        create_preview_window(self.root, path, self.theme)

    # ---------------- FILE SELECTION ----------------

    # ---------------- ENCRYPTION / DECRYPTION ----------------
    def _encrypt_with_progress(self):
        self._run_with_progress(self._perform_encryption, "Encrypting...", "Encryption complete")

    def _decrypt_with_progress(self):
        files = [f for f in self.selected_files if os.path.isfile(f)]
        archive_target = None
        if len(files) == 1 and files[0].lower().endswith(".csh"):
            archive_target = filedialog.askdirectory(title="Select folder to extract archive into")
            if not archive_target:
                return

            def task(progress_cb, dest=archive_target):
                self._perform_decryption(progress_cb, archive_target=dest)

            self._run_with_progress(task, "Decrypting archive...", "Archive decrypted")
        else:
            self._run_with_progress(self._perform_decryption, "Decrypting...", "Decryption complete")

    def _run_with_progress(self, task_fn, start_msg, end_msg):
        def update_progress(done: int, total: int) -> None:
            def _ui():
                pct = int(100 * done / total) if total else 0
                self._progress["value"] = pct
                self._progress_label.config(text=f"{pct}%")
            self.root.after(0, _ui)

        def on_start():
            self._set_busy_state(True)
            self._progress["value"] = 0
            self._progress_label.config(text="0%")
            self._update_status(start_msg)

        def on_success():
            self._progress["value"] = 100
            self._progress_label.config(text="100%")
            self._update_status(end_msg)
            self._notify_desktop(end_msg)
            self._set_busy_state(False)

        def on_error(msg: str):
            self._set_busy_state(False)
            messagebox.showerror("Error", msg)

        def run():
            try:
                self.root.after(0, on_start)
                task_fn(update_progress)
                self.root.after(0, on_success)
            except Exception as e:
                self.root.after(0, lambda: on_error(str(e)))

        threading.Thread(target=run, daemon=True).start()

    def _notify_desktop(self, msg: str):
        try:
            from plyer import notification #type: ignore
            notification.notify(title="CryptoShield", message=msg, app_name="CryptoShield", timeout=3)
        except Exception:
            pass

    def _perform_encryption(self, progress_cb):
        files = [f for f in self.selected_files if os.path.isfile(f)]
        if not files:
            self._show_error("Error", "Select at least one file.")
            return
        algo_name = self._algo_var.get()
        if algo_name == "RSA":
            if not self._rsa_keys_exist():
                self._show_error("RSA Keys Required", "Generate RSA keys first (Generate RSA Keys button).")
                return
            engine = get_algorithm(algo_name)(None)
        else:
            pwd = self._pass_entry.get()
            if not pwd:
                self._show_error("Error", "Enter a password.")
                return
            if not self._password_policy_ok(pwd):
                self._show_error(
                    "Weak password",
                    "Password is too weak. Use at least 12 characters and include uppercase, lowercase, number and symbol.",
                )
                return
            engine = get_algorithm(algo_name)(pwd)
        hasher = Hasher()
        manager = FileManager()
        total = len(files)
        for i, fp in enumerate(files):
            try:
                cb = progress_cb if total == 1 else None
                enc_path = engine.encrypt_file(fp, progress_callback=cb, delete_original=self._secure_delete_var.get())
                fh = hasher.generate_hash(enc_path)
                sz = os.path.getsize(fp) if os.path.exists(fp) else 0
                record = FileRecord(original_file=fp, encrypted_file=enc_path, file_hash=fh, time=str(datetime.now()), algorithm=algo_name, file_size=sz)
                manager.save_record(record)
            except Exception as e:
                self._show_error("Error", f"Failed: {fp}\n{e}")
                return
            if total > 1:
                progress_cb(i + 1, total)
        msg = f"Encrypted {len(files)} file(s)." if total > 1 else f"Encrypted to:\n{files[0]}.enc"
        self._show_info("Success", msg)

    def _perform_decryption(self, progress_cb, archive_target: str | None = None):
        files = [f for f in self.selected_files if os.path.isfile(f)]
        if not files:
            self._show_error("Error", "Select at least one file.")
            return
        algo_name = self._algo_var.get()
        if algo_name == "RSA":
            if not self._rsa_keys_exist():
                self._show_error("RSA Keys Required", "Private key not found. Generate RSA keys first.")
                return
            engine = get_algorithm(algo_name)(None)
        else:
            pwd = self._pass_entry.get()
            if not pwd:
                self._show_error("Error", "Enter a password.")
                return
            engine = get_algorithm(algo_name)(pwd)
        if archive_target and len(files) == 1 and files[0].lower().endswith(".csh"):
            pwd_arg = self._pass_entry.get() if algo_name != "RSA" else None
            self._perform_archive_decryption(files[0], pwd_arg, algo_name, archive_target, progress_cb)
            return
        total = len(files)
        for i, fp in enumerate(files):
            try:
                cb = progress_cb if total == 1 else None
                dec_path = engine.decrypt_file(fp, progress_callback=cb)
                if total > 1:
                    progress_cb(i + 1, total)
                self._show_info("Success", f"Decrypted to:\n{dec_path}")
                break
            except Exception as e:
                if algo_name == "RSA":
                    self._show_error("Error", str(e))
                    return
                try:
                    pwd_fallback = self._pass_entry.get()
                    decryptor = Decryptor(pwd_fallback)
                    dec_path = decryptor.decrypt_file(fp)
                    self._show_info("Success", f"Decrypted to:\n{dec_path}")
                    break
                except Exception as e2:
                    self._show_error("Error", str(e2))
                    return

    def _encrypt_folder_archive(self):
        folder = filedialog.askdirectory(title="Select folder to encrypt as archive")
        if not folder:
            return
        pwd = self._pass_entry.get()
        if not pwd:
            self._show_error("Error", "Enter a password before encrypting a folder archive.")
            return
        if not self._password_policy_ok(pwd):
            self._show_error(
                "Weak password",
                "Password is too weak. Use at least 12 characters and include uppercase, lowercase, number and symbol.",
            )
            return
        algo_name = self._algo_var.get()
        if algo_name == "RSA":
            self._show_info("Info", "Folder archive mode is not supported with RSA in this version.")
            return

        def task(progress_cb, folder_path=folder, algo=algo_name, password=pwd):
            self._perform_archive_encryption(folder_path, password, algo, progress_cb)

        self._run_with_progress(task, "Encrypting folder archive...", "Folder archive encrypted")

    def _perform_archive_encryption(self, folder_path: str, password: str, algo_name: str, progress_cb):
        if not os.path.isdir(folder_path):
            raise ValueError("Folder not found.")

        tmp_fd, tmp_zip_path = tempfile.mkstemp(suffix=".zip")
        os.close(tmp_fd)
        try:
            with zipfile.ZipFile(tmp_zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
                for root, _, files in os.walk(folder_path):
                    for name in files:
                        full = os.path.join(root, name)
                        if not os.path.isfile(full):
                            continue
                        rel = os.path.relpath(full, start=folder_path)
                        zf.write(full, arcname=rel)

            Engine = get_algorithm(algo_name)
            engine = Engine(password)

            parent = os.path.dirname(folder_path)
            base = os.path.basename(os.path.normpath(folder_path))
            candidate = os.path.join(parent, base + ".csh")
            idx = 1
            while os.path.exists(candidate):
                candidate = os.path.join(parent, f"{base}_{idx}.csh")
                idx += 1

            enc_path = engine.encrypt_file(tmp_zip_path, output_path=candidate, progress_callback=progress_cb)
            hasher = Hasher()
            manager = FileManager()
            fh = hasher.generate_hash(enc_path)
            sz = os.path.getsize(enc_path) if os.path.exists(enc_path) else 0
            record = FileRecord(
                original_file=folder_path,
                encrypted_file=enc_path,
                file_hash=fh,
                time=str(datetime.now()),
                algorithm=algo_name,
                file_size=sz,
            )
            manager.save_record(record)
            self._show_info("Success", f"Encrypted folder to archive:\n{enc_path}")
        finally:
            try:
                os.remove(tmp_zip_path)
            except OSError:
                pass

    def _perform_archive_decryption(
        self,
        enc_path: str,
        password: str,
        algo_name: str,
        target_dir: str,
        progress_cb,
    ) -> None:
        if not os.path.isfile(enc_path):
            raise ValueError("Encrypted archive not found.")
        if not os.path.isdir(target_dir):
            os.makedirs(target_dir, exist_ok=True)

        tmp_fd, tmp_zip_path = tempfile.mkstemp(suffix=".zip")
        os.close(tmp_fd)
        try:
            Engine = get_algorithm(algo_name)
            engine = Engine(password)
            engine.decrypt_file(enc_path, output_path=tmp_zip_path, progress_callback=progress_cb)

            with zipfile.ZipFile(tmp_zip_path, "r") as zf:
                zf.extractall(target_dir)

            self._show_info("Success", f"Archive decrypted to:\n{target_dir}")
        finally:
            try:
                os.remove(tmp_zip_path)
            except OSError:
                pass

    # ---------------- INTEGRITY & TAMPER ----------------
    def _verify_file(self):
        path = self.selected_files[0] if self.selected_files else None
        if not path or not os.path.isfile(path):
            self._show_error("Error", "Select a file first.")
            return
        hasher = Hasher()
        file_hash = hasher.generate_hash(path)
        self.root.clipboard_clear()
        self.root.clipboard_append(file_hash)
        self._schedule_clipboard_clear(10)
        self._show_info("SHA-256 Hash", f"{file_hash}\n(Copied to clipboard, will clear in 10s)")
        self._update_status("Hash generated")

    def _check_file_tamper(self):
        path = self.selected_files[0] if self.selected_files else None
        if not path or not os.path.isfile(path):
            self._show_error("Error", "Select a file first.")
            return
        manager = FileManager()
        records = manager.get_all_records()
        sel_norm = os.path.normpath(path)
        sel_basename = os.path.basename(path)
        record = next((r for r in records if os.path.normpath(r.get("encrypted_file", "")) == sel_norm or os.path.basename(r.get("encrypted_file", "")) == sel_basename), None)
        if not record:
            self._show_info("Info", "No metadata found for this file.")
            return
        hasher = Hasher()
        current_hash = hasher.generate_hash(path)
        if current_hash == record.get("file_hash"):
            self._show_info("Safe", "No tampering detected.")
            self._update_status("Integrity verified")
        else:
            self._show_warning("Tampered", "File has been tampered.")
            self._update_status("Tampering detected")

    # ---------------- HISTORY WINDOW (styled, search, export) ----------------
    def _show_history(self):
        manager = FileManager()
        records = manager.get_all_records()
        win = tk.Toplevel(self.root)
        win.title("History — CryptoShield")
        win.geometry("950x550")
        win.configure(bg=self.theme["bg"])
        win.minsize(700, 400)

        search_frame = tk.Frame(win, bg=self.theme["bg"])
        search_frame.pack(fill="x", padx=20, pady=(20, 10))
        tk.Label(search_frame, text="Search:", bg=self.theme["bg"], fg=self.theme["subtext"]).pack(side="left", padx=(0, 8))
        search_var = tk.StringVar()
        search_var.trace("w", lambda *a: None)
        search_entry = tk.Entry(search_frame, textvariable=search_var, width=25, font=(FONT_MONO[0], 10), bg=self.theme["card"], fg=self.theme["text"])
        search_entry.pack(side="left", padx=(0, 15))
        export_csv_btn = self._styled_btn(search_frame, "Export CSV", lambda: self._export_history(manager, "csv", records), self.theme["blue"])
        export_csv_btn.pack(side="right", padx=5)
        export_xls_btn = self._styled_btn(search_frame, "Export Excel", lambda: self._export_history(manager, "xlsx", records), self.theme["green"])
        export_xls_btn.pack(side="right")

        cols = ("Original", "Encrypted", "Algorithm", "Size", "Hash", "Time")
        tree = ttk.Treeview(win, columns=cols, show="headings", style="Rice.Treeview", height=18)
        widths = [180, 180, 80, 70, 120, 140]
        for c, w in zip(cols, widths):
            tree.heading(c, text=c)
            tree.column(c, width=w)
        sb = ttk.Scrollbar(win, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=sb.set)

        def refresh_tree(recs=None):
            for item in tree.get_children():
                tree.delete(item)
            rlist = recs or manager.get_all_records()
            q = search_var.get().strip().lower()
            if q:
                rlist = [r for r in rlist if q in (str(r.get("original_file",""))+str(r.get("encrypted_file",""))+str(r.get("file_hash",""))+str(r.get("time",""))).lower()]
            for r in rlist:
                rd = r if isinstance(r, dict) else (r.to_dict() if hasattr(r, "to_dict") else r)
                tree.insert("", "end", values=(
                    rd.get("original_file", "")[:50],
                    rd.get("encrypted_file", "")[:50],
                    rd.get("algorithm", "AES-256"),
                    str(rd.get("file_size", 0)),
                    (rd.get("file_hash", "") or "")[:24] + "…" if len(rd.get("file_hash", "") or "") > 24 else rd.get("file_hash", ""),
                    rd.get("time", ""),
                ))
        search_var.trace_add("write", lambda *a: refresh_tree())
        refresh_tree(records)

        tree.pack(side="left", fill="both", expand=True, padx=20, pady=(0, 20))
        sb.pack(side="right", fill="y", pady=(0, 20))

    def _export_history(self, manager, fmt: str, records: list):
        path = filedialog.asksaveasfilename(defaultextension=f".{fmt}", filetypes=[(f"{fmt.upper()} files", f"*.{fmt}")])
        if not path:
            return
        if fmt == "csv":
            manager.export_csv(path, records)
        else:
            ok = manager.export_excel(path, records)
            if not ok:
                self._show_error("Error", "Install openpyxl: pip install openpyxl")
                return
        self._show_info("Success", f"Exported to {path}")

    # ---------------- STATUS ----------------
    def _update_status(self, msg):
        self._status_label.config(text=f" λ  {msg}")

    def _toggle_watch_folder(self):
        if not HAS_WATCHDOG or not start_folder_watch:
            self._show_info("Info", "Install watchdog: pip install watchdog")
            return
        if self._folder_observer:
            stop_folder_watch(self._folder_observer)
            self._folder_observer = None
            self._update_status("Stopped watching folder")
            return
        folder = filedialog.askdirectory(title="Select folder to watch")
        if not folder:
            return
        algo_name = self._algo_var.get()
        if algo_name == "RSA":
            if not self._rsa_keys_exist():
                self._show_error("RSA Keys Required", "Generate RSA keys first for Watch Folder.")
                return
        else:
            pwd = self._pass_entry.get()
            if not pwd:
                self._show_warning("Warning", "Set a password first. New files will be encrypted with it.")
                return
            if not self._password_policy_ok(pwd):
                self._show_warning(
                    "Weak password",
                    "Password is too weak. Use at least 12 characters and include uppercase, lowercase, number and symbol.",
                )
                return
        def on_new(path):
            self.root.after(0, lambda: self._encrypt_file_path(path))
        self._folder_observer = start_folder_watch(folder, on_new)
        self._update_status(f"Watching: {folder}")

    def _encrypt_file_path(self, path: str):
        if not os.path.isfile(path):
            return
        algo_name = self._algo_var.get()
        if algo_name == "RSA":
            if not self._rsa_keys_exist():
                self._update_status("Auto-encrypt skipped (RSA keys not found)")
                return
            engine = get_algorithm(algo_name)(None)
        else:
            pwd = self._pass_entry.get()
            if not pwd:
                self._update_status("Auto-encrypt skipped (no password)")
                return
            if not self._password_policy_ok(pwd):
                self._update_status("Auto-encrypt skipped (weak password)")
                return
            engine = get_algorithm(algo_name)(pwd)
        try:
            enc_path = engine.encrypt_file(path)
            manager = FileManager()
            hasher = Hasher()
            fh = hasher.generate_hash(enc_path)
            record = FileRecord(original_file=path, encrypted_file=enc_path, file_hash=fh, time=str(datetime.now()), algorithm=self._algo_var.get(), file_size=os.path.getsize(path) if os.path.exists(path) else 0)
            manager.save_record(record)
            self._update_status(f"Auto-encrypted: {os.path.basename(path)}")
            self._notify_desktop(f"Encrypted: {os.path.basename(path)}")
        except Exception as e:
            self._update_status(f"Auto-encrypt failed: {e}")

    # ---------------- THEME TOGGLE ----------------
    def _toggle_theme(self):
        self.theme = Theme.LIGHT if self.theme == Theme.DARK else Theme.DARK
        self.root.configure(bg=self.theme["bg"])
        self._header_frame.configure(bg=self.theme["bg"])
        children = self._header_frame.winfo_children()
        if len(children) >= 2:
            children[0].configure(bg=self.theme["bg"], fg=self.theme["text"])
            children[1].configure(bg=self.theme["bg"], fg=self.theme["subtext"])
        self._content_frame.configure(bg=self.theme["bg"])
        self._actions_frame.configure(bg=self.theme["bg"])
        self._step3_frame.configure(bg=self.theme["bg"])
        self._step4_frame.configure(bg=self.theme["bg"])
        self._step3_label.configure(bg=self.theme["bg"], fg=self.theme["subtext"])
        self._step4_label.configure(bg=self.theme["bg"], fg=self.theme["subtext"])
        for w in self._step3_frame.winfo_children() + self._step4_frame.winfo_children():
            if isinstance(w, tk.Frame):
                w.configure(bg=self.theme["bg"])
        self._prog_frame.configure(bg=self.theme["bg"])
        self._status_frame.configure(bg=self.theme["bg_alt"])
        self._status_label.configure(bg=self.theme["bg_alt"], fg=self.theme["subtext"])
        self._file_card.configure(bg=self.theme["card"], highlightbackground=self.theme["border"])
        self._pass_card.configure(bg=self.theme["card"], highlightbackground=self.theme["border"])
        self._pass_entry_frame.configure(bg=self.theme["border"])
        self._file_label.configure(bg=self.theme["card"], fg=self.theme["text"])
        for w in self._file_card.winfo_children() + self._pass_card.winfo_children():
            if isinstance(w, tk.Label):
                w.configure(bg=self.theme["card"])
            elif isinstance(w, tk.Frame):
                w.configure(bg=self.theme.get("border", self.theme["card"]))
        self._pass_entry.configure(bg=self.theme["bg_alt"], fg=self.theme["text"], insertbackground=self.theme["text"])
        self._pass_strength.configure(bg=self.theme["card"])
        self._configure_ttk_styles()
        self._file_btn.configure(bg=self.theme["blue"])
        self._folder_btn.configure(bg=self.theme["teal"])
        self._preview_btn.configure(bg=self.theme["subtext"])
        self._gen_pass_btn.configure(bg=self.theme["teal"])
        self._theme_btn.configure(bg=self.theme["mauve"])
        self._progress_label.configure(bg=self.theme["bg"], fg=self.theme["subtext"])
        self._security_notice.configure(bg=self.theme["bg"], fg=self.theme["subtext"])

# ---------------- RUN ----------------
def run_app():
    root = tk.Tk()
    app = CryptoShieldApp(root)
    root.mainloop()
