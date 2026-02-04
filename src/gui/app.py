import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from encryption.encryptor import Encryptor
from encryption.decryptor import Decryptor
from integrity.hasher import Hasher
from core.file_manager import FileManager, FileRecord
from datetime import datetime
import os
import re
import threading

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
        self.root.title("CryptoShield — Secure Encryption")
        self.root.geometry("1000x720")
        self.root.minsize(900, 650)
        self.selected_file = ""
        self.theme = Theme.DARK
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
        self._build_header()
        self._build_main_content()
        self._build_action_grid()
        self._build_status_bar()
        self._build_progress_section()

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
            text="FILE",
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
        self._file_label.pack(anchor="w", padx=20, pady=(0, 12), fill="x")
        self._file_btn = self._styled_btn(self._file_card, "Browse File", self._select_file, self.theme["blue"])
        self._file_btn.pack(anchor="w", padx=20, pady=(0, 20))

        # Password card
        self._pass_card = self._create_card(self._content_frame, "pass")
        self._pass_card.grid(row=0, column=1, padx=(15, 0), pady=5, sticky="nsew")
        tk.Label(
            self._pass_card,
            text="SECURITY",
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
        self._pass_strength.pack(anchor="w", padx=20, pady=(0, 12))
        self._theme_btn = self._styled_btn(self._pass_card, "Toggle Theme", self._toggle_theme, self.theme["mauve"])
        self._theme_btn.pack(anchor="w", padx=20, pady=(0, 20))

    def _create_card(self, parent, tag):
        f = tk.Frame(parent, bg=self.theme["card"], highlightbackground=self.theme["border"], highlightthickness=1)
        return f

    # ---------------- ACTION BUTTONS ----------------
    def _build_action_grid(self):
        self._actions_frame = tk.Frame(self.root, bg=self.theme["bg"])
        self._actions_frame.pack(pady=(10, 20))
        self._actions_frame.columnconfigure(0, weight=1)
        self._actions_frame.columnconfigure(1, weight=1)
        self._actions_frame.columnconfigure(2, weight=1)

        btns = [
            ("Encrypt", self._encrypt_with_progress, self.theme["blue"]),
            ("Decrypt", self._decrypt_with_progress, self.theme["green"]),
            ("Verify Hash", self._verify_file, self.theme["peach"]),
            ("History", self._show_history, self.theme["subtext"]),
            ("Check Tamper", self._check_file_tamper, self.theme["red"]),
        ]
        for i, (text, cmd, color) in enumerate(btns):
            btn = self._styled_btn(self._actions_frame, text, cmd, color)
            btn.grid(row=i // 3, column=i % 3, padx=10, pady=8)

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
        self._progress.pack(fill="x", pady=5)

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
        score = 0
        if len(password) >= 8: score += 1
        if re.search(r"[A-Z]", password): score += 1
        if re.search(r"[a-z]", password): score += 1
        if re.search(r"\d", password): score += 1
        if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password): score += 1
        if score <= 2: return "weak", self.theme["red"]
        elif score <= 4: return "medium", self.theme["peach"]
        else: return "strong", self.theme["green"]

    def _update_password_strength(self, event=None):
        pwd = self._pass_entry.get()
        if pwd:
            strength, color = self._check_password_strength(pwd)
            self._pass_strength.config(text=f"Strength: {strength}", fg=color)
        else:
            self._pass_strength.config(text="")

    # ---------------- FILE SELECTION ----------------
    def _select_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.selected_file = path
            short = path if len(path) <= 50 else "…" + path[-47:]
            self._file_label.config(text=short)
            self._update_status("File selected")

    # ---------------- ENCRYPTION / DECRYPTION ----------------
    def _encrypt_with_progress(self):
        self._run_with_progress(self._perform_encryption, "Encrypting...", "Encryption complete")

    def _decrypt_with_progress(self):
        self._run_with_progress(self._perform_decryption, "Decrypting...", "Decryption complete")

    def _run_with_progress(self, task_fn, start_msg, end_msg):
        def run():
            try:
                self._progress["value"] = 0
                self._update_status(start_msg)
                for i in range(0, 101, 5):
                    self._progress["value"] = i
                    self.root.update_idletasks()
                    self.root.after(40)
                task_fn()
                self._progress["value"] = 100
                self._update_status(end_msg)
            except Exception as e:
                messagebox.showerror("Error", str(e))
        threading.Thread(target=run, daemon=True).start()

    def _perform_encryption(self):
        if not self.selected_file:
            messagebox.showerror("Error", "Select a file first.")
            return
        pwd = self._pass_entry.get()
        if not pwd:
            messagebox.showerror("Error", "Enter a password.")
            return
        encryptor = Encryptor(pwd)
        encrypted_path = encryptor.encrypt_file(self.selected_file)
        hasher = Hasher()
        file_hash = hasher.generate_hash(encrypted_path)
        manager = FileManager()
        record = FileRecord(
            original_file=self.selected_file,
            encrypted_file=encrypted_path,
            file_hash=file_hash,
            time=str(datetime.now()),
        )
        manager.save_record(record)
        messagebox.showinfo("Success", f"Encrypted to:\n{encrypted_path}")

    def _perform_decryption(self):
        if not self.selected_file:
            messagebox.showerror("Error", "Select a file first.")
            return
        pwd = self._pass_entry.get()
        if not pwd:
            messagebox.showerror("Error", "Enter a password.")
            return
        decryptor = Decryptor(pwd)
        decrypted_path = decryptor.decrypt_file(self.selected_file)
        messagebox.showinfo("Success", f"Decrypted to:\n{decrypted_path}")

    # ---------------- INTEGRITY & TAMPER ----------------
    def _verify_file(self):
        if not self.selected_file:
            messagebox.showerror("Error", "Select a file first.")
            return
        hasher = Hasher()
        file_hash = hasher.generate_hash(self.selected_file)
        messagebox.showinfo("SHA-256 Hash", file_hash)
        self._update_status("Hash generated")

    def _check_file_tamper(self):
        if not self.selected_file:
            messagebox.showerror("Error", "Select a file first.")
            return
        manager = FileManager()
        records = manager.get_all_records()
        filename = os.path.basename(self.selected_file)
        record = next((r for r in records if r["encrypted_file"] == filename), None)
        if not record:
            messagebox.showinfo("Info", "No metadata found for this file.")
            return
        hasher = Hasher()
        current_hash = hasher.generate_hash(self.selected_file)
        if current_hash == record["file_hash"]:
            messagebox.showinfo("Safe", "No tampering detected.")
            self._update_status("Integrity verified")
        else:
            messagebox.showwarning("Tampered", "File has been tampered.")
            self._update_status("Tampering detected")

    # ---------------- HISTORY WINDOW (styled) ----------------
    def _show_history(self):
        manager = FileManager()
        records = manager.get_all_records()
        win = tk.Toplevel(self.root)
        win.title("History — CryptoShield")
        win.geometry("900x480")
        win.configure(bg=self.theme["bg"])
        win.minsize(700, 400)

        ttk.Style().configure("Rice.Treeview", background=self.theme["card"], foreground=self.theme["text"])
        ttk.Style().configure("Rice.Treeview.Heading", background=self.theme["bg_alt"], foreground=self.theme["subtext"])

        cols = ("Original", "Encrypted", "Hash", "Time")
        tree = ttk.Treeview(win, columns=cols, show="headings", style="Rice.Treeview", height=15)
        for c in cols:
            tree.heading(c, text=c)
            tree.column(c, width=200)
        sb = ttk.Scrollbar(win, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=sb.set)
        for r in records:
            tree.insert("", "end", values=(r["original_file"], r["encrypted_file"], r["file_hash"], r["time"]))
        tree.pack(side="left", fill="both", expand=True, padx=20, pady=20)
        sb.pack(side="right", fill="y", pady=20)

    # ---------------- STATUS ----------------
    def _update_status(self, msg):
        self._status_label.config(text=f" λ  {msg}")

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
        self._theme_btn.configure(bg=self.theme["mauve"])

# ---------------- RUN ----------------
def run_app():
    root = tk.Tk()
    app = CryptoShieldApp(root)
    root.mainloop()
