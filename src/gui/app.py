import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from encryption.encryptor import Encryptor
from encryption.decryptor import Decryptor
from encryption.algorithms import get_algorithm, ALGORITHMS
from integrity.hasher import Hasher
from core.file_manager import FileManager, FileRecord
from core.keygen import generate_random_password
from .tooltip import ToolTip
from .preview import create_preview_window, can_preview_text, can_preview_image

try:
    from core.folder_watcher import start_folder_watch, stop_folder_watch, HAS_WATCHDOG
except Exception:
    HAS_WATCHDOG = False
    start_folder_watch = stop_folder_watch = None
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
        self.selected_files = []
        self.theme = Theme.DARK
        self._clipboard_clear_id = None
        self._folder_observer = None
        self._backup_folder = ""
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
        self._pass_strength.pack(anchor="w", padx=20, pady=(0, 8))
        opt_row = tk.Frame(self._pass_card, bg=self.theme["card"])
        opt_row.pack(anchor="w", padx=20, pady=(0, 20))
        self._gen_pass_btn = self._styled_btn(opt_row, "Generate", self._generate_password, self.theme["teal"])
        self._gen_pass_btn.pack(side="left", padx=(0, 8))
        self._theme_btn = self._styled_btn(opt_row, "Toggle Theme", self._toggle_theme, self.theme["mauve"])
        self._theme_btn.pack(side="left")
        ToolTip(self._gen_pass_btn, "Generate a secure random password")
        self._algo_var = tk.StringVar(value="AES-256")
        algo_frame = tk.Frame(self._pass_card, bg=self.theme["card"])
        algo_frame.pack(anchor="w", padx=20, pady=(0, 8))
        tk.Label(algo_frame, text="Algorithm:", bg=self.theme["card"], fg=self.theme["subtext"], font=(FONT_UI[0], 9)).pack(side="left", padx=(0, 8))
        ttk.Combobox(algo_frame, textvariable=self._algo_var, values=list(ALGORITHMS.keys()), state="readonly", width=12).pack(side="left")
        self._secure_delete_var = tk.BooleanVar(value=False)
        sd_cb = tk.Checkbutton(self._pass_card, text="Secure delete original", variable=self._secure_delete_var, bg=self.theme["card"], fg=self.theme["subtext"], selectcolor=self.theme["bg_alt"], activebackground=self.theme["card"], activeforeground=self.theme["text"])
        sd_cb.pack(anchor="w", padx=20, pady=(0, 4))
        ToolTip(sd_cb, "Overwrite file with random data before deletion after encryption")

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
            ("Encrypt", self._encrypt_with_progress, self.theme["blue"], "Encrypt selected file(s) with password"),
            ("Decrypt", self._decrypt_with_progress, self.theme["green"], "Decrypt selected encrypted file(s)"),
            ("Verify Hash", self._verify_file, self.theme["peach"], "Generate SHA-256 hash of selected file"),
            ("History", self._show_history, self.theme["subtext"], "View encrypted file history and export"),
            ("Check Tamper", self._check_file_tamper, self.theme["red"], "Verify if encrypted file has been modified"),
            ("Watch Folder", self._toggle_watch_folder, self.theme["lavender"], "Auto-encrypt new files in a folder (requires watchdog)"),
        ]
        for i, (text, cmd, color, tip) in enumerate(btns):
            btn = self._styled_btn(self._actions_frame, text, cmd, color)
            btn.grid(row=i // 3, column=i % 3, padx=10, pady=8)
            ToolTip(btn, tip)

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
        self._progress.pack(fill="x", pady=2)
        self._progress_label = tk.Label(self._prog_frame, text="", font=(FONT_MONO[0], 9), bg=self.theme["bg"], fg=self.theme["subtext"])
        self._progress_label.pack(anchor="e")

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

    def _generate_password(self):
        pwd = generate_random_password(20)
        self._pass_entry.delete(0, tk.END)
        self._pass_entry.insert(0, pwd)
        self._update_password_strength()
        self.root.clipboard_clear()
        self.root.clipboard_append(pwd)
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
                messagebox.showinfo("Info", "No files found in folder.")

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
            messagebox.showinfo("Info", "Select a file first.")
            return
        if not (can_preview_text(path) or can_preview_image(path)):
            messagebox.showinfo("Info", "Preview not available for this file type.")
            return
        create_preview_window(self.root, path, self.theme)

    # ---------------- FILE SELECTION ----------------

    # ---------------- ENCRYPTION / DECRYPTION ----------------
    def _encrypt_with_progress(self):
        self._run_with_progress(self._perform_encryption, "Encrypting...", "Encryption complete")

    def _decrypt_with_progress(self):
        self._run_with_progress(self._perform_decryption, "Decrypting...", "Decryption complete")

    def _run_with_progress(self, task_fn, start_msg, end_msg):
        def run():
            try:
                self._progress["value"] = 0
                self._progress_label.config(text="0%")
                self._update_status(start_msg)

                def update_progress(done: int, total: int):
                    pct = int(100 * done / total) if total else 0
                    self._progress["value"] = pct
                    self._progress_label.config(text=f"{pct}%")
                    self.root.update_idletasks()

                task_fn(update_progress)
                self._progress["value"] = 100
                self._progress_label.config(text="100%")
                self._update_status(end_msg)
                self._notify_desktop(end_msg)
            except Exception as e:
                messagebox.showerror("Error", str(e))
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
            messagebox.showerror("Error", "Select at least one file.")
            return
        pwd = self._pass_entry.get()
        if not pwd:
            messagebox.showerror("Error", "Enter a password.")
            return
        algo_name = self._algo_var.get()
        if algo_name == "RSA":
            messagebox.showinfo("Info", "RSA mode: Use RSA key files. Generate keys first.")
            return
        Engine = get_algorithm(algo_name)
        engine = Engine(pwd)
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
                messagebox.showerror("Error", f"Failed: {fp}\n{e}")
                return
            if total > 1:
                progress_cb(i + 1, total)
                self.root.update_idletasks()
        msg = f"Encrypted {len(files)} file(s)." if total > 1 else f"Encrypted to:\n{files[0]}.enc"
        messagebox.showinfo("Success", msg)

    def _perform_decryption(self, progress_cb):
        files = [f for f in self.selected_files if os.path.isfile(f)]
        if not files:
            messagebox.showerror("Error", "Select at least one file.")
            return
        pwd = self._pass_entry.get()
        if not pwd:
            messagebox.showerror("Error", "Enter a password.")
            return
        algo_name = self._algo_var.get()
        if algo_name == "RSA":
            messagebox.showinfo("Info", "RSA mode: Load private key for decryption.")
            return
        Engine = get_algorithm(algo_name)
        engine = Engine(pwd)
        total = len(files)
        for i, fp in enumerate(files):
            try:
                cb = progress_cb if total == 1 else None
                dec_path = engine.decrypt_file(fp, progress_callback=cb)
                if total > 1:
                    progress_cb(i + 1, total)
                messagebox.showinfo("Success", f"Decrypted to:\n{dec_path}")
                break
            except Exception as e:
                try:
                    decryptor = Decryptor(pwd)
                    dec_path = decryptor.decrypt_file(fp)
                    messagebox.showinfo("Success", f"Decrypted to:\n{dec_path}")
                    break
                except Exception as e2:
                    messagebox.showerror("Error", str(e2))
                    return

    # ---------------- INTEGRITY & TAMPER ----------------
    def _verify_file(self):
        path = self.selected_files[0] if self.selected_files else None
        if not path or not os.path.isfile(path):
            messagebox.showerror("Error", "Select a file first.")
            return
        hasher = Hasher()
        file_hash = hasher.generate_hash(path)
        self.root.clipboard_clear()
        self.root.clipboard_append(file_hash)
        self._schedule_clipboard_clear(10)
        messagebox.showinfo("SHA-256 Hash", f"{file_hash}\n(Copied to clipboard, will clear in 10s)")
        self._update_status("Hash generated")

    def _check_file_tamper(self):
        path = self.selected_files[0] if self.selected_files else None
        if not path or not os.path.isfile(path):
            messagebox.showerror("Error", "Select a file first.")
            return
        manager = FileManager()
        records = manager.get_all_records()
        sel_norm = os.path.normpath(path)
        sel_basename = os.path.basename(path)
        record = next((r for r in records if os.path.normpath(r.get("encrypted_file", "")) == sel_norm or os.path.basename(r.get("encrypted_file", "")) == sel_basename), None)
        if not record:
            messagebox.showinfo("Info", "No metadata found for this file.")
            return
        hasher = Hasher()
        current_hash = hasher.generate_hash(path)
        if current_hash == record.get("file_hash"):
            messagebox.showinfo("Safe", "No tampering detected.")
            self._update_status("Integrity verified")
        else:
            messagebox.showwarning("Tampered", "File has been tampered.")
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
                messagebox.showerror("Error", "Install openpyxl: pip install openpyxl")
                return
        messagebox.showinfo("Success", f"Exported to {path}")

    # ---------------- STATUS ----------------
    def _update_status(self, msg):
        self._status_label.config(text=f" λ  {msg}")

    def _toggle_watch_folder(self):
        if not HAS_WATCHDOG or not start_folder_watch:
            messagebox.showinfo("Info", "Install watchdog: pip install watchdog")
            return
        if self._folder_observer:
            stop_folder_watch(self._folder_observer)
            self._folder_observer = None
            self._update_status("Stopped watching folder")
            return
        folder = filedialog.askdirectory(title="Select folder to watch")
        if not folder:
            return
        pwd = self._pass_entry.get()
        if not pwd:
            messagebox.showwarning("Warning", "Set a password first. New files will be encrypted with it.")
            return
        def on_new(path):
            self.root.after(0, lambda: self._encrypt_file_path(path))
        self._folder_observer = start_folder_watch(folder, on_new)
        self._update_status(f"Watching: {folder}")

    def _encrypt_file_path(self, path: str):
        pwd = self._pass_entry.get()
        if not pwd or not os.path.isfile(path):
            return
        try:
            Engine = get_algorithm(self._algo_var.get())
            engine = Engine(pwd)
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

# ---------------- RUN ----------------
def run_app():
    root = tk.Tk()
    app = CryptoShieldApp(root)
    root.mainloop()
