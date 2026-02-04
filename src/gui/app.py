import tkinter as tk
from tkinter import ttk
from tkinter import filedialog, messagebox
from encryption.encryptor import Encryptor
from encryption.decryptor import Decryptor
from integrity.hasher import Hasher
from core.file_manager import FileManager, FileRecord
from datetime import datetime
import os 

class CryptoShieldApp:
    def __init__(self, root):
        self.root = root
        self.root.title("CryptoShield - Secure File Encryption Tool")
        self.root.geometry("1000x700")

        x = (self.root.winfo_screenwidth() // 2) - 500
        y = (self.root.winfo_screenheight() // 2) - 350
        self.root.geometry(f"1000x700+{x}+{y}")

        self.root.resizable(True, True)

        self.selected_file = ""

        self.build_ui()

    def build_ui(self):

        title = tk.Label(
            self.root,
            text="CryptoShield",
            font=("Helvetica", 28, "bold"),
            fg="#1f2933"
        )
        title.pack(pady=15)

        subtitle = tk.Label(
            self.root,
            text="Secure File Encryption & Integrity Verification",
            font=("Helvetica", 12)
        )
        subtitle.pack(pady=5)

        main_frame = tk.Frame(self.root)
        main_frame.pack(pady=30)

        file_frame = tk.LabelFrame(
            main_frame,
            text=" File Selection ",
            padx=20,
            pady=20,
            font=("Arial", 12, "bold")
        )
        file_frame.grid(row=0, column=0, padx=20, pady=10)

        self.file_label = tk.Label(
            file_frame,
            text="No file selected",
            width=50,
            wraplength=350,
            anchor="w"
        )
        self.file_label.pack(pady=10)

        select_btn = tk.Button(
            file_frame,
            text="Browse File",
            width=20,
            command=self.select_file
        )
        select_btn.pack()

        pass_frame = tk.LabelFrame(
            main_frame,
            text=" Security ",
            padx=20,
            pady=20,
            font=("Arial", 12, "bold")
        )
        pass_frame.grid(row=0, column=1, padx=20, pady=10)

        tk.Label(pass_frame, text="Enter Password:").pack(pady=5)

        self.password_entry = tk.Entry(
            pass_frame,
            show="*",
            width=30,
            font=("Arial", 12)
        )
        self.password_entry.pack(pady=10)

        action_frame = tk.LabelFrame(
            self.root,
            text=" Actions ",
            padx=20,
            pady=20,
            font=("Arial", 12, "bold")
        )
        action_frame.pack(pady=20)

        tk.Button(
            action_frame,
            text="Encrypt File",
            width=20,
            height=2,
            command=self.encrypt_file
        ).grid(row=0, column=0, padx=15, pady=10)

        tk.Button(
            action_frame,
            text="Decrypt File",
            width=20,
            height=2,
            command=self.decrypt_file
        ).grid(row=0, column=1, padx=15, pady=10)

        tk.Button(
            action_frame,
            text="Verify Integrity",
            width=20,
            height=2,
            command=self.verify_file
        ).grid(row=0, column=2, padx=15, pady=10)

        tk.Button(
            action_frame,
            text="View Encrypted Files",
            width=20,
            height=2,
            command=self.show_history
        ).grid(row=1, column=1, pady=10)

        self.status_label = tk.Label(
            self.root,
            text="Status: Ready",
            bd=1,
            relief=tk.SUNKEN,
            anchor="w",
            padx=10
        )
        self.status_label.pack(fill="x", side="bottom")

    # ---------------- FUNCTIONS ----------------

    def select_file(self):
        self.selected_file = filedialog.askopenfilename()
        if self.selected_file:
            self.file_label.config(text=self.selected_file)
            self.update_status("File selected")

    def encrypt_file(self):
        if not self.selected_file:
            messagebox.showerror("Error", "Please select a file first!")
            return

        password = self.password_entry.get()
        if not password:
            messagebox.showerror("Error", "Please enter a password!")
            return

        try:
            encryptor = Encryptor(password)
            encrypted_path = encryptor.encrypt_file(self.selected_file)

            hasher = Hasher()
            file_hash = hasher.generate_hash(self.selected_file)

            manager = FileManager()

            record = FileRecord(
                original_file=os.path.basename(self.selected_file),
                encrypted_file=os.path.basename(encrypted_path),
                file_hash=file_hash,
                time=str(datetime.now())
            )

            manager.save_record(record)

            self.update_status("File encrypted and metadata saved")

            messagebox.showinfo(
                "Success",
                f"Encrypted file saved as:\n{encrypted_path}"
            )

        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decrypt_file(self):
        if not self.selected_file:
            messagebox.showerror("Error", "Please select a file first!")
            return

        password = self.password_entry.get()
        if not password:
            messagebox.showerror("Error", "Please enter a password!")
            return

        try:
            decryptor = Decryptor(password)
            decrypted_path = decryptor.decrypt_file(self.selected_file)

            self.update_status("File decrypted successfully")

            messagebox.showinfo(
                "Success",
                f"Decrypted file saved as:\n{decrypted_path}"
            )

        except Exception:
            messagebox.showerror("Error", "Incorrect password or corrupted file!")

    def verify_file(self):
        if not self.selected_file:
            messagebox.showerror("Error", "Please select a file first!")
            return

        try:
            hasher = Hasher()
            file_hash = hasher.generate_hash(self.selected_file)

            messagebox.showinfo(
                "Integrity Hash",
                f"SHA-256 Hash:\n{file_hash}"
            )

            self.update_status("Hash generated")

        except Exception as e:
            messagebox.showerror("Error", str(e))

    def show_history(self):
        manager = FileManager()
        records = manager.get_all_records()   # fresh load

        history_window = tk.Toplevel(self.root)
        history_window.title("Encrypted File History")
        history_window.geometry("900x500")

        columns = ("Original File", "Encrypted File", "Hash", "Time")

        tree = ttk.Treeview(history_window, columns=columns, show="headings")

        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=200)

        for record in records:
            tree.insert(
                "",
                "end",
                values=(
                    record["original_file"],
                    record["encrypted_file"],
                    record["file_hash"],   # ✅ FIXED
                    record["time"]
                )
            )

        scrollbar = ttk.Scrollbar(
            history_window,
            orient="vertical",
            command=tree.yview
        )

        tree.configure(yscroll=scrollbar.set)

        tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def update_status(self, message):
        self.status_label.config(text=f"Status: {message}")


def run_app():
    root = tk.Tk()
    app = CryptoShieldApp(root)
    root.mainloop()
