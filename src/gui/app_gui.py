import tkinter as tk
from tkinter import filedialog, messagebox
import os

from core.key_manager import KeyManager
from core.encryptor import Encryptor
from core.decryptor import Decryptor
from core.integrity_checker import IntegrityChecker


class CryptoShieldApp:
    def __init__(self, root):
        self.root = root
        self.root.title("CryptoShield - Secure File Tool")
        self.root.geometry("500x400")

        self.file_path = tk.StringVar()
        self.hash_value = tk.StringVar()

        self.build_ui()

    def build_ui(self):
        tk.Label(self.root, text="CryptoShield", font=("Arial", 18, "bold")).pack(pady=10)

        tk.Entry(self.root, textvariable=self.file_path, width=50).pack(pady=5)
        tk.Button(self.root, text="Browse File", command=self.browse_file).pack()

        tk.Label(self.root, text="Password").pack(pady=5)
        self.password_entry = tk.Entry(self.root, show="*", width=30)
        self.password_entry.pack()

        tk.Button(self.root, text="Encrypt File", command=self.encrypt_file).pack(pady=5)
        tk.Button(self.root, text="Decrypt File", command=self.decrypt_file).pack(pady=5)

        tk.Button(self.root, text="Generate Hash", command=self.generate_hash).pack(pady=5)
        tk.Entry(self.root, textvariable=self.hash_value, width=60).pack(pady=5)

        tk.Button(self.root, text="Verify Integrity", command=self.verify_integrity).pack(pady=5)

    def browse_file(self):
        file = filedialog.askopenfilename()
        if file:
            self.file_path.set(file)

    def encrypt_file(self):
        path = self.file_path.get()
        password = self.password_entry.get()

        if not path or not password:
            messagebox.showerror("Error", "File and password required")
            return

        km = KeyManager(password)
        key = km.derive_key()
        encryptor = Encryptor(key)

        output = path + ".enc"
        encryptor.encrypt_file(path, output)

        checker = IntegrityChecker()
        self.hash_value.set(checker.generate_hash(output))

        messagebox.showinfo("Success", "File encrypted successfully")

    def decrypt_file(self):
        path = self.file_path.get()
        password = self.password_entry.get()

        if not path or not password:
            messagebox.showerror("Error", "File and password required")
            return

        km = KeyManager(password)
        key = km.derive_key()
        decryptor = Decryptor(key)

        output = path.replace(".enc", ".dec")
        success = decryptor.decrypt_file(path, output)

        if success:
            messagebox.showinfo("Success", "File decrypted successfully")
        else:
            if os.path.exists(output):
                os.remove(output)
            messagebox.showerror("Error", "Wrong password or corrupted file")

    def generate_hash(self):
        path = self.file_path.get()
        if not path:
            messagebox.showerror("Error", "Select a file first")
            return

        checker = IntegrityChecker()
        self.hash_value.set(checker.generate_hash(path))

    def verify_integrity(self):
        path = self.file_path.get()
        expected_hash = self.hash_value.get()

        if not path or not expected_hash:
            messagebox.showerror("Error", "File and hash required")
            return

        checker = IntegrityChecker()
        if checker.verify_integrity(path, expected_hash):
            messagebox.showinfo("Verified", "File integrity intact")
        else:
            messagebox.showerror("Warning", "File integrity compromised")


def run():
    root = tk.Tk()
    app = CryptoShieldApp(root)
    root.mainloop()
