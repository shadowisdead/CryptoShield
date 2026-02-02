import tkinter as tk
from tkinter import filedialog, messagebox

class CryptoShieldApp:
    def __init__(self, root):
        self.root = root
        self.root.title("CryptoShield - Secure File Encryption Tool")
        self.root.geometry("800x500")
        self.root.update_idletasks()
        width = 800
        height = 500
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f"{width}x{height}+{x}+{y}")

        self.root.resizable(True, True)

        self.selected_file = ""

        self.build_ui()

    def build_ui(self):

        # ===== TITLE =====
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

        # ===== MAIN FRAME =====
        main_frame = tk.Frame(self.root)
        main_frame.pack(pady=30)

        # ===== FILE SECTION =====
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

        # ===== PASSWORD SECTION =====
        pass_frame = tk.LabelFrame(
            main_frame,
            text=" Security ",
            padx=20,
            pady=20,
            font=("Arial", 12, "bold")
        )
        pass_frame.grid(row=0, column=1, padx=20, pady=10)

        pass_label = tk.Label(pass_frame, text="Enter Password:")
        pass_label.pack(pady=5)

        self.password_entry = tk.Entry(
            pass_frame,
            show="*",
            width=30,
            font=("Arial", 12)
        )
        self.password_entry.pack(pady=10)

        # ===== ACTION BUTTONS =====
        action_frame = tk.LabelFrame(
            self.root,
            text=" Actions ",
            padx=20,
            pady=20,
            font=("Arial", 12, "bold")
        )
        action_frame.pack(pady=20)

        encrypt_btn = tk.Button(
            action_frame,
            text="Encrypt File",
            width=20,
            height=2,
            command=self.encrypt_file
        )
        encrypt_btn.grid(row=0, column=0, padx=15, pady=10)

        decrypt_btn = tk.Button(
            action_frame,
            text="Decrypt File",
            width=20,
            height=2,
            command=self.decrypt_file
        )
        decrypt_btn.grid(row=0, column=1, padx=15, pady=10)

        verify_btn = tk.Button(
            action_frame,
            text="Verify Integrity",
            width=20,
            height=2,
            command=self.verify_file
        )
        verify_btn.grid(row=0, column=2, padx=15, pady=10)

        # ===== STATUS BAR =====
        self.status_label = tk.Label(
            self.root,
            text="Status: Ready",
            bd=1,
            relief=tk.SUNKEN,
            anchor="w",
            padx=10
        )
        self.status_label.pack(fill="x", side="bottom")

    # ------------------ FUNCTIONS ------------------

    def select_file(self):
        self.selected_file = filedialog.askopenfilename()
        if self.selected_file:
            self.file_label.config(text=self.selected_file)
            self.update_status("File selected")

    def encrypt_file(self):
        if not self.selected_file:
            messagebox.showerror("Error", "Please select a file first!")
            return
        self.update_status("Encryption will be added next")

    def decrypt_file(self):
        if not self.selected_file:
            messagebox.showerror("Error", "Please select a file first!")
            return
        self.update_status("Decryption will be added next")

    def verify_file(self):
        if not self.selected_file:
            messagebox.showerror("Error", "Please select a file first!")
            return
        self.update_status("Integrity check will be added next")

    def update_status(self, message):
        self.status_label.config(text=f"Status: {message}")


def run_app():
    root = tk.Tk()
    app = CryptoShieldApp(root)
    root.mainloop()
