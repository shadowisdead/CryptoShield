"""File preview for text and images."""

import tkinter as tk
import os

# Optional PIL for image preview
try:
    from PIL import Image, ImageTk #type: ignore
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

TEXT_EXTS = {".txt", ".py", ".json", ".xml", ".html", ".css", ".js", ".md", ".log", ".csv"}
IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp"}
MAX_PREVIEW_BYTES = 64 * 1024  # 64 KB for text
MAX_PREVIEW_LINES = 50


def can_preview_text(path: str) -> bool:
    ext = os.path.splitext(path)[1].lower()
    return ext in TEXT_EXTS


def can_preview_image(path: str) -> bool:
    ext = os.path.splitext(path)[1].lower()
    return ext in IMAGE_EXTS and HAS_PIL


def get_text_preview(path: str) -> str:
    """Return truncated text preview."""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read(MAX_PREVIEW_BYTES)
        lines = content.splitlines()[:MAX_PREVIEW_LINES]
        return "\n".join(lines) + ("\n..." if len(content) >= MAX_PREVIEW_BYTES else "")
    except Exception:
        return "(Unable to preview)"


def create_preview_window(parent: tk.Tk, path: str, theme: dict) -> tk.Toplevel:
    """Create a preview window for text or image files."""
    win = tk.Toplevel(parent)
    win.title(f"Preview — {os.path.basename(path)}")
    win.geometry("600x450")
    win.configure(bg=theme.get("bg", "#1e1e2e"))
    win.minsize(400, 300)

    if can_preview_image(path):
        try:
            img = Image.open(path)
            img.thumbnail((580, 400))
            photo = ImageTk.PhotoImage(img)
            lbl = tk.Label(win, image=photo, bg=theme.get("bg", "#1e1e2e"))
            lbl.image = photo
            lbl.pack(expand=True, fill="both", padx=10, pady=10)
        except Exception:
            txt = tk.Text(win, wrap="word", font=("Consolas", 10), bg=theme.get("card", "#313244"), fg=theme.get("text", "#cdd6f4"))
            txt.insert("1.0", get_text_preview(path))
            txt.pack(expand=True, fill="both", padx=10, pady=10)
            txt.config(state="disabled")
    elif can_preview_text(path):
        txt = tk.Text(win, wrap="word", font=("Consolas", 10), bg=theme.get("card", "#313244"), fg=theme.get("text", "#cdd6f4"))
        txt.insert("1.0", get_text_preview(path))
        txt.pack(expand=True, fill="both", padx=10, pady=10)
        txt.config(state="disabled")
    else:
        lbl = tk.Label(win, text="Preview not available for this file type.", font=("Segoe UI", 11), bg=theme.get("bg"), fg=theme.get("subtext"))
        lbl.pack(expand=True, padx=20, pady=20)

    return win
