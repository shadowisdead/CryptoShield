"""Tooltip widget for buttons and controls."""

import tkinter as tk


class ToolTip:
    """Shows a tooltip on hover."""

    def __init__(self, widget: tk.Widget, text: str, delay: int = 500):
        self.widget = widget
        self.text = text
        self.delay = delay
        self._id = None
        self._tw = None
        widget.bind("<Enter>", self._on_enter)
        widget.bind("<Leave>", self._on_leave)

    def _on_enter(self, event=None):
        self._id = self.widget.after(self.delay, self._show)

    def _on_leave(self, event=None):
        if self._id:
            self.widget.after_cancel(self._id)
            self._id = None
        self._hide()

    def _show(self):
        self._id = None
        if self._tw:
            return
        x, y, _, _ = self.widget.bbox("insert") if hasattr(self.widget, "bbox") else (0, 0, 0, 0)
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 25
        self._tw = tk.Toplevel(self.widget)
        self._tw.wm_overrideredirect(True)
        self._tw.wm_geometry(f"+{x}+{y}")
        label = tk.Label(
            self._tw,
            text=self.text,
            justify="left",
            relief="solid",
            borderwidth=1,
            padx=6,
            pady=4,
            font=("Segoe UI", 9),
        )
        label.pack()

    def _hide(self):
        if self._tw:
            self._tw.destroy()
            self._tw = None
