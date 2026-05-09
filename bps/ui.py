"""
Small UI dialogs based on tkinter (ships with Python, zero extra deps).

These are intentionally minimal - the *real* UI is the HTML report. The tray
just needs prompts and progress.
"""

from __future__ import annotations

import platform
import threading
import tkinter as tk
from pathlib import Path
from tkinter import simpledialog, messagebox
from datetime import datetime


_ASSET_DIR = Path(__file__).parent / "assets"
_ICO_PATH = _ASSET_DIR / "logo.ico"
_PNG_PATH = _ASSET_DIR / "logo.png"


def _apply_window_icon(root: tk.Tk | tk.Toplevel) -> None:
    """Best-effort: stamp the Burika logo onto a Tk window's title bar.

    On Windows ``iconbitmap`` with a real .ico file is the only way to get a
    crisp icon; ``iconphoto`` with PNG works cross-platform but Windows often
    renders it blurry at small sizes. We try both so missing assets degrade
    gracefully.
    """
    if platform.system() == "Windows" and _ICO_PATH.exists():
        try:
            root.iconbitmap(default=str(_ICO_PATH))
            return
        except Exception:
            pass
    if _PNG_PATH.exists():
        try:
            img = tk.PhotoImage(file=str(_PNG_PATH))
            root.iconphoto(True, img)
            # Tk does not retain a reference; without this, the icon vanishes
            # the moment Python garbage-collects ``img``.
            root._bps_icon_ref = img  # type: ignore[attr-defined]
        except Exception:
            pass


def ask_destination(default: str = "") -> str | None:
    """Modal prompt for a destination host."""
    root = tk.Tk()
    _apply_window_icon(root)
    root.withdraw()
    try:
        return simpledialog.askstring(
            "BPS — BurikaPathScope",
            "Destination host (e.g. eu320e.odoo.com or google.com):",
            initialvalue=default,
        )
    finally:
        root.destroy()


def show_message(title: str, message: str) -> None:
    root = tk.Tk()
    _apply_window_icon(root)
    root.withdraw()
    try:
        messagebox.showinfo(title, message)
    finally:
        root.destroy()


class ProgressWindow:
    """A tiny non-modal progress window with a log + close button."""

    def __init__(self, title: str = "BPS — BurikaPathScope"):
        self.root = tk.Tk()
        _apply_window_icon(self.root)
        self.root.title(title)
        self.root.configure(bg="#fafaf7")

        self._title_var = tk.StringVar(value="Working…")
        self._title = tk.Label(
            self.root,
            textvariable=self._title_var,
            font=("Helvetica", 14, "bold"),
            bg="#fafaf7", fg="#1a1a1a",
            anchor="w", padx=16, pady=12,
        )
        self._title.pack(fill="x")

        # Sizing strategy:
        #  - Text widget gets explicit char-grid dims (width, height) which
        #    Tk converts into pixel hints for the parent geometry manager.
        #  - We don't call .geometry() so the window opens sized to content.
        #  - User can still resize and the Text widget grows because we pack
        #    with fill+expand and don't pin anything below.
        self._text = tk.Text(
            self.root,
            font=("Menlo", 10),
            bg="white", fg="#1a1a1a",
            wrap="word", padx=12, pady=8,
            width=78, height=12,  # initial size; grows as we log up to the cap
            highlightthickness=1, highlightbackground="#e8e6df",
        )
        self._text.pack(fill="both", expand=True, padx=16, pady=(0, 12))
        self._text.configure(state="disabled")

        self._btn_frame = tk.Frame(self.root, bg="#fafaf7")
        self._btn_frame.pack(fill="x", padx=16, pady=(0, 16))
        self._close_btn = tk.Button(
            self._btn_frame, text="Close", command=self.root.destroy,
            state="disabled",
        )
        self._close_btn.pack(side="right")

        # Set a reasonable minimum so the window doesn't squash on resize
        self.root.update_idletasks()
        self.root.minsize(420, 380)

        self._lock = threading.Lock()
        # Track lines so we can grow the Text widget to fit content (within
        # a sensible cap) instead of forcing the user to scroll.
        self._line_count = 0
        self._max_grow_lines = 32

    def set_title(self, text: str) -> None:
        self.root.after(0, lambda: self._title_var.set(text))

    def log(self, line: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        msg = f"[{ts}] {line}\n"

        def _append():
            self._text.configure(state="normal")
            self._text.insert("end", msg)
            self._text.see("end")
            self._text.configure(state="disabled")

            # Grow the Text widget to fit content, up to a cap. Beyond that
            # the user scrolls — keeping the window from filling the screen
            # on long traces.
            self._line_count += 1
            target = min(self._line_count + 2, self._max_grow_lines)
            try:
                if int(self._text["height"]) < target:
                    self._text.configure(height=target)
            except (tk.TclError, ValueError):
                pass

        self.root.after(0, _append)

    def done(self, title: str | None = None) -> None:
        if title:
            self.set_title(title)
        self.root.after(0, lambda: self._close_btn.configure(state="normal"))

    def run(self) -> None:
        self.root.mainloop()
