"""BPS entry point.

On Windows we do a small bit of process setup *before* importing pystray /
tkinter / speedtest so that:

- ``sys.stdin/stdout/stderr`` are real file objects even under pythonw.exe
  and PyInstaller --windowed (otherwise libraries that call ``.fileno()``
  on them — speedtest-cli is one such — crash the request);
- the python.exe console window doesn't appear in the taskbar (this is a
  background tray app);
- the OS treats us as our own application via AppUserModelID, so the
  taskbar / Alt-Tab grouping shows the Burika icon instead of Python's.

All three steps are best-effort: if any of them fail we still launch.
"""

from __future__ import annotations

import os
import platform
import sys


def _patch_missing_stdio() -> None:
    """Re-bind ``sys.stdin/stdout/stderr`` to os.devnull when they are ``None``.

    pythonw.exe and PyInstaller --windowed run without a console, leaving the
    standard streams as ``None``. Most stdlib code is fine with that, but
    third-party libraries (notably speedtest-cli) call ``.fileno()`` on
    stderr to size progress bars and crash with::

        AttributeError: 'NoneType' object has no attribute 'fileno'

    Pointing the streams at the OS null device gives them a real fd, costs
    nothing, and keeps the streams compatible with any library that wants
    to write to them.
    """
    try:
        if sys.stdin is None:
            sys.stdin = open(os.devnull, "r")
        if sys.stdout is None:
            sys.stdout = open(os.devnull, "w")
        if sys.stderr is None:
            sys.stderr = open(os.devnull, "w")
    except OSError:
        pass


def _windows_pre_init() -> None:
    """Hide the console and claim our own AppUserModelID."""
    if platform.system() != "Windows":
        return
    try:
        import ctypes
        # SW_HIDE = 0 — drop the console window so it doesn't show in taskbar.
        hwnd = ctypes.windll.kernel32.GetConsoleWindow()
        if hwnd:
            ctypes.windll.user32.ShowWindow(hwnd, 0)
    except Exception:
        pass
    try:
        import ctypes
        # AppUserModelID needs a reverse-DNS-style identifier. With this set,
        # Windows associates our window icon with the *app* (not the running
        # python.exe) so taskbar grouping and the icon both come from us.
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
            "co.burika.bps"
        )
    except Exception:
        pass


# Patch stdio FIRST — must happen before any module that touches the streams
# during import (pystray and tkinter both write to stderr in some paths).
_patch_missing_stdio()
_windows_pre_init()

from .tray import main  # noqa: E402  (import after pre-init by design)


if __name__ == "__main__":
    main()
