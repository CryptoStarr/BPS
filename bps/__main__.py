"""BPS entry point.

On Windows we do a small bit of process setup *before* importing pystray /
tkinter so that:

- the python.exe console window doesn't appear in the taskbar (this is a
  background tray app);
- the OS treats us as our own application via AppUserModelID, so the
  taskbar / Alt-Tab grouping shows the Burika icon instead of Python's.

Both calls are best-effort: if any of them fail we still launch.
"""

from __future__ import annotations

import platform


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


_windows_pre_init()

from .tray import main  # noqa: E402  (import after pre-init by design)


if __name__ == "__main__":
    main()
