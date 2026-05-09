"""PyInstaller entry point.

PyInstaller wants a script path, not ``python -m bps``. This file is the
shim: it runs the same Windows pre-init that ``python -m bps`` would run,
then hands control to the tray.
"""

from bps.__main__ import _windows_pre_init
_windows_pre_init()

from bps.tray import main  # noqa: E402

if __name__ == "__main__":
    main()
