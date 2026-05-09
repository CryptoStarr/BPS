@echo off
rem Launch BPS as a background tray app — uses pythonw.exe so no console
rem window flashes up. Double-click this file to start; the Burika icon
rem will appear in the system tray.
start "" pythonw -m bps
