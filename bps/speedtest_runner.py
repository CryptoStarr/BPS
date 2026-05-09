"""
Local speedtest wrapper.

We use the `speedtest-cli` Python library (Ookla-style measurement against
their nearest server). This is what the ISP would do, so we are running
exactly the same test the ISP runs - and that's the point: it'll usually
look fine even when a specific destination is slow.
"""

from __future__ import annotations

import os
import sys
import time
from dataclasses import dataclass


def _ensure_stdio() -> None:
    """speedtest-cli prints to stderr and calls ``sys.stderr.fileno()`` for
    progress output. Under pythonw.exe / PyInstaller --windowed those streams
    are ``None``, which raises ``'NoneType' has no attribute 'fileno'``. The
    fix is to point the stream at the OS null device so it has a real fd.
    The main entry point already does this; doing it again here is a cheap
    safeguard for callers (e.g. tests) that bypass __main__."""
    try:
        if sys.stdin is None:
            sys.stdin = open(os.devnull, "r")
        if sys.stdout is None:
            sys.stdout = open(os.devnull, "w")
        if sys.stderr is None:
            sys.stderr = open(os.devnull, "w")
    except OSError:
        pass


@dataclass
class SpeedtestResult:
    download_mbps: float
    upload_mbps: float
    ping_ms: float
    server_name: str
    server_country: str
    server_sponsor: str
    started_at: float
    finished_at: float
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "download_mbps": self.download_mbps,
            "upload_mbps": self.upload_mbps,
            "ping_ms": self.ping_ms,
            "server_name": self.server_name,
            "server_country": self.server_country,
            "server_sponsor": self.server_sponsor,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_s": self.finished_at - self.started_at,
            "error": self.error,
        }


def run_speedtest() -> SpeedtestResult:
    started = time.time()
    _ensure_stdio()
    try:
        import speedtest  # type: ignore
    except ImportError:
        return SpeedtestResult(
            download_mbps=0, upload_mbps=0, ping_ms=0,
            server_name="", server_country="", server_sponsor="",
            started_at=started, finished_at=time.time(),
            error="speedtest-cli is not installed (pip install speedtest-cli)",
        )

    try:
        s = speedtest.Speedtest(secure=True)
        s.get_best_server()
        s.download(threads=None)
        s.upload(threads=None, pre_allocate=False)
        results = s.results.dict()
        srv = results.get("server", {})
        return SpeedtestResult(
            download_mbps=results["download"] / 1_000_000,
            upload_mbps=results["upload"] / 1_000_000,
            ping_ms=results["ping"],
            server_name=srv.get("name", ""),
            server_country=srv.get("country", ""),
            server_sponsor=srv.get("sponsor", ""),
            started_at=started,
            finished_at=time.time(),
        )
    except Exception as e:
        return SpeedtestResult(
            download_mbps=0, upload_mbps=0, ping_ms=0,
            server_name="", server_country="", server_sponsor="",
            started_at=started, finished_at=time.time(),
            error=str(e),
        )
