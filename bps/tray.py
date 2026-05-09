"""
The tray agent: a system-tray icon with a menu that runs path tests.

Uses pystray (cross-platform: Windows, macOS, Linux). The icon is loaded
from bps/assets/logo.png (Burika brand mark) with a programmatic fallback
for fresh checkouts where the asset isn't yet on disk.
"""

from __future__ import annotations

import threading
import time
import webbrowser
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from PIL import Image, ImageDraw
import pystray

from . import APP_NAME, APP_LONG_NAME, history
from .analyzer import analyze
from .geoip import asn_lookup, enrich, is_private
from .report import render_report
from .server import server_url, start_server
from .speedtest_runner import run_speedtest
from .tracer import Tracer
from .ui import ProgressWindow, ask_destination, show_message


# Brand strings — keep UI labels routed through here so a future rename only
# touches one place.
APP_TITLE = f"{APP_NAME} — {APP_LONG_NAME}"

ASSET_DIR = Path(__file__).parent / "assets"
LOGO_PATH = ASSET_DIR / "logo.png"


# State that persists across menu invocations
_LAST_DEST = "google.com"
_LAST_REPORT: Path | None = None


def _load_icon_image() -> Image.Image:
    """Load the Burika brand logo from ``bps/assets/logo.png``.

    Falls back to a programmatic chain-of-dots icon if the asset is missing,
    so the app still launches in a fresh checkout where the binary hasn't
    been committed yet.
    """
    if LOGO_PATH.exists():
        try:
            img = Image.open(LOGO_PATH).convert("RGBA")
            # System trays render at 16–32 px; pre-resizing with LANCZOS
            # gives a cleaner glyph than letting the OS scale a 1024 px PNG.
            img.thumbnail((64, 64), Image.LANCZOS)
            return img
        except Exception:
            pass
    return _fallback_icon_image()


def _fallback_icon_image(color: str = "#1a1a1a") -> Image.Image:
    """Three connected dots — used when the brand asset isn't on disk."""
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    centers = [(12, 32), (32, 32), (52, 32)]
    d.line([centers[0], centers[2]], fill=color, width=3)
    for cx, cy in centers:
        d.ellipse((cx - 6, cy - 6, cx + 6, cy + 6), fill=color)
    return img


# ---------- Workflows ----------

def _run_path_test(destination: str, run_speedtest_too: bool) -> None:
    """Worker. Builds the report and opens it. Called on a background thread."""
    global _LAST_DEST, _LAST_REPORT
    _LAST_DEST = destination

    progress = ProgressWindow(title=f"{APP_TITLE} — {destination}")

    def worker():
        try:
            progress.log(f"Resolving and tracing {destination} (3 parallel passes for ECMP detection)…")
            tracer = Tracer(max_hops=30, probes_per_hop=3, timeout_s=2.0, port=443, passes=3)

            # Per-hop streaming so the user can watch progress instead of
            # staring at "Working…". One log line per (pass, ttl) pair to
            # avoid 3-passes-triple-up; AS resolution happens off-thread so
            # the IP/RTT shows immediately and the network name follows when
            # the Cymru lookup returns.
            seen_pass_ttl: set[tuple[int, int]] = set()
            resolved_ips: set[str] = set()
            seen_lock = threading.Lock()
            asn_pool = ThreadPoolExecutor(max_workers=4)

            def _resolve_async(ip: str) -> None:
                with seen_lock:
                    if ip in resolved_ips:
                        return
                    resolved_ips.add(ip)
                if is_private(ip):
                    progress.log(f"             ↳ {ip}: Local network")
                    return
                asn, name = asn_lookup(ip)
                if name and asn:
                    progress.log(f"             ↳ {ip}: {name} · {asn}")
                elif name:
                    progress.log(f"             ↳ {ip}: {name}")
                elif asn:
                    progress.log(f"             ↳ {ip}: {asn}")
                # If neither resolves, stay quiet — no point logging "no info"

            def _on_hop(pass_idx: int, hop) -> None:
                key = (pass_idx, hop.ttl)
                with seen_lock:
                    if key in seen_pass_ttl:
                        return
                    seen_pass_ttl.add(key)
                ip = hop.ip or "*"
                rtt = f"{hop.min_rtt:.0f}ms" if hop.min_rtt is not None else "—"
                progress.log(f"  pass {pass_idx + 1}: hop {hop.ttl:>2} → {ip} ({rtt})")
                if hop.ip:
                    asn_pool.submit(_resolve_async, hop.ip)

            # Run trace + speedtest in parallel
            with ThreadPoolExecutor(max_workers=2) as pool:
                trace_future = pool.submit(tracer.trace_full, destination, _on_hop)
                st_future = pool.submit(run_speedtest) if run_speedtest_too else None

                trace = trace_future.result()
                progress.log(f"Trace finished: {len(trace.hops)} hops, "
                             f"method={trace.method}")

                # Wait for any pending streaming AS lookups before we start
                # the bulk enrichment, so the log lines stay in order.
                asn_pool.shutdown(wait=True)
                progress.log("Looking up reverse DNS and AS info for hops…")
                enrich(trace.hops)

                if st_future is not None:
                    progress.log("Waiting for local speedtest to finish…")
                    st = st_future.result()
                    if st.error:
                        progress.log(f"Speedtest error: {st.error}")
                    else:
                        progress.log(
                            f"Speedtest: {st.download_mbps:.1f}↓ / "
                            f"{st.upload_mbps:.1f}↑ Mbps, ping {st.ping_ms:.0f}ms"
                        )
                else:
                    st = None

            progress.log("Analyzing path…")
            analysis = analyze(trace)
            progress.log(f"Verdict: {analysis.headline}")

            progress.log("Rendering report…")
            ts = int(trace.started_at)
            safe = "".join(c if c.isalnum() else "_" for c in destination)[:40]
            report_path = history.reports_dir() / f"{ts}_{safe}.html"
            render_report(trace, analysis, st, report_path)

            history.save_run(trace, analysis, st, report_path)

            global _LAST_REPORT
            _LAST_REPORT = report_path

            progress.log(f"Report saved to {report_path}")
            progress.log("Opening in browser…")
            webbrowser.open(report_path.as_uri())
            progress.done(title=f"{APP_TITLE} — done ({analysis.overall.upper()})")

        except Exception as e:
            progress.log(f"ERROR: {e}")
            progress.done(title=f"{APP_TITLE} — failed")

    threading.Thread(target=worker, daemon=True).start()
    progress.run()


# ---------- Menu callbacks ----------

def _on_run_path_test(icon, item):
    dest = ask_destination(default=_LAST_DEST)
    if dest:
        _run_path_test(dest.strip(), run_speedtest_too=False)


def _on_run_path_and_speedtest(icon, item):
    dest = ask_destination(default=_LAST_DEST)
    if dest:
        _run_path_test(dest.strip(), run_speedtest_too=True)


def _on_open_last_report(icon, item):
    if _LAST_REPORT and _LAST_REPORT.exists():
        webbrowser.open(_LAST_REPORT.as_uri())
    else:
        show_message(f"{APP_TITLE}", "No report yet. Run a path test first.")


def _on_view_history(icon, item):
    runs = history.list_runs(limit=20)
    if not runs:
        show_message(f"{APP_TITLE}", "No history yet.")
        return
    lines = []
    from datetime import datetime
    for r in runs:
        when = datetime.fromtimestamp(r["started_at"]).strftime("%Y-%m-%d %H:%M")
        verdict = r["verdict"].upper()
        lines.append(f"{when}  {verdict:5}  {r['destination']}")
    show_message(f"{APP_TITLE} — recent runs", "\n".join(lines))


def _on_open_history_folder(icon, item):
    webbrowser.open(history.reports_dir().as_uri())


def _on_open_dashboard(icon, item):
    """Open the live HTML dashboard in the user's default browser."""
    url = server_url()
    if not url:
        show_message(APP_TITLE, "Dashboard server is not running.")
        return
    webbrowser.open(url)


def _on_quit(icon, item):
    icon.stop()


# ---------- Entry point ----------

def main() -> None:
    # Start the local dashboard server in the background so the menu's
    # "Open live dashboard" option always has somewhere to send the browser.
    try:
        start_server(port=8765)
    except Exception:
        # If we can't bind a port we still want the rest of the tray to
        # work — the menu item will just show an error message.
        pass

    icon = pystray.Icon(
        name="bps",
        icon=_load_icon_image(),
        title=APP_TITLE,
        menu=pystray.Menu(
            pystray.MenuItem("Open live dashboard…", _on_open_dashboard, default=True),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Run path test…", _on_run_path_test),
            pystray.MenuItem("Run path test + speedtest…", _on_run_path_and_speedtest),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Open last report", _on_open_last_report),
            pystray.MenuItem("View history…", _on_view_history),
            pystray.MenuItem("Open reports folder", _on_open_history_folder),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Quit", _on_quit),
        ),
    )
    icon.run()


if __name__ == "__main__":
    main()
