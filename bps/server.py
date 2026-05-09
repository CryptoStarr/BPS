"""Tiny localhost HTTP server that powers the live dashboard.

Why a local web server instead of a richer Tk window? The HTML/SVG pipeline
we already use for the report is the most polished part of BPS — reusing it
in the browser means the live view inherits every rendering improvement we
make to reports for free. It also gives us hover tooltips, smooth scaling,
and cross-platform consistency without picking up a heavy GUI dependency.

Endpoints
---------
GET  /                       Dashboard HTML (single page with embedded JS)
GET  /api/last               JSON of the latest completed trace + rendered SVG
POST /api/trace?host=foo.com Kick off a new trace in the background; returns immediately
GET  /api/status?host=...    Trace status for a destination ("idle"|"running"|"done"|"error")
GET  /api/history?host=...   Last N runs for a destination from ~/.bps/history/

Bound to 127.0.0.1 — never exposes the dashboard outside the machine.
"""

from __future__ import annotations

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from . import APP_LONG_NAME, APP_NAME, __version__, history
from .analyzer import analyze
from .geoip import asn_lookup, enrich, is_private
from .report import _render_hop_svg
from .tracer import Tracer, hop_deltas


# ---------- shared state ----------

# Map: host -> dict(status, started_at, finished_at, error, trace_dict, svg)
_state: dict[str, dict] = {}
_state_lock = threading.Lock()
_last_host: str | None = None


def _set_state(host: str, **kwargs) -> None:
    with _state_lock:
        cur = _state.setdefault(host, {})
        cur.update(kwargs)


def _get_state(host: str) -> dict:
    with _state_lock:
        return dict(_state.get(host, {}))


def _set_last_host(host: str) -> None:
    global _last_host
    with _state_lock:
        _last_host = host


def _get_last_host() -> str | None:
    with _state_lock:
        return _last_host


# ---------- the actual trace job ----------

def _update_live_hop(host: str, ttl: int, **fields) -> None:
    """Insert-or-update one entry in _state[host]['live_hops'] keyed by ttl,
    keeping the list sorted. Used both by the per-hop callback (initial
    discovery) and by the async enrichment thread (later AS enrichment)."""
    with _state_lock:
        cur = _state.setdefault(host, {})
        live = cur.setdefault("live_hops", [])
        for entry in live:
            if entry["ttl"] == ttl:
                entry.update({k: v for k, v in fields.items() if v is not None})
                return
        new = {"ttl": ttl}
        new.update({k: v for k, v in fields.items() if v is not None})
        live.append(new)
        live.sort(key=lambda h: h["ttl"])


def _async_enrich_ip(host: str, ttl: int, ip: str) -> None:
    """Look up rDNS + ASN for an IP and patch the matching live_hops entry."""
    if not ip:
        return
    if is_private(ip):
        _update_live_hop(host, ttl, asn_name="Local network")
        return
    asn, name = asn_lookup(ip)
    if asn or name:
        _update_live_hop(host, ttl, asn=asn, asn_name=name)


def _run_trace_job(host: str) -> None:
    """Execute a 3-pass trace + enrichment, then render the live SVG.

    Streams partial hop data into ``_state[host]['live_hops']`` as each TTL
    is discovered, so the dashboard can render an interactive log without
    waiting for all 3 passes to complete (~12-15 s).
    """
    _set_state(host, status="running", started_at=time.time(),
               error=None, trace=None, svg=None, analysis=None,
               live_hops=[])

    enrich_pool = ThreadPoolExecutor(max_workers=4)

    def on_hop(pass_idx: int, hop) -> None:
        # Per-hop streaming: surface IP / RTT / loss the moment a hop arrives,
        # then kick off an async AS lookup that backfills the same entry.
        rtt = round(hop.min_rtt, 1) if hop.min_rtt is not None else None
        _update_live_hop(
            host, hop.ttl,
            ip=hop.ip,
            min_rtt=rtt,
            loss_pct=round(hop.loss_pct, 1),
            all_ips=list(hop.all_ips or []) or None,
        )
        if hop.ip:
            enrich_pool.submit(_async_enrich_ip, host, hop.ttl, hop.ip)

    try:
        tracer = Tracer(max_hops=30, probes_per_hop=3, timeout_s=2.0,
                        port=443, passes=3)
        trace = tracer.trace_full(host, on_hop=on_hop)
        # Wait for inflight async enrichments before the canonical pass so
        # the live_hops list ends up consistent with the final trace.
        enrich_pool.shutdown(wait=True)
        enrich(trace.hops)
        analysis = analyze(trace)
        deltas = hop_deltas(trace.hops)
        svg = _render_hop_svg(trace, analysis, deltas)

        # Persist to disk so /api/history can find it later.
        try:
            history.save_run(trace, analysis, None, None)
        except Exception:
            pass

        _set_state(
            host,
            status="done",
            finished_at=time.time(),
            trace=trace.to_dict(),
            analysis={
                "overall": analysis.overall,
                "headline": analysis.headline,
                "summary": analysis.summary,
                "suspect_hop": analysis.suspect_hop,
                "suspect_owner": analysis.suspect_owner,
                "suspect_role": analysis.suspect_role,
            },
            svg=svg,
        )
        _set_last_host(host)
    except Exception as e:
        _set_state(host, status="error", finished_at=time.time(),
                   error=str(e))


# ---------- HTTP handler ----------

DASHBOARD_HTML_PATH = Path(__file__).parent / "dashboard.html"


def _dashboard_html() -> str:
    """Read the dashboard template from disk so designers can iterate on it
    without touching Python."""
    if DASHBOARD_HTML_PATH.exists():
        return DASHBOARD_HTML_PATH.read_text(encoding="utf-8")
    return "<h1>dashboard.html missing</h1>"


class _Handler(BaseHTTPRequestHandler):
    # Silence default access-log spam in the console.
    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        return

    def _send_json(self, code: int, payload: dict) -> None:
        body = json.dumps(payload, default=str).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, body: str) -> None:
        b = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(b)

    # GET / and /api/...
    def do_GET(self) -> None:  # noqa: N802 (BaseHTTPRequestHandler API)
        u = urlsplit(self.path)
        params = parse_qs(u.query)
        path = u.path

        if path in ("/", "/index.html"):
            self._send_html(_dashboard_html())
            return

        if path == "/api/info":
            self._send_json(200, {
                "name": APP_NAME,
                "long_name": APP_LONG_NAME,
                "version": __version__,
            })
            return

        if path == "/api/last":
            host = (params.get("host", [None])[0]) or _get_last_host()
            if not host:
                self._send_json(200, {"host": None, "status": "idle"})
                return
            self._send_json(200, {"host": host, **_get_state(host)})
            return

        if path == "/api/status":
            host = (params.get("host", [""])[0]).strip()
            self._send_json(200, {"host": host, **_get_state(host)})
            return

        if path == "/api/history":
            host = (params.get("host", [""])[0]).strip()
            limit = int((params.get("limit", ["50"])[0]) or 50)
            runs = [r for r in history.list_runs(limit=200)
                    if (not host or r["destination"] == host)][:limit]
            self._send_json(200, {"host": host, "runs": runs})
            return

        self.send_error(404, "not found")

    def do_POST(self) -> None:  # noqa: N802
        u = urlsplit(self.path)
        params = parse_qs(u.query)
        path = u.path

        if path == "/api/trace":
            host = (params.get("host", [""])[0]).strip()
            if not host:
                self._send_json(400, {"error": "host param required"})
                return

            with _state_lock:
                cur = _state.get(host, {})
                if cur.get("status") == "running":
                    self._send_json(200, {"host": host, "status": "running",
                                          "note": "already in progress"})
                    return

            threading.Thread(target=_run_trace_job, args=(host,),
                             daemon=True).start()
            _set_last_host(host)
            self._send_json(202, {"host": host, "status": "running"})
            return

        self.send_error(404, "not found")


# ---------- public entry point ----------

_server: ThreadingHTTPServer | None = None
_server_thread: threading.Thread | None = None


def start_server(port: int = 8765) -> int:
    """Start the dashboard server on 127.0.0.1:port (or the next free port).

    Returns the port that ended up bound. Idempotent — calling twice is a
    no-op and returns the original port.
    """
    global _server, _server_thread
    if _server is not None:
        return _server.server_address[1]

    last_err: Exception | None = None
    for candidate in range(port, port + 20):
        try:
            srv = ThreadingHTTPServer(("127.0.0.1", candidate), _Handler)
            _server = srv
            t = threading.Thread(target=srv.serve_forever, daemon=True,
                                 name="bps-server")
            t.start()
            _server_thread = t
            return candidate
        except OSError as e:
            last_err = e
    raise RuntimeError(f"Could not bind dashboard server: {last_err}")


def server_url() -> str:
    if _server is None:
        return ""
    host, port = _server.server_address[:2]
    return f"http://{host}:{port}/"
