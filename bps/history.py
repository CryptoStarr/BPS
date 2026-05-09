"""
Lightweight history store. JSON files in ~/.bps/history/.

Reports continue to be written here even when the user invokes a one-shot
trace from the tray, so a "last report" link always works without
remembering filesystem state across runs.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, is_dataclass
from pathlib import Path

from .tracer import TraceResult
from .analyzer import Analysis
from .speedtest_runner import SpeedtestResult


def _data_dir() -> Path:
    d = Path.home() / ".bps"
    # Migrate from the legacy ~/.pathscope/ directory if it exists and the
    # new one does not. Cheap one-time move; no harm if the user manually
    # relocates afterwards.
    legacy = Path.home() / ".pathscope"
    if legacy.exists() and not d.exists():
        try:
            legacy.rename(d)
        except OSError:
            d.mkdir(parents=True, exist_ok=True)
    d.mkdir(parents=True, exist_ok=True)
    (d / "history").mkdir(exist_ok=True)
    (d / "reports").mkdir(exist_ok=True)
    return d


def history_dir() -> Path:
    return _data_dir() / "history"


def reports_dir() -> Path:
    return _data_dir() / "reports"


def _serialize(o):
    if is_dataclass(o):
        return asdict(o)
    if isinstance(o, (list, tuple)):
        return [_serialize(x) for x in o]
    if isinstance(o, dict):
        return {k: _serialize(v) for k, v in o.items()}
    return o


def save_run(
    trace: TraceResult,
    analysis: Analysis,
    speedtest: SpeedtestResult | None,
    report_path: Path | None,
) -> Path:
    ts = int(trace.started_at)
    safe_dest = "".join(c if c.isalnum() else "_" for c in trace.destination)[:40]
    fname = f"{ts}_{safe_dest}.json"
    path = history_dir() / fname
    payload = {
        "trace": trace.to_dict(),
        "analysis": _serialize(analysis),
        "speedtest": speedtest.to_dict() if speedtest else None,
        "report_path": str(report_path) if report_path else None,
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def list_runs(limit: int = 50) -> list[dict]:
    files = sorted(history_dir().glob("*.json"), reverse=True)[:limit]
    out = []
    for f in files:
        try:
            d = json.loads(f.read_text())
            out.append({
                "file": str(f),
                "destination": d["trace"]["destination"],
                "started_at": d["trace"]["started_at"],
                "verdict": d["analysis"]["overall"],
                "headline": d["analysis"]["headline"],
                "report_path": d.get("report_path"),
            })
        except Exception:
            continue
    return out
