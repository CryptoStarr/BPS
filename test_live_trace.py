"""End-to-end smoke test using the system tracert fallback (we know
the raw TCP backend has a bug on Windows we want to investigate separately)."""
import sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from bps import tracer as tracer_mod
from bps.tracer import Tracer
from bps.geoip import enrich
from bps.analyzer import analyze
from bps.report import render_report
from bps import history

# Force the system tracert backend so we test that branch end-to-end.
Tracer._can_use_raw_icmp = staticmethod(lambda: False)

DEST = sys.argv[1] if len(sys.argv) > 1 else "google.com"

print(f"Tracing {DEST} (system tracert) ...")
t0 = time.time()
tr = Tracer(max_hops=20, probes_per_hop=3, timeout_s=2.0, port=443, passes=3)
trace = tr.trace_full(DEST)
print(f"  method={trace.method}  hops={len(trace.hops)}  took={time.time()-t0:.1f}s")

print("Enriching with rDNS + ASN ...")
enrich(trace.hops)

print("Analyzing ...")
analysis = analyze(trace)
print(f"  verdict: {analysis.overall.upper()} - {analysis.headline}")

ts = int(trace.started_at)
safe = "".join(c if c.isalnum() else "_" for c in DEST)[:40]
out = history.reports_dir() / f"{ts}_{safe}.html"
render_report(trace, analysis, None, out)
history.save_run(trace, analysis, None, out)
print(f"Report: {out}")

for h in trace.hops:
    rtt = f"{h.min_rtt:.0f}ms" if h.min_rtt is not None else "*"
    ecmp = ""
    if len(h.all_ips) > 1:
        ecmp = "  ECMP: " + ", ".join(h.all_ips)
    print(f"  hop {h.ttl:>2}  {h.ip or '*':<16} {rtt:>6}  loss={h.loss_pct:.0f}%  {h.asn_name or ''}{ecmp}")
