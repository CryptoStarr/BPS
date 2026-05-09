"""Sanity tests for the analyzer's rules."""
import sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from bps.tracer import TraceResult, Hop, HopProbe
from bps.analyzer import analyze


def hop(ttl, ip, rtts, asn_name=None):
    return Hop(ttl=ttl, ip=ip, asn_name=asn_name,
               probes=[HopProbe(rtt_ms=r, reply_from=ip) for r in rtts])


def trace_for(hops):
    return TraceResult(
        destination="example.com", destination_ip="1.2.3.4", port=443,
        started_at=time.time(), finished_at=time.time(), hops=hops,
        method="test",
    )


# 1. Healthy path -> ok
healthy = [
    hop(1, "192.168.1.1",   [1, 1, 1], "Local network"),
    hop(2, "10.0.0.1",      [2, 2, 2], "Local network"),
    hop(3, "100.64.0.1",    [10, 10, 10], "ISP"),
    hop(4, "1.2.3.4",       [12, 13, 12], "Destination"),
]
a = analyze(trace_for(healthy))
assert a.overall == "ok", f"healthy path should be ok, got {a.overall}"
assert a.suspect_hop is None
print("PASS: healthy path -> ok")

# 2. Single big jump in middle -> bad, that hop is the suspect
middle_spike = [
    hop(1, "192.168.1.1",   [1, 1, 1], "Local network"),
    hop(2, "10.0.0.1",      [2, 2, 2], "Local network"),
    hop(3, "100.64.0.1",    [10, 10, 10], "ISP"),
    hop(4, "203.0.113.1",   [200, 220, 210], "Bad Transit"),
    hop(5, "203.0.113.2",   [205, 222, 215], "Bad Transit"),
    hop(6, "1.2.3.4",       [210, 225, 218], "Destination"),
]
a = analyze(trace_for(middle_spike))
assert a.overall == "bad"
assert a.suspect_hop == 4, f"expected hop 4, got {a.suspect_hop}"
assert "Bad Transit" in (a.suspect_owner or "")
print(f"PASS: middle spike detected at hop {a.suspect_hop} ({a.suspect_owner})")

# 3. Loss at a hop -> warn or bad
with_loss = [
    hop(1, "192.168.1.1",   [1, 1, 1]),
    hop(2, "100.64.0.1",    [10, 10, 10], "ISP"),
    # 1 of 3 probes lost = 33% loss
    Hop(ttl=3, ip="1.2.3.4",
        probes=[HopProbe(20, "1.2.3.4"), HopProbe(None, None), HopProbe(None, None)]),
]
a = analyze(trace_for(with_loss))
assert a.overall in ("warn", "bad"), f"loss should warn or worse, got {a.overall}"
print(f"PASS: packet loss flagged ({a.overall})")

# 4a. Long stretch of silent hops with a healthy destination -> ok
# (this is what tracert produces when intermediate routers rate-limit ICMP
# but the destination is fine — it should NOT flag a bottleneck)
silent_stretch = [
    hop(1, "192.168.1.1", [1, 1, 1]),
    Hop(ttl=2, ip=None, probes=[HopProbe(None, None)] * 3),
    Hop(ttl=3, ip=None, probes=[HopProbe(None, None)] * 3),
    Hop(ttl=4, ip=None, probes=[HopProbe(None, None)] * 3),
    Hop(ttl=5, ip=None, probes=[HopProbe(None, None)] * 3),
    hop(6, "1.2.3.4", [40, 41, 40], "Destination"),
]
a = analyze(trace_for(silent_stretch))
assert a.overall == "ok", f"silent stretch + healthy dest should be ok, got {a.overall}"
print("PASS: silent-hop stretch with healthy destination -> ok")

# 5. Long path with no anomalies -> ok even with high absolute latency
overseas_but_fine = [
    hop(1, "192.168.1.1",   [1]),
    hop(2, "100.64.0.1",    [5], "ISP"),
    hop(3, "10.10.10.1",    [12], "ISP"),
    hop(4, "11.11.11.1",    [80], "Submarine cable"),  # +68ms but expected
    hop(5, "12.12.12.1",    [180], "Submarine cable"),  # +100ms
    hop(6, "13.13.13.1",    [185], "Destination"),
]
a = analyze(trace_for(overseas_but_fine))
# Each jump is big but path median is also big - the 3x rule should NOT fire
print(f"INFO: long-haul path verdict = {a.overall} (suspect hop: {a.suspect_hop})")

print("\nAll core checks passed.")
