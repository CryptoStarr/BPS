"""
Demo that produces a realistic-looking BPS report using the data
from the user's NetPath screenshots (Cape Town -> eu320e.odoo.com via
Angola Cables transit). Run this to verify the report renderer.
"""

import sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from bps.tracer import TraceResult, Hop, HopProbe
from bps.analyzer import analyze
from bps.speedtest_runner import SpeedtestResult
from bps.report import render_report


def make_hop(ttl, ip, hostname=None, asn=None, asn_name=None, rtts=(1, 1, 1)):
    return Hop(
        ttl=ttl, ip=ip, hostname=hostname, asn=asn, asn_name=asn_name,
        probes=[HopProbe(rtt_ms=r, reply_from=ip) for r in rtts],
    )


# Reconstruct the path from your first screenshot:
# 02-us-up.sirkel-n.co.za (192.168.0.98) -> ... -> Angola Cables AS37468
# -> 102.130.68.67 (BAD: red node) -> 197.149.151.110 (latency spike)
# -> OVH SAS AS16276 -> eu320e.odoo.com 57.128.117.70
hops = [
    make_hop(1, "192.168.0.98",   asn_name="Local network", rtts=(2, 2, 2)),
    make_hop(2, "192.168.0.254",  asn_name="Local network", rtts=(2, 3, 2)),
    make_hop(3, "10.0.0.5",       asn_name="Local network", rtts=(3, 3, 4)),
    make_hop(4, "172.16.0.254",   asn_name="Local network", rtts=(4, 5, 4)),
    make_hop(5, "102.164.0.29",   asn="AS37105", asn_name="Sirkel ISP", rtts=(5, 5, 5)),
    # ECMP at hop 6: two parallel transit routers in Sirkel ISP
    make_hop(6, "100.124.1.2",    asn="AS37105", asn_name="Sirkel ISP", rtts=(6, 6, 7)),
    make_hop(7, "100.126.101.254", asn="AS37105", asn_name="Sirkel ISP", rtts=(7, 8, 7)),
    make_hop(8, "100.64.192.152", asn="AS37468", asn_name="Angola Cables", rtts=(9, 9, 10)),
    make_hop(9, "102.130.68.67",  asn="AS37468", asn_name="Angola Cables", rtts=(11, 12, 11)),
    make_hop(10, "197.149.151.110", asn="AS37468", asn_name="Angola Cables",
             rtts=(161, 168, 203)),
    # ECMP at hop 11: OVH backbone load-balanced across two routers
    make_hop(11, "51.255.0.1",    asn="AS16276", asn_name="OVH SAS", rtts=(165, 165, 166)),
    make_hop(12, "51.255.0.2",    asn="AS16276", asn_name="OVH SAS", rtts=(232, 244, 261)),
    make_hop(13, "57.128.117.70", hostname="eu320e.odoo.com",
             asn="AS16276", asn_name="OVH SAS", rtts=(243, 244, 245)),
]
# Inject simulated ECMP at hop 6 and hop 11 (multiple replier IPs same TTL)
hops[5].all_ips = ["100.124.1.2", "100.124.3.2"]
hops[10].all_ips = ["51.255.0.1", "51.255.4.7"]

trace = TraceResult(
    destination="eu320e.odoo.com",
    destination_ip="57.128.117.70",
    port=443,
    started_at=time.time() - 30,
    finished_at=time.time(),
    hops=hops,
    method="tcp_raw",
)

speedtest = SpeedtestResult(
    download_mbps=104.7, upload_mbps=42.3, ping_ms=8,
    server_name="Cape Town", server_country="South Africa",
    server_sponsor="Sirkel ISP",
    started_at=trace.started_at, finished_at=trace.finished_at,
)

analysis = analyze(trace)

print("Verdict:", analysis.overall)
print("Headline:", analysis.headline)
print("Suspect hop:", analysis.suspect_hop)
print("Suspect role:", analysis.suspect_role)
print("Suspect owner:", analysis.suspect_owner)
print()

out = Path(__file__).parent / "sample_report.html"
render_report(trace, analysis, speedtest, out)
print(f"Report written to {out}")
