# BPS — BurikaPathScope

A system tray agent that proves to ISPs where the real bottleneck is when a
client visits a specific website.

## The problem this solves

Your client says "the internet is slow when I visit X". The ISP runs a speedtest
to *their own server* and reports "100/100 Mbps, perfect". Both can be true at
the same time — the bottleneck is somewhere between the ISP edge and the
destination (a peering point, a transit provider, an upstream of the
destination).

BPS captures all three signals in one report:

1. **Local speedtest** — what the ISP measures, to one of their nearby servers.
2. **Path trace to the actual destination** — TCP-based hop-by-hop trace on the
   real port (443 by default), with per-hop latency, loss and the AS / owner of
   each hop. Multiple passes are merged so ECMP load-balancing shows up as
   parallel branches in the report.
3. **Verdict** — automatically identifies where in the path the latency or loss
   spikes, and labels the responsible party (your LAN / your ISP / a transit
   provider / the destination's host).

The output is a self-contained, branded HTML report you can email to the ISP
as evidence.

## Why TCP traceroute, not ICMP

Most home routers and ISP edge devices deprioritize or rate-limit ICMP, which
makes classic `traceroute` produce misleadingly bad numbers (or missing hops).
TCP SYN probes on the destination's actual service port (443/80) follow the
forwarding path the real HTTPS traffic takes and are not deprioritized. It also
means **BPS does not require admin/root** on most platforms — when raw sockets
aren't available BPS falls back to the system `tracert` / `traceroute` binary
and parses its output, so it Just Works for end users.

## Install

```bash
pip install -r requirements.txt
python -m bps
```

A tray icon appears (the BurikaPathScope logo). Right-click for the menu:

- **Run path test…** — prompts for a hostname (e.g. `eu320e.odoo.com`), traces
  the path 3 times for ECMP detection, shows the live result.
- **Run path test + speedtest…** — runs a local speedtest *and* the path test
  in parallel, then renders both side-by-side in the report.
- **Open last report** — opens the most recent HTML report in the browser.
- **View history…** — past tests with timestamps and verdicts.
- **Open reports folder** — `~/.bps/reports/`.
- **Quit**.

## Layout

```
bps/
├── __main__.py          # Entry point — starts the tray
├── tray.py              # Tray icon + menu (pystray)
├── tracer.py            # TCP/ICMP hop-by-hop tracer (multi-pass + ECMP merge)
├── speedtest_runner.py  # Local speedtest wrapper
├── geoip.py             # rDNS + AS lookup for hops (Team Cymru)
├── analyzer.py          # Decides where the bottleneck is
├── report.py            # Renders the self-contained HTML report
├── history.py           # Stores past tests (~/.bps/history/)
├── ui.py                # Small dialog windows (Tk)
└── assets/
    └── logo.png         # Brand logo (used in tray + report header)
```

## How the analyzer decides

Per-hop deltas are computed using **min RTT** (the propagation+serialisation
floor — robust against single-probe spikes). A hop is flagged if:

- Its delta exceeds 50 ms AND is more than 3× the median delta of the path, OR
- Packet loss at that hop exceeds 5% AND persists at later hops (a single
  100% loss hop with healthy hops afterwards is treated as an
  ICMP-rate-limited router, not a bottleneck).

The first such hop is the prime suspect. We then map its IP to an AS via the
Team Cymru DNS WHOIS service (queried over public resolvers — works on
networks where the local DNS doesn't), and label the suspect as your
LAN / your ISP / a transit provider / the destination network.
