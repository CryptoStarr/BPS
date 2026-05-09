"""
Renders a self-contained HTML report you can email to the ISP.

Design goals:
  - Single .html file - no external assets, no internet needed to view.
  - Print-friendly so it can be PDF'd.
  - The hop graph is inline SVG so it copy-pastes / prints cleanly.
  - One headline verdict at the top, then evidence below.
"""

from __future__ import annotations

import base64
import html
import json
from datetime import datetime
from pathlib import Path

from . import __version__ as APP_VERSION
from .analyzer import Analysis
from .tracer import TraceResult, hop_deltas
from .speedtest_runner import SpeedtestResult


_LOGO_PATH = Path(__file__).parent / "assets" / "logo.png"


def _logo_data_url() -> str | None:
    """Return the brand logo as a base64 data: URL, or None if not on disk.

    The HTML report is intentionally self-contained (one file, mailable, no
    external assets) — so when we want a logo we have to inline it.
    """
    if not _LOGO_PATH.exists():
        return None
    try:
        data = _LOGO_PATH.read_bytes()
        b64 = base64.b64encode(data).decode("ascii")
        return f"data:image/png;base64,{b64}"
    except OSError:
        return None


def render_report(
    trace: TraceResult,
    analysis: Analysis,
    speedtest: SpeedtestResult | None,
    out_path: Path,
) -> Path:
    """Write the HTML report and return its path."""
    html_str = _build_html(trace, analysis, speedtest)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html_str, encoding="utf-8")
    return out_path


def _build_html(trace: TraceResult, analysis: Analysis, st: SpeedtestResult | None) -> str:
    deltas = hop_deltas(trace.hops)
    svg = _render_hop_svg(trace, analysis, deltas)
    table = _render_hop_table(trace, analysis, deltas)
    speed_section = _render_speedtest(st) if st else ""
    timestamp = datetime.fromtimestamp(trace.started_at).strftime("%Y-%m-%d %H:%M:%S")

    overall_color = {"ok": "#2f9e44", "warn": "#f08c00", "bad": "#c92a2a"}[analysis.overall]
    overall_label = {"ok": "PATH OK", "warn": "DEGRADED", "bad": "BOTTLENECK FOUND"}[analysis.overall]

    logo_url = _logo_data_url()
    logo_html = (
        f'<img src="{logo_url}" alt="BPS" class="brand-logo"/>'
        if logo_url else ""
    )

    map_section = _render_geo_map_section(trace)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>BPS report — {html.escape(trace.destination)}</title>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"
      integrity="sha256-p4NxAoJBhIIN+hmNHrzRCf9tD/miZyoHS5obTRR9BMY=" crossorigin="" />
<script defer src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"
        integrity="sha256-20nQCchB9co0qIjJZRGuk2/Z9VM+kNiyxNV1lvTlZBo=" crossorigin=""></script>
<style>
  :root {{
    /* Match the live dashboard: dark slate frame, light card surfaces.
       The print-media block at the bottom flips the frame back to white
       so PDFs / printouts stay legible (and don't waste ink on big dark
       backgrounds when an ISP forwards the report internally). */
    --bg: #16202d;
    --header-bg: #0f1623;
    --surface: #ffffff;
    --ink: #1a1a1a;
    --on-dark: #e6e8eb;
    --on-dark-muted: #8b95a3;
    --muted: #6b6b6b;
    --line: #e8e6df;
    --line-on-dark: #2a3445;
    --ok: #2f9e44;
    --warn: #f08c00;
    --bad: #c92a2a;
    --accent: {overall_color};
  }}
  * {{ box-sizing: border-box; }}
  body {{
    font-family: 'Iowan Old Style', 'Palatino Linotype', Palatino, 'Hoefler Text', Georgia, serif;
    background: var(--bg);
    color: var(--on-dark);
    margin: 0;
    padding: 0;
    line-height: 1.55;
  }}
  .container {{
    max-width: 1100px;
    margin: 0 auto;
    padding: 48px 56px 80px;
  }}
  header {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 1px solid var(--line-on-dark);
    padding-bottom: 20px;
    margin-bottom: 32px;
    gap: 24px;
  }}
  header .brand {{
    display: flex;
    align-items: center;
    gap: 16px;
  }}
  header .brand-logo {{
    width: 56px;
    height: 56px;
    display: block;
  }}
  header h1 {{
    font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;
    font-weight: 800;
    font-size: 28px;
    letter-spacing: -0.02em;
    margin: 0;
    color: var(--on-dark);
  }}
  header h1 .muted-on-dark {{ color: var(--on-dark-muted); font-weight: 300; }}
  header .meta {{
    font-family: 'SF Mono', 'Monaco', 'Menlo', monospace;
    font-size: 11px;
    color: var(--on-dark-muted);
    text-align: right;
    letter-spacing: 0.04em;
  }}
  .verdict {{
    display: grid;
    grid-template-columns: auto 1fr;
    gap: 24px;
    align-items: center;
    padding: 24px 28px;
    background: white;
    border-left: 6px solid var(--accent);
    margin-bottom: 40px;
    box-shadow: 0 1px 0 var(--line);
  }}
  .verdict-tag {{
    font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;
    font-weight: 700;
    font-size: 11px;
    letter-spacing: 0.18em;
    color: var(--accent);
    white-space: nowrap;
  }}
  .verdict-headline {{
    font-size: 22px;
    font-weight: 600;
    margin: 0 0 6px;
  }}
  .verdict-summary {{
    font-size: 15px;
    color: var(--muted);
    margin: 0;
  }}
  section {{ margin-bottom: 48px; }}
  section h2 {{
    font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;
    font-size: 13px;
    font-weight: 700;
    letter-spacing: 0.15em;
    text-transform: uppercase;
    color: var(--on-dark-muted);
    border-bottom: 1px solid var(--line-on-dark);
    padding-bottom: 8px;
    margin: 0 0 20px;
  }}
  .path-svg-wrap {{
    overflow-x: auto;
    background: var(--surface);
    border: 1px solid var(--line);
    border-radius: 6px;
    padding: 20px;
  }}
  /* Hop table sits on its own white card so the rows read on the dark frame. */
  .table-card {{
    background: var(--surface);
    border: 1px solid var(--line);
    border-radius: 6px;
    padding: 8px 4px;
    color: var(--ink);
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
  }}
  thead th {{
    text-align: left;
    font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;
    font-weight: 700;
    font-size: 10px;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: var(--muted);
    padding: 10px 12px;
    border-bottom: 1px solid var(--line);
  }}
  tbody td {{
    padding: 10px 12px;
    border-bottom: 1px solid var(--line);
    vertical-align: top;
  }}
  tbody tr.bad td {{ background: rgba(201, 42, 42, 0.06); }}
  tbody tr.warn td {{ background: rgba(240, 140, 0, 0.06); }}
  tbody tr.suspect td {{
    box-shadow: inset 4px 0 0 var(--bad);
    font-weight: 600;
  }}
  .pill {{
    display: inline-block;
    font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.08em;
    padding: 2px 8px;
    border-radius: 999px;
    text-transform: uppercase;
  }}
  .pill.ok   {{ background: #e6f4ea; color: var(--ok); }}
  .pill.warn {{ background: #fef3e1; color: var(--warn); }}
  .pill.bad  {{ background: #fbe5e5; color: var(--bad); }}
  .mono {{
    font-family: 'SF Mono', 'Monaco', 'Menlo', monospace;
    font-size: 12px;
  }}
  .speedtest-grid {{
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 1px;
    background: var(--line);
    border: 1px solid var(--line);
  }}
  .speedtest-cell {{
    background: white;
    padding: 20px 24px;
  }}
  .speedtest-cell .label {{
    font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;
    font-size: 10px;
    letter-spacing: 0.15em;
    text-transform: uppercase;
    color: var(--muted);
    margin-bottom: 8px;
  }}
  .speedtest-cell .value {{
    font-size: 32px;
    font-weight: 600;
    letter-spacing: -0.02em;
  }}
  .speedtest-cell .unit {{
    font-size: 14px;
    color: var(--muted);
    font-weight: 400;
    margin-left: 4px;
  }}
  .callout {{
    background: #fffbe6;
    border: 1px solid #ffe58f;
    padding: 16px 20px;
    margin-top: 16px;
    font-size: 14px;
  }}
  footer {{
    margin-top: 64px;
    padding-top: 20px;
    border-top: 1px solid var(--line-on-dark);
    font-size: 11px;
    color: var(--on-dark-muted);
    text-align: center;
    font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;
  }}
  /* Geographic map */
  .map-card {{
    background: var(--surface);
    border: 1px solid var(--line);
    border-radius: 6px;
    overflow: hidden;
  }}
  #report-map {{ height: 380px; width: 100%; background: #eef2f4; }}
  .leaflet-container {{ font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; font-size: 12px; }}

  /* When the ISP prints or PDFs this report, flip the frame to white so
     dark backgrounds don't waste ink and the document stays legible on
     paper. Cards stay the same; only the page chrome changes. */
  @media print {{
    body {{ background: white; color: var(--ink); }}
    header h1, header h1 .muted-on-dark, header .meta,
    section h2, footer {{ color: var(--muted); }}
    header h1 {{ color: var(--ink); }}
    header {{ border-bottom-color: var(--ink); }}
    section h2, footer {{ border-color: var(--line); }}
    .container {{ padding: 24px; }}
    section {{ break-inside: avoid; }}
  }}
</style>
</head>
<body>
<div class="container">
  <header>
    <div class="brand">
      {logo_html}
      <h1>BPS <span class="muted-on-dark">/ BurikaPathScope · network path report</span></h1>
    </div>
    <div class="meta">
      DESTINATION  {html.escape(trace.destination)}<br>
      RESOLVED     {html.escape(trace.destination_ip)}:{trace.port}<br>
      RUN AT       {timestamp}<br>
      METHOD       {html.escape(trace.method)}
    </div>
  </header>

  <div class="verdict">
    <div class="verdict-tag">{overall_label}</div>
    <div>
      <p class="verdict-headline">{html.escape(analysis.headline)}</p>
      <p class="verdict-summary">{html.escape(analysis.summary)}</p>
    </div>
  </div>

  {speed_section}

  <section>
    <h2>Path visualization</h2>
    <div class="path-svg-wrap">{svg}</div>
  </section>

  <section>
    <h2>Hop-by-hop detail</h2>
    <div class="table-card">{table}</div>
  </section>

  {map_section}

  <footer>
    Generated by BPS v{APP_VERSION} — BurikaPathScope. The ICMP/TCP probes used to build
    this report follow the same forwarding path as real HTTPS traffic to the destination.
  </footer>
</div>
</body>
</html>
"""


def _render_speedtest(st: SpeedtestResult) -> str:
    if st.error:
        return f"""
  <section>
    <h2>Local ISP speedtest</h2>
    <p style="color:var(--muted)">Speedtest could not run: {html.escape(st.error)}</p>
  </section>"""

    return f"""
  <section>
    <h2>Local ISP speedtest <span style="text-transform:none; letter-spacing:0; font-weight:400; color:var(--muted)">— what your ISP sees</span></h2>
    <div class="speedtest-grid">
      <div class="speedtest-cell">
        <div class="label">Download</div>
        <div class="value">{st.download_mbps:.1f}<span class="unit">Mbps</span></div>
      </div>
      <div class="speedtest-cell">
        <div class="label">Upload</div>
        <div class="value">{st.upload_mbps:.1f}<span class="unit">Mbps</span></div>
      </div>
      <div class="speedtest-cell">
        <div class="label">Ping</div>
        <div class="value">{st.ping_ms:.0f}<span class="unit">ms</span></div>
      </div>
    </div>
    <div class="callout">
      Speedtest server: <strong>{html.escape(st.server_sponsor or "—")}</strong>
      in {html.escape(st.server_name or "—")}, {html.escape(st.server_country or "—")}.
      This server sits inside (or very close to) your ISP's network. A good number here
      proves the link from you to your ISP is healthy — but says nothing about the
      path to the actual destination above.
    </div>
  </section>"""


def _group_meta_json(group: dict) -> str:
    """JSON-encoded summary of a group's hops, attached to the SVG node so
    the live dashboard's tooltip can display per-hop and per-cluster data
    without a second round-trip to the server."""
    hops_meta = []
    for h in group["hops"]:
        hops_meta.append({
            "ttl": h.ttl,
            "ip": h.ip,
            "all_ips": list(h.all_ips or []),
            "hostname": h.hostname,
            "asn": h.asn,
            "asn_name": h.asn_name,
            "min_rtt": round(h.min_rtt, 1) if h.min_rtt is not None else None,
            "avg_rtt": round(h.avg_rtt, 1) if h.avg_rtt is not None else None,
            "max_rtt": round(h.max_rtt, 1) if h.max_rtt is not None else None,
            "loss_pct": round(h.loss_pct, 1),
        })
    return json.dumps({
        "label": group["label"] or "",
        "asn": group["asn"] or "",
        "severity": group["severity"],
        "is_cluster": len(group["hops"]) >= 2,
        "hops": hops_meta,
    }, separators=(",", ":"))


def _is_ecmp(hop) -> bool:
    """True if this hop saw 2+ distinct replier IPs (load-balanced)."""
    return len(getattr(hop, "all_ips", None) or []) >= 2


def _group_key(hop) -> str | None:
    """Hops collapse into a cluster when this key matches and is non-None.

    ECMP hops never collapse into a cluster — they are visually disruptive
    (rendered as diamonds) and the user will want to see them on their own.
    """
    if _is_ecmp(hop):
        return None
    if hop.asn:
        return f"asn:{hop.asn}"
    if hop.asn_name:
        return f"name:{hop.asn_name}"
    return None  # ungroupable


def _group_hops(hops, severity_by_ttl):
    """Walk hops in order and emit a list of groups.

    Each group is a dict: hops (list of Hop), severity (worst), label, asn.
    Single-hop groups render as either a numbered circle (1 IP) or a diamond
    (2+ IPs / ECMP). Multi-hop groups render as a cluster glyph.
    """
    groups = []
    current = None
    current_key = None
    for h in hops:
        key = _group_key(h)
        sev = severity_by_ttl.get(h.ttl, "ok")
        if key is not None and key == current_key and current is not None:
            current["hops"].append(h)
            order = {"ok": 0, "warn": 1, "bad": 2}
            if order[sev] > order[current["severity"]]:
                current["severity"] = sev
        else:
            current = {
                "hops": [h],
                "severity": sev,
                "label": h.asn_name or "",
                "asn": h.asn,
                "key": key,
            }
            groups.append(current)
            current_key = key
    return groups


def _render_hop_svg(trace: TraceResult, analysis: Analysis, deltas: list[float | None]) -> str:
    """
    NetPath-style horizontal path with AS-cluster glyphs.

    Single-AS hops render as numbered circles (so individual routers stay
    visible). Two or more consecutive hops in the same AS collapse into a
    cluster glyph: a ring containing three small overlapping circles, with the
    AS name + ASN + "(N)" count beneath it. The full per-hop detail is in the
    table below the SVG so nothing is actually hidden — the visual just
    summarises which network owns each stretch.
    """
    if not trace.hops:
        return "<p>No hops to display.</p>"

    severity_by_ttl = {v.ttl: v.severity for v in analysis.hop_verdicts}
    delta_by_ttl = {trace.hops[i].ttl: deltas[i] for i in range(len(trace.hops))}
    groups = _group_hops(trace.hops, severity_by_ttl)

    NODE_R = 16
    CLUSTER_R = 22
    H_PAD = 50
    V_CENTER = 95
    SPACING = 140
    n_items = len(groups) + 2  # +source +destination
    width = H_PAD * 2 + n_items * SPACING
    # Extra height so a 2-line wrapped AS name + ASN line fits without clipping.
    height = 260

    parts: list[str] = []
    parts.append(
        f'<svg viewBox="0 0 {width} {height}" '
        f'xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid meet" '
        f'style="display:block; width:100%; height:auto; '
        f'font-family:\'Helvetica Neue\',Helvetica,Arial,sans-serif;">'
    )

    src_x = H_PAD + SPACING // 2
    src_label = trace.source_name or "agent"
    src_sub = trace.source_ip or "source"
    parts.append(_node(src_x, V_CENTER, "ok", "▶", label=src_label, sub=src_sub))

    prev_x = src_x
    prev_r = NODE_R
    for gi, g in enumerate(groups):
        x = H_PAD + SPACING // 2 + (gi + 1) * SPACING
        sev = g["severity"]
        is_cluster = len(g["hops"]) >= 2

        # Sum of deltas across the group for the segment label
        group_delta = 0.0
        any_delta = False
        for h in g["hops"]:
            d = delta_by_ttl.get(h.ttl)
            if d is not None:
                group_delta += d
                any_delta = True

        line_color = "#cfd8dc" if sev == "ok" else ("#f08c00" if sev == "warn" else "#c92a2a")
        line_w = 2 if sev == "ok" else 4
        this_r = CLUSTER_R if is_cluster else NODE_R
        parts.append(
            f'<line x1="{prev_x + prev_r}" y1="{V_CENTER}" x2="{x - this_r}" y2="{V_CENTER}" '
            f'stroke="{line_color}" stroke-width="{line_w}"/>'
        )
        if any_delta:
            label = f"+{group_delta:.0f}ms" if group_delta >= 1 else "<1ms"
            mid = (prev_x + x) / 2
            parts.append(
                f'<text x="{mid}" y="{V_CENTER - 28}" text-anchor="middle" '
                f'font-size="11" fill="#6b6b6b">{label}</text>'
            )

        # Wrap each rendered group in a <g> with data-* attrs so the live
        # dashboard JS can show a hover tooltip with the same info we'd put
        # in the report's hop table.
        meta = _group_meta_json(g)
        parts.append(
            f'<g class="bps-hop" data-hop="{html.escape(meta, quote=True)}">'
        )

        if is_cluster:
            owner = g["label"] or "Unknown"
            asn = g["asn"] or ""
            parts.append(_cluster_node(x, V_CENTER, sev, len(g["hops"]),
                                       label=owner, sub=asn))
        elif _is_ecmp(g["hops"][0]):
            h = g["hops"][0]
            owner = h.asn_name or ""
            parts.append(_diamond_branch(
                center_x=x, center_y=V_CENTER, severity=sev, hop=h,
                in_x=prev_x + prev_r,
                out_x=x + NODE_R + 4,
                node_r=NODE_R,
            ))
            owner_text = owner or "ECMP"
            parts.append(
                f'<text x="{x}" y="{V_CENTER + 70}" text-anchor="middle" '
                f'font-size="11" font-weight="600" fill="#1a1a1a">'
                f'{html.escape(owner_text[:24])}</text>'
            )
            if h.asn:
                parts.append(
                    f'<text x="{x}" y="{V_CENTER + 84}" text-anchor="middle" '
                    f'font-size="10" fill="#6b6b6b">'
                    f'{html.escape(h.asn)} (TTL {h.ttl})</text>'
                )
        else:
            h = g["hops"][0]
            ip_label = h.ip or "*"
            owner = h.asn_name or ""
            parts.append(_node(x, V_CENTER, sev, str(h.ttl),
                               label=ip_label, sub=owner))

        parts.append("</g>")

        prev_x = x
        prev_r = this_r

    dst_x = H_PAD + SPACING // 2 + (len(groups) + 1) * SPACING
    parts.append(
        f'<line x1="{prev_x + prev_r}" y1="{V_CENTER}" x2="{dst_x - NODE_R}" y2="{V_CENTER}" '
        f'stroke="#cfd8dc" stroke-width="2"/>'
    )
    parts.append(
        _node(dst_x, V_CENTER, "ok", "■",
              label=trace.destination, sub=trace.destination_ip)
    )

    parts.append("</svg>")
    return "".join(parts)


def _render_geo_map_section(trace: TraceResult) -> str:
    """Build the geographic-path map section.

    Returns HTML containing a Leaflet map seeded with one marker per hop
    that has lat/lon. If no hop has geo data, returns "" so we don't render
    an empty card. The map fits all markers on load and falls back gracefully
    when the report is opened offline (the empty tile area still looks fine
    against the card background).
    """
    points = []
    for h in trace.hops:
        g = getattr(h, "geo", None) or None
        if not g:
            continue
        lat, lon = g.get("lat"), g.get("lon")
        if not isinstance(lat, (int, float)) or not isinstance(lon, (int, float)):
            continue
        points.append({
            "ttl": h.ttl,
            "ip": h.ip or "",
            "city": g.get("city") or "",
            "country": g.get("country") or "",
            "asn_name": h.asn_name or "",
            "min_rtt": h.min_rtt,
            "loss_pct": round(h.loss_pct, 1),
            "lat": lat, "lon": lon,
        })
    if not points:
        return ""
    payload = json.dumps(points, separators=(",", ":"))
    return f"""
  <section>
    <h2>Geographic path</h2>
    <div class="map-card">
      <div id="report-map"></div>
    </div>
    <script>
      (function() {{
        const points = {payload};
        function mkMap() {{
          if (typeof L === 'undefined') {{ setTimeout(mkMap, 100); return; }}
          const map = L.map('report-map', {{ scrollWheelZoom: false }}).setView([0,0], 2);
          L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png', {{
            maxZoom: 18,
            attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>',
          }}).addTo(map);
          const ll = points.map(p => [p.lat, p.lon]);
          points.forEach(p => {{
            const sev = p.loss_pct >= 15 ? 'bad'
                      : (p.loss_pct >= 1 || (p.min_rtt != null && p.min_rtt >= 150)) ? 'warn'
                      : 'ok';
            const color = sev === 'bad' ? '#c92a2a' : sev === 'warn' ? '#f08c00' : '#2f9e44';
            const m = L.circleMarker([p.lat, p.lon], {{
              radius: 7, weight: 2, color: color,
              fillColor: 'white', fillOpacity: 1,
            }}).addTo(map);
            const where = [p.city, p.country].filter(Boolean).join(', ');
            m.bindTooltip(
              '<strong>Hop ' + p.ttl + ': ' + (p.ip || '—') + '</strong><br>' +
              (p.asn_name ? p.asn_name + '<br>' : '') +
              (where ? where + '<br>' : '') +
              (p.min_rtt != null ? p.min_rtt + ' ms' : '') +
              (p.loss_pct > 0 ? ' · loss ' + p.loss_pct + '%' : ''),
              {{ direction: 'top', offset: [0, -6] }}
            );
          }});
          if (ll.length >= 2) {{
            L.polyline(ll, {{ color: '#1a1a1a', weight: 2, opacity: 0.55, dashArray: '5, 6' }}).addTo(map);
          }}
          map.fitBounds(L.latLngBounds(ll).pad(0.2), {{ animate: false }});
        }}
        mkMap();
      }})();
    </script>
  </section>"""


def _wrap_label(label: str, max_chars: int = 18, max_lines: int = 2) -> list[str]:
    """Word-wrap ``label`` into at most ``max_lines`` lines of ~``max_chars``
    characters each. The last line is hard-truncated with an ellipsis if the
    text overflows. Designed for SVG text where there's no native word-wrap."""
    label = label.strip()
    if not label:
        return [""]
    if len(label) <= max_chars:
        return [label]

    words = label.split()
    lines: list[str] = []
    current = ""
    for w in words:
        if not current:
            current = w
        elif len(current) + 1 + len(w) <= max_chars:
            current = f"{current} {w}"
        else:
            lines.append(current)
            current = w
            if len(lines) == max_lines - 1:
                # Last line: keep current + remaining as a single block,
                # truncate if it overflows.
                idx = words.index(w)
                rest = " ".join([current] + words[idx + 1:])
                if len(rest) > max_chars:
                    rest = rest[: max_chars - 1].rstrip() + "…"
                lines.append(rest)
                return lines
    if current:
        lines.append(current)
    return lines


def _cluster_node(cx: int, cy: int, severity: str, count: int,
                  label: str = "", sub: str = "") -> str:
    """NetPath-style AS cluster glyph.

    A ring (sized larger than a single hop) containing three small overlapping
    filled circles. Below the ring: the AS name (word-wrapped to up to 2
    lines), then the ASN in muted text with the count badge "(N)" appended.
    """
    fill_map = {"ok": "#ffffff", "warn": "#fff4e0", "bad": "#fdecec"}
    stroke_map = {"ok": "#7d8a8d", "warn": "#f08c00", "bad": "#c92a2a"}
    inner_map = {"ok": "#7d8a8d", "warn": "#f08c00", "bad": "#c92a2a"}
    sw = 2 if severity == "ok" else 3
    inner_fill = inner_map[severity]

    inner_r = 4.5
    offset = 4.5

    # Wrap the bold AS name. ASN line lives below whatever wrapped block we
    # produce, so the spacing stays consistent regardless of label length.
    label_lines = _wrap_label(label, max_chars=18, max_lines=2)
    LINE_HEIGHT = 14
    LABEL_TOP = cy + 40
    name_block = []
    for i, line in enumerate(label_lines):
        y = LABEL_TOP + i * LINE_HEIGHT
        name_block.append(
            f'<text x="{cx}" y="{y}" text-anchor="middle" font-size="12" '
            f'font-weight="700" fill="#1a1a1a">{html.escape(line)}</text>'
        )
    sub_y = LABEL_TOP + len(label_lines) * LINE_HEIGHT + 2

    return (
        # Outer ring
        f'<circle cx="{cx}" cy="{cy}" r="22" fill="{fill_map[severity]}" '
        f'stroke="{stroke_map[severity]}" stroke-width="{sw}"/>'
        # Three-dot cluster glyph
        f'<circle cx="{cx - offset}" cy="{cy - 2}" r="{inner_r}" fill="{inner_fill}"/>'
        f'<circle cx="{cx + offset}" cy="{cy - 2}" r="{inner_r}" fill="{inner_fill}"/>'
        f'<circle cx="{cx}" cy="{cy + offset + 1}" r="{inner_r}" fill="{inner_fill}"/>'
        # AS name (wrapped)
        + "".join(name_block) +
        # ASN + count badge
        f'<text x="{cx}" y="{sub_y}" text-anchor="middle" font-size="11" '
        f'fill="#6b6b6b">{html.escape(sub)} ({count})</text>'
    )


def _diamond_branch(center_x: int, center_y: int, severity: str, hop,
                    in_x: int, out_x: int, node_r: int) -> str:
    """Render an ECMP diamond: parallel circles fanned vertically.

    Lines splay from the previous-node anchor (``in_x``) into each parallel
    replier, then converge to ``out_x``. Each parallel circle gets its IP
    underneath. The shape replaces the single circle that would otherwise
    sit at (center_x, center_y).
    """
    ips = list(hop.all_ips or ([hop.ip] if hop.ip else []))
    if not ips:
        return ""

    fill_map = {"ok": "#ffffff", "warn": "#fff4e0", "bad": "#fdecec"}
    stroke_map = {"ok": "#7d8a8d", "warn": "#f08c00", "bad": "#c92a2a"}
    line_color = "#cfd8dc" if severity == "ok" else stroke_map[severity]
    line_w = 2 if severity == "ok" else 3
    sw = 2 if severity == "ok" else 3
    small_r = 11

    # Vertical layout for the parallel branches
    n = len(ips)
    spread = 28  # px between branches
    # Branches centered around center_y
    ys = [center_y + (i - (n - 1) / 2) * spread for i in range(n)]

    parts: list[str] = []
    # Splayed lines IN
    for y in ys:
        parts.append(
            f'<line x1="{in_x}" y1="{center_y}" x2="{center_x - small_r}" y2="{y}" '
            f'stroke="{line_color}" stroke-width="{line_w}"/>'
        )
    # Splayed lines OUT
    for y in ys:
        parts.append(
            f'<line x1="{center_x + small_r}" y1="{y}" x2="{out_x}" y2="{center_y}" '
            f'stroke="{line_color}" stroke-width="{line_w}"/>'
        )
    # Parallel circles + IP labels
    for ip, y in zip(ips, ys):
        parts.append(
            f'<circle cx="{center_x}" cy="{y}" r="{small_r}" '
            f'fill="{fill_map[severity]}" stroke="{stroke_map[severity]}" '
            f'stroke-width="{sw}"/>'
        )
        parts.append(
            f'<text x="{center_x}" y="{y + 3}" text-anchor="middle" font-size="9" '
            f'font-weight="600" fill="#1a1a1a">{html.escape(str(hop.ttl))}</text>'
        )
        # IP to the side of the circle (right-of for top half, left for bottom
        # would crowd the labels) — simplest: stack each IP underneath its
        # circle, on the right
        parts.append(
            f'<text x="{center_x + small_r + 4}" y="{y + 3}" text-anchor="start" '
            f'font-size="9" font-family="SF Mono,Monaco,Menlo,monospace" '
            f'fill="#1a1a1a">{html.escape(ip[:18])}</text>'
        )
    return "".join(parts)


def _node(cx: int, cy: int, severity: str, inner: str, label: str = "", sub: str = "") -> str:
    fill_map = {"ok": "#ffffff", "warn": "#fff4e0", "bad": "#fdecec"}
    stroke_map = {"ok": "#9aa5a8", "warn": "#f08c00", "bad": "#c92a2a"}
    sw = 2 if severity == "ok" else 3

    # Word-wrap the sub line so e.g. "NTT DATA, Broadband, South Africa"
    # doesn't bleed into the next node.
    sub_lines = _wrap_label(sub, max_chars=20, max_lines=2) if sub else [""]

    parts = [
        f'<circle cx="{cx}" cy="{cy}" r="14" fill="{fill_map[severity]}" '
        f'stroke="{stroke_map[severity]}" stroke-width="{sw}"/>',
        f'<text x="{cx}" y="{cy + 4}" text-anchor="middle" font-size="10" '
        f'font-weight="600" fill="#1a1a1a">{html.escape(str(inner))}</text>',
        f'<text x="{cx}" y="{cy + 36}" text-anchor="middle" font-size="10" '
        f'font-family="SF Mono,Monaco,Menlo,monospace" fill="#1a1a1a">'
        f'{html.escape(label[:24])}</text>',
    ]
    base_y = cy + 50
    for i, line in enumerate(sub_lines):
        parts.append(
            f'<text x="{cx}" y="{base_y + i * 12}" text-anchor="middle" '
            f'font-size="9" fill="#6b6b6b">{html.escape(line)}</text>'
        )
    return "".join(parts)


def _render_hop_table(trace: TraceResult, analysis: Analysis, deltas: list[float | None]) -> str:
    rows: list[str] = []
    severity_by_ttl = {v.ttl: v for v in analysis.hop_verdicts}

    rows.append("""<thead><tr>
        <th>Hop</th>
        <th>IP</th>
        <th>Hostname</th>
        <th>Network (AS)</th>
        <th>Min</th>
        <th>Avg</th>
        <th>Max</th>
        <th>+&Delta;</th>
        <th>Loss</th>
        <th>Status</th>
      </tr></thead>""")

    rows.append("<tbody>")
    for i, hop in enumerate(trace.hops):
        v = severity_by_ttl.get(hop.ttl)
        sev = v.severity if v else "ok"
        is_suspect = analysis.suspect_hop == hop.ttl
        cls = sev + (" suspect" if is_suspect else "")

        rows.append(f'<tr class="{cls}">')
        rows.append(f'<td class="mono">{hop.ttl}</td>')
        rows.append(f'<td class="mono">{html.escape(hop.ip or "*")}</td>')
        rows.append(f'<td class="mono" style="color:var(--muted)">{html.escape(hop.hostname or "—")}</td>')
        net = ""
        if hop.asn_name:
            net = hop.asn_name
            if hop.asn:
                net += f" ({hop.asn})"
        rows.append(f"<td>{html.escape(net or '—')}</td>")
        rows.append(f"<td class='mono'>{_fmt_ms(hop.min_rtt)}</td>")
        rows.append(f"<td class='mono'>{_fmt_ms(hop.avg_rtt)}</td>")
        rows.append(f"<td class='mono'>{_fmt_ms(hop.max_rtt)}</td>")
        rows.append(f"<td class='mono'>{_fmt_ms(deltas[i])}</td>")
        rows.append(f"<td class='mono'>{hop.loss_pct:.0f}%</td>")
        pill_label = {"ok": "ok", "warn": "warn", "bad": "bad"}[sev]
        rows.append(f'<td><span class="pill {sev}">{pill_label}</span>')
        if v and v.reason:
            rows.append(f'<div style="font-size:11px; color:var(--muted); margin-top:4px;">{html.escape(v.reason)}</div>')
        rows.append("</td></tr>")

    rows.append("</tbody>")

    return f'<table>{"".join(rows)}</table>'


def _fmt_ms(x: float | None) -> str:
    if x is None:
        return "—"
    return f"{x:.1f}"
