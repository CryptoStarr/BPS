"""
The bottleneck analyzer.

Given a TraceResult, decide:
  - Is there a bottleneck at all?
  - Which hop is the culprit?
  - Whose responsibility is it (LAN / ISP / transit / destination)?

Rules (kept simple and explainable so you can defend them to an ISP):

  Loss rule:    a hop with >=5% loss that persists at later hops is bad.
  Latency rule: the per-hop delta is "bad" when it is BOTH
                  - greater than 50ms absolute, AND
                  - greater than 3x the median delta of the path.
                The first such hop is the prime suspect.

We deliberately use the MIN rtt for delta math (not avg) because min-RTT
is the propagation+serialisation floor; spikes above it are queueing or
congestion. Using min reduces false positives from one bad probe.
"""

from __future__ import annotations

from dataclasses import dataclass
from .tracer import Hop, TraceResult, hop_deltas, median_nonnull
from .geoip import is_private


# Tunable thresholds
LOSS_THRESHOLD_PCT = 5.0
DELTA_ABS_MS = 50.0
DELTA_REL_FACTOR = 3.0


@dataclass
class HopVerdict:
    ttl: int
    delta_ms: float | None
    loss_pct: float
    severity: str  # "ok" | "warn" | "bad"
    reason: str


@dataclass
class Analysis:
    overall: str  # "ok" | "warn" | "bad"
    headline: str
    suspect_hop: int | None
    suspect_owner: str | None  # e.g. "Angola Cables (AS37468)"
    suspect_role: str | None  # "Local network" | "Your ISP" | "Transit provider" | "Destination network"
    summary: str
    hop_verdicts: list[HopVerdict]


def _classify_role(hop_index: int, total_hops: int, hop: Hop) -> str:
    if hop.ip and is_private(hop.ip):
        return "Local network"
    if hop_index <= 1:
        # First public hop is almost always the ISP edge
        return "Your ISP"
    if hop_index >= total_hops - 2:
        return "Destination network"
    return "Transit provider"


def analyze(result: TraceResult) -> Analysis:
    hops = result.hops
    if not hops:
        return Analysis(
            overall="bad",
            headline="No hops returned.",
            suspect_hop=None,
            suspect_owner=None,
            suspect_role=None,
            summary="The trace returned zero hops. Check connectivity and try again.",
            hop_verdicts=[],
        )

    deltas = hop_deltas(hops)
    med = median_nonnull(deltas)
    threshold_rel = max(DELTA_ABS_MS, med * DELTA_REL_FACTOR)

    # A hop's loss only matters as evidence of a real path problem if it
    # continues all the way to the destination. ICMP-rate-limited routers
    # are extremely common on the public internet — they appear as 100%-loss
    # hops on traceroute even when the path itself is healthy. If the
    # *destination* responded, all earlier silent hops are a measurement
    # artefact, not a real bottleneck.
    final_hop_responded = hops[-1].loss_pct < LOSS_THRESHOLD_PCT

    def loss_persists_downstream(idx: int) -> bool:
        if final_hop_responded:
            return False
        # Destination didn't reply: treat loss as real only if it continues
        # uninterrupted to the end of the visible path.
        downstream = hops[idx + 1 :]
        if not downstream:
            return True
        return all(h.loss_pct >= LOSS_THRESHOLD_PCT for h in downstream)

    verdicts: list[HopVerdict] = []
    suspect_idx: int | None = None

    for i, hop in enumerate(hops):
        delta = deltas[i]
        loss = hop.loss_pct
        severity = "ok"
        reason = ""

        if loss >= LOSS_THRESHOLD_PCT and loss_persists_downstream(i):
            severity = "bad" if loss >= 20 else "warn"
            reason = f"{loss:.0f}% packet loss at this hop"
        elif loss >= LOSS_THRESHOLD_PCT:
            # Silent hop (likely ICMP-rate-limited router) — note it but don't blame it.
            severity = "ok"
            reason = "no reply (likely rate-limited router; downstream is healthy)"
        elif delta is not None and delta >= DELTA_ABS_MS and delta >= threshold_rel:
            severity = "bad"
            reason = (
                f"+{delta:.0f}ms jump at this hop "
                f"(median jump on this path is {med:.0f}ms)"
            )
        elif delta is not None and delta >= DELTA_ABS_MS:
            severity = "warn"
            reason = f"+{delta:.0f}ms jump at this hop"

        verdicts.append(
            HopVerdict(
                ttl=hop.ttl,
                delta_ms=delta,
                loss_pct=loss,
                severity=severity,
                reason=reason,
            )
        )

        if severity == "bad" and suspect_idx is None:
            suspect_idx = i

    # Roll-up
    has_bad = any(v.severity == "bad" for v in verdicts)
    has_warn = any(v.severity == "warn" for v in verdicts)
    overall = "bad" if has_bad else ("warn" if has_warn else "ok")

    if suspect_idx is None:
        return Analysis(
            overall=overall,
            headline="No clear bottleneck detected." if overall == "ok"
                     else "Path looks acceptable but with minor anomalies.",
            suspect_hop=None,
            suspect_owner=None,
            suspect_role=None,
            summary=(
                f"Reached {result.destination} ({result.destination_ip}) in "
                f"{len(hops)} hops with no hop showing significant delay or loss."
                if overall == "ok"
                else "Some hops showed mild jumps in latency but nothing severe."
            ),
            hop_verdicts=verdicts,
        )

    suspect_hop = hops[suspect_idx]
    role = _classify_role(suspect_idx, len(hops), suspect_hop)
    owner = suspect_hop.asn_name or "Unknown operator"
    if suspect_hop.asn:
        owner = f"{owner} ({suspect_hop.asn})"

    headline_map = {
        "Local network": f"Bottleneck is on the local network at hop {suspect_hop.ttl}.",
        "Your ISP": f"Bottleneck is at the ISP edge (hop {suspect_hop.ttl}).",
        "Transit provider": f"Bottleneck is at the transit provider {owner} (hop {suspect_hop.ttl}).",
        "Destination network": f"Bottleneck is on the destination network {owner} (hop {suspect_hop.ttl}).",
    }
    headline = headline_map[role]

    summary = (
        f"From {result.destination} ({result.destination_ip}), the path traverses "
        f"{len(hops)} hops. The first hop showing significant degradation is hop "
        f"{suspect_hop.ttl} ({suspect_hop.ip}, {owner}). "
        f"{verdicts[suspect_idx].reason.capitalize()}. "
        f"This means a local speedtest to your ISP will not show the issue, "
        f"because the speedtest server sits *before* this hop."
    )

    return Analysis(
        overall=overall,
        headline=headline,
        suspect_hop=suspect_hop.ttl,
        suspect_owner=owner,
        suspect_role=role,
        summary=summary,
        hop_verdicts=verdicts,
    )
