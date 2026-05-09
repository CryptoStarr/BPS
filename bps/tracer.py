"""
TCP-based path tracer.

Why TCP, not ICMP:
- ICMP is rate-limited and deprioritized by many routers, producing misleading
  latency numbers and missing hops.
- The real client traffic is TCP on port 443 (or 80). To diagnose what the
  *user* experiences, we have to probe the path the *user's* traffic takes.
- TCP SYN with a low TTL elicits an ICMP TIME_EXCEEDED from each transit
  router (same as ICMP traceroute) but the forward path is the real one.

How it works:
1. For TTL = 1..max_hops, send a TCP SYN to (dst, port) with that TTL.
2. The router that decrements TTL to 0 replies with ICMP TIME_EXCEEDED.
3. We use a raw ICMP socket (or scapy if available) to read the source IP
   of that reply -> that's hop N.
4. When we finally reach the destination, the SYN is answered with SYN/ACK
   (or RST), which we detect via the TCP socket itself - no raw socket
   needed for the final hop.

Fallback: on platforms where raw ICMP isn't available without admin (Windows
without admin, locked-down corp Macs), we fall back to using the system
`tracert` / `traceroute` binary and parse its output. The tracer interface
is the same either way.
"""

from __future__ import annotations

import os
import platform
import re
import socket
import struct
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from statistics import median
from typing import Iterator


# ---------- Data model ----------

@dataclass
class HopProbe:
    rtt_ms: float | None  # None = timeout
    reply_from: str | None  # IP that replied (None if no reply)


@dataclass
class Hop:
    ttl: int
    ip: str | None  # primary replier (first one we saw); kept for back-compat
    hostname: str | None = None
    asn: str | None = None
    asn_name: str | None = None
    probes: list[HopProbe] = field(default_factory=list)
    # All distinct replier IPs at this TTL across passes. Length > 1 means
    # the path is load-balancing (ECMP) at this hop and the visualizer should
    # render the hop as a diamond/branch instead of a single circle.
    all_ips: list[str] = field(default_factory=list)
    # Per-extra-IP enrichment (the primary IP's enrichment lives on the hop
    # itself). Map: ip -> (hostname, asn, asn_name).
    extra_ip_info: dict[str, tuple[str | None, str | None, str | None]] = field(default_factory=dict)
    # Geolocation: {lat, lon, city, country, country_code, isp, org} or None.
    # Populated during enrichment and used by the dashboard/report's map view.
    geo: dict | None = None

    @property
    def avg_rtt(self) -> float | None:
        rtts = [p.rtt_ms for p in self.probes if p.rtt_ms is not None]
        return sum(rtts) / len(rtts) if rtts else None

    @property
    def min_rtt(self) -> float | None:
        rtts = [p.rtt_ms for p in self.probes if p.rtt_ms is not None]
        return min(rtts) if rtts else None

    @property
    def max_rtt(self) -> float | None:
        rtts = [p.rtt_ms for p in self.probes if p.rtt_ms is not None]
        return max(rtts) if rtts else None

    @property
    def loss_pct(self) -> float:
        if not self.probes:
            return 0.0
        lost = sum(1 for p in self.probes if p.rtt_ms is None)
        return 100.0 * lost / len(self.probes)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["avg_rtt"] = self.avg_rtt
        d["min_rtt"] = self.min_rtt
        d["max_rtt"] = self.max_rtt
        d["loss_pct"] = self.loss_pct
        return d


@dataclass
class TraceResult:
    destination: str
    destination_ip: str
    port: int
    started_at: float
    finished_at: float
    hops: list[Hop]
    method: str  # "tcp_raw", "system_traceroute", "system_tracert"
    # Identity of the machine running the trace — surfaces in the report's
    # leftmost (source) node so reports auto-document who ran them.
    source_name: str | None = None  # socket.gethostname()
    source_ip: str | None = None    # local IP used to reach the destination

    def to_dict(self) -> dict:
        return {
            "destination": self.destination,
            "destination_ip": self.destination_ip,
            "port": self.port,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_s": self.finished_at - self.started_at,
            "method": self.method,
            "source_name": self.source_name,
            "source_ip": self.source_ip,
            "hops": [h.to_dict() for h in self.hops],
        }


# ---------- The tracer ----------

class Tracer:
    """
    Traces the path to (host, port). Yields Hop objects as it discovers them
    so the UI can render progressively.
    """

    def __init__(
        self,
        max_hops: int = 30,
        probes_per_hop: int = 3,
        timeout_s: float = 2.0,
        port: int = 443,
        passes: int = 1,
    ):
        self.max_hops = max_hops
        self.probes_per_hop = probes_per_hop
        self.timeout_s = timeout_s
        self.port = port
        # Number of full traces to run back-to-back. Multiple passes are how
        # we discover ECMP: many backbone networks load-balance per-flow, so
        # different probes may hit different routers at the same TTL.
        self.passes = max(1, passes)

    def trace(self, host: str) -> Iterator[Hop]:
        """Yield Hop objects one-by-one as the trace progresses (single pass)."""
        try:
            dst_ip = socket.gethostbyname(host)
        except socket.gaierror as e:
            raise RuntimeError(f"Cannot resolve {host!r}: {e}") from e

        # Pick a backend
        if self._can_use_raw_icmp():
            yield from self._trace_tcp_raw(host, dst_ip)
        else:
            yield from self._trace_system(host, dst_ip)

    def trace_full(self, host: str, on_hop=None) -> TraceResult:
        """Synchronous version that returns a complete TraceResult.

        Runs ``self.passes`` independent traces in **parallel** and merges
        replier IPs seen at each TTL. ``on_hop(pass_idx, hop)`` is called
        from a worker thread every time a hop arrives so the UI can stream
        progress instead of staring at a blank "Working…" screen.
        """
        started = time.time()
        try:
            dst_ip = socket.gethostbyname(host)
        except socket.gaierror as e:
            raise RuntimeError(f"Cannot resolve {host!r}: {e}") from e

        # Identify the agent (this machine). Used as the label of the leftmost
        # node so reports auto-document who ran them.
        source_name = agent_hostname()
        source_ip = local_ip_for(dst_ip)

        method = "tcp_raw" if self._can_use_raw_icmp() else (
            "system_tracert" if platform.system() == "Windows" else "system_traceroute"
        )

        merged_by_ttl: dict[int, Hop] = {}
        order: list[int] = []
        merge_lock = threading.Lock()

        def _merge_hop(pass_idx: int, hop: Hop) -> None:
            with merge_lock:
                if hop.ttl not in merged_by_ttl:
                    merged_by_ttl[hop.ttl] = hop
                    order.append(hop.ttl)
                    if hop.ip and hop.ip not in hop.all_ips:
                        hop.all_ips.append(hop.ip)
                else:
                    existing = merged_by_ttl[hop.ttl]
                    existing.probes.extend(hop.probes)
                    if hop.ip and hop.ip not in existing.all_ips:
                        existing.all_ips.append(hop.ip)
            if on_hop is not None:
                try:
                    on_hop(pass_idx, hop)
                except Exception:
                    # Never let UI exceptions kill the trace
                    pass

        def _run_one_pass(pass_idx: int) -> None:
            for hop in self.trace(host):
                _merge_hop(pass_idx, hop)

        if self.passes <= 1:
            _run_one_pass(0)
        else:
            # Concurrent traces: each spawns its own tracert subprocess (or
            # raw-socket session) so they don't interfere. Total wall-clock
            # is bounded by the slowest single pass, not the sum.
            with ThreadPoolExecutor(max_workers=self.passes) as pool:
                futures = [pool.submit(_run_one_pass, i)
                           for i in range(self.passes)]
                for f in futures:
                    f.result()

        # Render in TTL order even if passes finished out of order.
        hops = [merged_by_ttl[t] for t in sorted(merged_by_ttl)]
        return TraceResult(
            destination=host,
            destination_ip=dst_ip,
            port=self.port,
            started_at=started,
            finished_at=time.time(),
            hops=hops,
            method=method,
            source_name=source_name,
            source_ip=source_ip,
        )

    # ---------- Backend selection ----------

    @staticmethod
    def _can_use_raw_icmp() -> bool:
        """True if we can open a raw ICMP socket AND expect it to actually work.

        On Windows the raw ICMP socket frequently *opens* without admin but
        fails to deliver TIME_EXCEEDED packets back to userspace, which makes
        it look like every transit hop is silently dropping our probes. The
        system ``tracert`` binary is reliable and fast on Windows, so we
        always prefer it there. On POSIX, raw sockets behave correctly when
        the process has the necessary privilege/capability.
        """
        if platform.system() == "Windows":
            return False
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            s.close()
            return True
        except (PermissionError, OSError):
            return False

    # ---------- Backend 1: raw TCP+ICMP (preferred) ----------

    def _trace_tcp_raw(self, host: str, dst_ip: str) -> Iterator[Hop]:
        """
        For each TTL, fire ``probes_per_hop`` TCP SYNs with that TTL and read
        the ICMP TIME_EXCEEDED replies. Probes run in parallel so a hop returns
        in ~timeout_s, not probes_per_hop * timeout_s. Distinct replier IPs
        across the parallel probes feed Hop.all_ips for ECMP visualization.
        """
        import select  # local import: only used by the raw backend

        for ttl in range(1, self.max_hops + 1):
            probes: list[HopProbe] = []
            replier_ips: list[str] = []
            reached_dest = False

            with ThreadPoolExecutor(max_workers=self.probes_per_hop) as pool:
                futures = [
                    pool.submit(self._tcp_probe_one, dst_ip, ttl, select)
                    for _ in range(self.probes_per_hop)
                ]
                for fut in as_completed(futures):
                    rtt, src, hit_dest = fut.result()
                    probes.append(HopProbe(rtt_ms=rtt, reply_from=src))
                    if src and src not in replier_ips:
                        replier_ips.append(src)
                    if hit_dest:
                        reached_dest = True

            primary = replier_ips[0] if replier_ips else None
            hop = Hop(ttl=ttl, ip=primary, probes=probes,
                      all_ips=list(replier_ips))
            yield hop

            if reached_dest:
                return

    def _tcp_probe_one(self, dst_ip: str, ttl: int, select_mod=None
                       ) -> tuple[float | None, str | None, bool]:
        """
        Send one TCP SYN with the given TTL. Listen on a raw ICMP socket for
        TIME_EXCEEDED from a transit router; also detect TCP connection
        success (=> we reached the destination) using a proper ``select``
        on the TCP socket's writability instead of the broken
        ``getsockopt(SO_ERROR)`` poll. Returns (rtt_ms, replier_ip, reached_dest).
        """
        if select_mod is None:
            import select as select_mod  # type: ignore

        try:
            icmp = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        except (PermissionError, OSError):
            return None, None, False
        icmp.settimeout(self.timeout_s)

        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        tcp.setblocking(False)

        sent_at = time.perf_counter()
        try:
            tcp.connect_ex((dst_ip, self.port))
        except OSError:
            pass

        deadline = sent_at + self.timeout_s
        try:
            while True:
                remaining = deadline - time.perf_counter()
                if remaining <= 0:
                    return None, None, False

                # Wait for either the ICMP socket to be readable
                # OR the TCP socket to become writable (connect completed).
                slice_s = min(remaining, 0.1)
                try:
                    rready, wready, _ = select_mod.select(
                        [icmp], [tcp], [], slice_s
                    )
                except (OSError, ValueError):
                    rready, wready = [], []

                if icmp in rready:
                    try:
                        pkt, addr = icmp.recvfrom(1500)
                    except OSError:
                        continue
                    rtt = (time.perf_counter() - sent_at) * 1000
                    src = addr[0]
                    # IP header is at least 20 bytes; ICMP type is the next byte
                    if len(pkt) >= 21:
                        icmp_type = pkt[20]
                        if icmp_type in (3, 11):
                            return rtt, src, False
                    # Other ICMP types: ignore and keep waiting
                    continue

                if tcp in wready:
                    # connect() completed (success or refused). Check SO_ERROR.
                    err = tcp.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                    rtt = (time.perf_counter() - sent_at) * 1000
                    if err == 0:
                        # Successful connection to the destination
                        return rtt, dst_ip, True
                    # ECONNREFUSED / RST also means we reached the destination
                    # at the IP layer (a router would not reply with a TCP RST
                    # to a packet whose TTL was already 0). Treat as reached.
                    if err in (
                        getattr(__import__("errno"), "ECONNREFUSED", 111),
                        10061,  # WSAECONNREFUSED on Windows
                    ):
                        return rtt, dst_ip, True
                    # Anything else: keep waiting briefly in case ICMP arrives
                    return None, None, False
        finally:
            try: icmp.close()
            except OSError: pass
            try: tcp.close()
            except OSError: pass

    # ---------- Backend 2: system traceroute ----------

    def _trace_system(self, host: str, dst_ip: str) -> Iterator[Hop]:
        """Fallback that shells out to the OS tool and parses its output."""
        is_windows = platform.system() == "Windows"
        if is_windows:
            cmd = ["tracert", "-d", "-h", str(self.max_hops),
                   "-w", str(int(self.timeout_s * 1000)), host]
        else:
            # -n no DNS, -q probes, -w timeout, -m max
            cmd = ["traceroute", "-n",
                   "-q", str(self.probes_per_hop),
                   "-w", str(int(self.timeout_s)),
                   "-m", str(self.max_hops),
                   host]

        # On Windows, suppress the cmd.exe / tracert.exe console window that
        # would otherwise pop up for every subprocess. CREATE_NO_WINDOW (0x08000000)
        # is the right flag — DETACHED_PROCESS would also work but interferes
        # with stdout capture.
        popen_kwargs = {
            "stdout": subprocess.PIPE,
            "stderr": subprocess.STDOUT,
            "text": True,
            "bufsize": 1,
        }
        if platform.system() == "Windows":
            popen_kwargs["creationflags"] = getattr(
                subprocess, "CREATE_NO_WINDOW", 0x08000000
            )

        try:
            proc = subprocess.Popen(cmd, **popen_kwargs)
        except FileNotFoundError as e:
            raise RuntimeError(
                f"Neither raw socket access nor system traceroute is available: {e}"
            ) from e

        if proc.stdout is None:
            return

        for line in proc.stdout:
            hop = self._parse_traceroute_line(line, is_windows)
            if hop is not None:
                yield hop
        proc.wait()

    @staticmethod
    def _parse_traceroute_line(line: str, is_windows: bool) -> Hop | None:
        """Parse a single line of tracert/traceroute output into a Hop."""
        line = line.strip()
        if not line:
            return None

        if is_windows:
            # Windows tracert lines look like:
            #   "  3    24 ms    23 ms    24 ms  10.0.0.1"
            #   "  4     *        *        *     Request timed out."
            m = re.match(r"^\s*(\d+)\s+(.*)$", line)
            if not m:
                return None
            ttl = int(m.group(1))
            rest = m.group(2)
            # Three rtt fields then an IP (or "*" for timeout)
            rtt_pat = re.compile(r"(\d+)\s*ms|\*")
            rtts = []
            for tok in rtt_pat.findall(rest):
                if tok == "":
                    continue
                rtts.append(None if tok == "*" else float(tok))
            ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", rest)
            ip = ip_match.group(1) if ip_match else None
            probes = [HopProbe(rtt_ms=r, reply_from=ip) for r in rtts[:3]]
            while len(probes) < 3:
                probes.append(HopProbe(rtt_ms=None, reply_from=None))
            return Hop(ttl=ttl, ip=ip, probes=probes)
        else:
            # Linux/Mac:
            #   " 3  10.0.0.1  1.234 ms  1.111 ms  1.222 ms"
            #   " 4  * * *"
            m = re.match(r"^\s*(\d+)\s+(.*)$", line)
            if not m:
                return None
            ttl = int(m.group(1))
            rest = m.group(2)
            ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", rest)
            ip = ip_match.group(1) if ip_match else None
            rtts: list[float | None] = []
            for tok in re.findall(r"([\d.]+)\s*ms|\*", rest):
                if isinstance(tok, tuple):
                    val, star = tok if len(tok) == 2 else (tok[0], "")
                    rtts.append(float(val) if val else None)
                else:
                    rtts.append(None if tok == "*" else float(tok))
            probes = [HopProbe(rtt_ms=r, reply_from=ip) for r in rtts[:3]]
            while len(probes) < 3:
                probes.append(HopProbe(rtt_ms=None, reply_from=None))
            return Hop(ttl=ttl, ip=ip, probes=probes)


# ---------- Helpers ----------

def hop_deltas(hops: list[Hop]) -> list[float | None]:
    """Per-hop incremental latency: hop[n].rtt - hop[n-1].rtt (uses min_rtt)."""
    deltas: list[float | None] = []
    prev: float | None = None
    for h in hops:
        cur = h.min_rtt
        if cur is None or prev is None:
            deltas.append(None)
        else:
            deltas.append(max(0.0, cur - prev))
        if cur is not None:
            prev = cur
    return deltas


def median_nonnull(xs: list[float | None]) -> float:
    vals = [x for x in xs if x is not None]
    return median(vals) if vals else 0.0


def agent_hostname() -> str:
    """Return this machine's hostname (e.g. ``DESKTOP-ABC123``).

    Falls back to ``"agent"`` if the OS doesn't expose a hostname for some
    reason — never raises, since this is only used as a label.
    """
    try:
        return socket.gethostname() or "agent"
    except OSError:
        return "agent"


def local_ip_for(remote_ip: str) -> str | None:
    """Determine which local IP this machine would use to reach ``remote_ip``.

    No packet is sent: we open a UDP socket and call ``connect`` (which on
    every major OS picks a route and binds a local interface) then read the
    chosen local address back via ``getsockname``. This works without any
    privilege and gives the right answer even on multi-homed machines.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((remote_ip, 1))
            return s.getsockname()[0]
        finally:
            s.close()
    except OSError:
        return None
