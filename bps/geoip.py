"""
Enrich each hop IP with a hostname (rDNS) and the AS (network operator) it belongs to.

We use a two-tier lookup:

1. **Team Cymru DNS WHOIS** (https://www.team-cymru.com/ip-asn-mapping) —
   IP→ASN mapping. Fast, free, no API key. Returns abbreviated registry
   labels like "NTT-DATA-Inc, US" that are technically correct but terse.

2. **PeeringDB** (https://www.peeringdb.com/api/net?asn=N) — ASN→long name.
   Optional second hop that turns "NTT-DATA-Inc" into "NTT Communications
   Corporation (aka NTT-COM)". PeeringDB is the operator-curated database
   so its names are the ones an ISP would actually recognise. Best-effort:
   if PeeringDB is offline or doesn't have the AS, we fall back to Cymru.

All lookups are cached per-IP and per-ASN for the lifetime of the process.
"""

from __future__ import annotations

import ipaddress
import platform
import re
import socket
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor

try:
    import dns.resolver  # type: ignore
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

try:
    import requests  # type: ignore
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


_rdns_cache: dict[str, str | None] = {}
_asn_cache: dict[str, tuple[str | None, str | None]] = {}
# Cache for PeeringDB long names keyed by ASN string ("AS20011" or "20011").
_peeringdb_cache: dict[str, str | None] = {}
# Cache for ip-api.com geolocation results keyed by IP. Value is a small
# dict with lat/lon/city/country_code, or None when the lookup failed.
_geo_cache: dict[str, dict | None] = {}
_lock = threading.Lock()

# Team Cymru's DNS WHOIS is hosted under cymru.com but the queries we send
# (e.g. "78.47.251.142.origin.asn.cymru.com") are unusual TXT lookups that
# some local resolvers (ISP routers, captive DNS) silently drop or rate-limit.
# We fall back to public resolvers so the lookup is reliable across networks.
_PUBLIC_DNS = ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4"]


def _cymru_resolver(timeout: float):
    """A dnspython resolver pinned to public DNS, for Cymru lookups only."""
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = list(_PUBLIC_DNS)
    r.timeout = timeout
    r.lifetime = timeout
    return r


def is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


_netbios_cache: dict[str, str | None] = {}


def netbios_name(ip: str, timeout: float = 1.5) -> str | None:
    """Windows-only: NetBIOS name of a host on the local network, or None.

    The output of ``nbtstat -A <ip>`` lists registered names; the unique
    ``<00>`` entry is the computer name. Most home routers and Windows
    machines respond, even when rDNS doesn't have a PTR record. Cached so
    repeated lookups are free.
    """
    if platform.system() != "Windows":
        return None
    with _lock:
        if ip in _netbios_cache:
            return _netbios_cache[ip]

    name: str | None = None
    try:
        proc = subprocess.run(
            ["nbtstat", "-A", ip],
            capture_output=True, text=True, timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000),
        )
        for line in proc.stdout.splitlines():
            m = re.match(r"\s*(\S+)\s+<00>\s+UNIQUE", line)
            if m and m.group(1).upper() != "MAC":
                name = m.group(1)
                break
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    with _lock:
        _netbios_cache[ip] = name
    return name


def reverse_dns(ip: str, timeout: float = 1.5) -> str | None:
    """rDNS lookup with caching."""
    with _lock:
        if ip in _rdns_cache:
            return _rdns_cache[ip]

    socket.setdefaulttimeout(timeout)
    try:
        host, _, _ = socket.gethostbyaddr(ip)
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        host = None
    finally:
        socket.setdefaulttimeout(None)

    with _lock:
        _rdns_cache[ip] = host
    return host


def peeringdb_long_name(asn_or_num: str, timeout: float = 3.0) -> str | None:
    """Return the operator-curated long name for an AS, or None.

    Reads the public PeeringDB API (no auth, anonymous read-only) and pulls
    ``name_long`` plus ``aka`` (alternate names). PeeringDB is the source
    network operators themselves register with — its labels are the ones
    that match what an ISP's NOC will recognise on a complaint email.

    Examples:
      AS20011 -> "NTT Communications Corporation (aka NTT-COM)"
      AS15169 -> "Google LLC"
      AS16276 -> "OVH SAS"
    """
    if not HAS_REQUESTS:
        return None
    asn_num = asn_or_num.lstrip("ASas").strip()
    if not asn_num.isdigit():
        return None
    cache_key = asn_num
    with _lock:
        if cache_key in _peeringdb_cache:
            return _peeringdb_cache[cache_key]
    name: str | None = None
    try:
        r = requests.get(
            f"https://www.peeringdb.com/api/net?asn={asn_num}",
            timeout=timeout,
            headers={"User-Agent": "BPS-BurikaPathScope/1.0"},
        )
        if r.status_code == 200:
            entries = r.json().get("data") or []
            if entries:
                d = entries[0]
                long_name = (d.get("name_long") or d.get("name") or "").strip()
                aka = (d.get("aka") or "").strip()
                if long_name and aka and aka.lower() != long_name.lower():
                    name = f"{long_name} (aka {aka})"
                elif long_name:
                    name = long_name
    except Exception:
        # Network down / API hiccup / weird JSON — fall back to Cymru.
        name = None
    with _lock:
        _peeringdb_cache[cache_key] = name
    return name


def geo_locate_batch(ips: list[str], timeout: float = 5.0) -> dict[str, dict | None]:
    """Resolve a batch of IPs to geo coordinates via ip-api.com's free /batch
    endpoint (no API key required, up to 100 IPs per request).

    Returns a dict keyed by IP. Each value is either a small dict with
    ``lat``, ``lon``, ``city``, ``country``, ``country_code``, ``isp``,
    ``org`` — or ``None`` for IPs that didn't resolve. Cached so repeated
    traces of the same path are instant.

    Public IPs only; private IPs are skipped (no point — they'd map to
    nowhere, and ip-api flags them as ``status=fail``).
    """
    if not HAS_REQUESTS or not ips:
        return {}

    todo: list[str] = []
    out: dict[str, dict | None] = {}
    with _lock:
        for ip in ips:
            if ip in _geo_cache:
                out[ip] = _geo_cache[ip]
            elif is_private(ip):
                _geo_cache[ip] = None
                out[ip] = None
            else:
                todo.append(ip)

    if not todo:
        return out

    fields = "status,country,countryCode,city,lat,lon,isp,org,as,query"
    try:
        r = requests.post(
            "http://ip-api.com/batch",
            params={"fields": fields},
            json=[{"query": ip} for ip in todo],
            timeout=timeout,
            headers={"User-Agent": "BPS-BurikaPathScope/1.0"},
        )
        if r.status_code == 200:
            for entry in r.json():
                ip = entry.get("query")
                if not ip:
                    continue
                if entry.get("status") == "success":
                    out[ip] = {
                        "lat": entry.get("lat"),
                        "lon": entry.get("lon"),
                        "city": entry.get("city") or "",
                        "country": entry.get("country") or "",
                        "country_code": entry.get("countryCode") or "",
                        "isp": entry.get("isp") or "",
                        "org": entry.get("org") or "",
                    }
                else:
                    out[ip] = None
                with _lock:
                    _geo_cache[ip] = out[ip]
        else:
            for ip in todo:
                out[ip] = None
                with _lock:
                    _geo_cache[ip] = None
    except Exception:
        for ip in todo:
            out[ip] = None
            with _lock:
                _geo_cache[ip] = None

    return out


def geo_locate(ip: str, timeout: float = 4.0) -> dict | None:
    """Single-IP wrapper around :func:`geo_locate_batch`."""
    return geo_locate_batch([ip], timeout=timeout).get(ip)


def asn_lookup(ip: str, timeout: float = 2.0) -> tuple[str | None, str | None]:
    """
    Returns (asn, asn_name) e.g. ("AS37468", "Angola Cables Networks SA").

    Step 1: Cymru DNS WHOIS to map IP → ASN + a short registry label.
    Step 2: PeeringDB to upgrade the short label into the operator's full
            registered name. If PeeringDB has no entry, we keep the Cymru
            label so we always return SOMETHING for legitimate ASes.
    """
    with _lock:
        if ip in _asn_cache:
            return _asn_cache[ip]

    if is_private(ip) or not HAS_DNSPYTHON:
        result = (None, None)
        with _lock:
            _asn_cache[ip] = result
        return result

    try:
        # Reverse the IPv4 octets for the cymru query
        reversed_ip = ".".join(reversed(ip.split(".")))
        resolver = _cymru_resolver(timeout)

        # Step 1: IP -> ASN
        answers = resolver.resolve(f"{reversed_ip}.origin.asn.cymru.com", "TXT")
        txt = str(answers[0]).strip('"')
        # "37468 | 102.130.68.0/22 | AO | afrinic | 2018-10-19"
        asn_num = txt.split("|")[0].strip()
        if not asn_num.isdigit():
            result = (None, None)
        else:
            asn = f"AS{asn_num}"

            # Step 2: ASN -> name
            try:
                answers2 = resolver.resolve(f"AS{asn_num}.asn.cymru.com", "TXT")
                txt2 = str(answers2[0]).strip('"')
                # "37468 | ZA | afrinic | 2018-10-19 | ANGOLA-CABLES, AO"
                parts = [p.strip() for p in txt2.split("|")]
                name = parts[-1] if parts else None
                # Strip trailing country code: "ANGOLA-CABLES, AO" -> "ANGOLA-CABLES"
                if name and "," in name:
                    name = name.rsplit(",", 1)[0].strip()
                result = (asn, name)
            except Exception:
                result = (asn, None)
    except Exception:
        result = (None, None)

    # Step 3: try PeeringDB for a richer operator-curated name. Only attempts
    # if Cymru produced an ASN; the result replaces Cymru's short label when
    # available, falls back to the short label otherwise.
    asn, short_name = result
    if asn:
        long_name = peeringdb_long_name(asn)
        if long_name:
            result = (asn, long_name)

    with _lock:
        _asn_cache[ip] = result
    return result


def enrich(hops, max_workers: int = 8) -> None:
    """Fill in hostname / asn / asn_name for every hop in-place, in parallel.

    Also enriches Hop.all_ips beyond the primary one (so ECMP siblings show
    proper rDNS/ASN data in tooltips and the cluster grouping logic).
    """
    work_ips: list[tuple[object, str, bool]] = []  # (hop, ip, is_primary)
    for h in hops:
        if h.ip and not is_private(h.ip):
            work_ips.append((h, h.ip, True))
        for extra in getattr(h, "all_ips", None) or []:
            if extra != h.ip and not is_private(extra):
                work_ips.append((h, extra, False))
    if not work_ips:
        # still need to label private hops below
        pass

    def _do(item):
        hop, ip, is_primary = item
        host = reverse_dns(ip)
        asn, name = asn_lookup(ip)
        if is_primary:
            hop.hostname = host
            hop.asn = asn
            hop.asn_name = name
        else:
            if not hasattr(hop, "extra_ip_info") or hop.extra_ip_info is None:
                hop.extra_ip_info = {}
            hop.extra_ip_info[ip] = (host, asn, name)

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        list(pool.map(_do, work_ips))

    # Identify private (LAN) hops by name where possible: try rDNS, then
    # NetBIOS on Windows. Fall back to a generic "Local network" label.
    private_hops = [h for h in hops if h.ip and is_private(h.ip)]

    def _identify_private(hop):
        host = reverse_dns(hop.ip)
        if not host:
            host = netbios_name(hop.ip)
        hop.hostname = host
        # Use the device name as the AS label so it shows on the cluster /
        # node glyph; keep "Local network" if we couldn't identify it.
        hop.asn_name = host or "Local network"

    if private_hops:
        with ThreadPoolExecutor(max_workers=min(max_workers, len(private_hops))) as pool:
            list(pool.map(_identify_private, private_hops))

    # Geolocate every public IP in a single batched call (ip-api.com /batch
    # accepts up to 100 IPs per request, so any realistic trace fits).
    public_ips = [h.ip for h in hops if h.ip and not is_private(h.ip)]
    if public_ips:
        geo = geo_locate_batch(public_ips)
        for h in hops:
            if h.ip and h.ip in geo:
                h.geo = geo[h.ip]
