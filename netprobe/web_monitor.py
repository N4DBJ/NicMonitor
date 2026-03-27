"""
netprobe/web_monitor.py - Web Page Load Analyser
==================================================
Breaks a URL request into discrete phases and times each individually
to pinpoint where slowdowns occur:

  1. DNS Resolution  — compared across system default, Google (8.8.8.8),
                       and Cloudflare (1.1.1.1) to identify DNS-specific delays
  2. TCP Connect     — time to establish the socket connection
  3. TLS Handshake   — time for SSL negotiation (HTTPS only)
  4. Time to First Byte (TTFB) — time from sending the HTTP request
                       until the first byte of the response arrives
  5. Content Download — time to read the full response body
  6. Total           — end-to-end wall-clock time

All operations use only the Python standard library (socket, ssl, http.client,
subprocess) so there are no extra dependencies.

Version: 1.5.0
"""

import http.client
import logging
import re
import socket
import ssl
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger("netprobe.web_monitor")


# ---------------------------------------------------------------------------
# Data structure for a single probe result
# ---------------------------------------------------------------------------

@dataclass
class DnsComparison:
    """DNS resolution result from a single resolver."""
    resolver_name: str = ""
    resolver_ip: str = ""        # "" means "system default"
    resolved_ip: str = ""
    time_ms: float = 0.0
    error: str = ""


@dataclass
class WebProbeResult:
    """Full timing breakdown for a single URL probe."""
    url: str = ""
    timestamp: datetime = field(default_factory=datetime.now)

    # Parsed URL parts
    scheme: str = ""             # http or https
    hostname: str = ""
    port: int = 0
    path: str = "/"

    # Phase timings (milliseconds), -1 means skipped/error
    dns_ms: float = -1           # System DNS resolution
    tcp_connect_ms: float = -1   # Socket connect after DNS
    tls_handshake_ms: float = -1  # SSL negotiation (HTTPS only)
    ttfb_ms: float = -1          # Time to first byte
    download_ms: float = -1      # Content transfer
    total_ms: float = -1         # Wall-clock total

    # Response info
    status_code: int = 0
    status_reason: str = ""
    content_length: int = 0
    response_headers: Dict[str, str] = field(default_factory=dict)

    # DNS comparison across resolvers
    dns_comparisons: List[DnsComparison] = field(default_factory=list)

    # Resolved IP used for the actual connection
    resolved_ip: str = ""

    # Diagnosis
    bottleneck: str = ""         # Which phase is the slowest
    diagnosis: List[str] = field(default_factory=list)
    error: str = ""              # Fatal error if the probe failed entirely

    def analyse(self) -> None:
        """Run automatic bottleneck detection and produce diagnosis strings."""
        self.diagnosis = []

        if self.error:
            self.diagnosis.append(f"FATAL: {self.error}")
            return

        # Identify the slowest phase
        phases = {}
        if self.dns_ms >= 0:
            phases["DNS Resolution"] = self.dns_ms
        if self.tcp_connect_ms >= 0:
            phases["TCP Connect"] = self.tcp_connect_ms
        if self.tls_handshake_ms >= 0:
            phases["TLS Handshake"] = self.tls_handshake_ms
        if self.ttfb_ms >= 0:
            phases["TTFB"] = self.ttfb_ms
        if self.download_ms >= 0:
            phases["Download"] = self.download_ms

        if phases:
            self.bottleneck = max(phases, key=phases.get)

        # DNS analysis
        if self.dns_ms > 500:
            self.diagnosis.append(
                f"CRITICAL: DNS resolution took {self.dns_ms:.0f}ms "
                f"— very slow, possible DNS server issue"
            )
        elif self.dns_ms > 100:
            self.diagnosis.append(
                f"WARNING: DNS resolution took {self.dns_ms:.0f}ms "
                f"— slower than expected"
            )

        # Compare DNS resolvers
        sys_dns = next(
            (d for d in self.dns_comparisons if d.resolver_ip == ""), None
        )
        alt_resolvers = [
            d for d in self.dns_comparisons if d.resolver_ip != "" and not d.error
        ]
        if sys_dns and alt_resolvers and sys_dns.time_ms > 0:
            fastest_alt = min(alt_resolvers, key=lambda d: d.time_ms)
            if sys_dns.time_ms > fastest_alt.time_ms * 3 and sys_dns.time_ms > 50:
                self.diagnosis.append(
                    f"WARNING: System DNS ({sys_dns.time_ms:.0f}ms) is "
                    f"{sys_dns.time_ms / max(fastest_alt.time_ms, 1):.1f}x slower "
                    f"than {fastest_alt.resolver_name} ({fastest_alt.time_ms:.0f}ms) "
                    f"— consider changing DNS servers"
                )

        # TCP Connect
        if self.tcp_connect_ms > 200:
            self.diagnosis.append(
                f"WARNING: TCP connect took {self.tcp_connect_ms:.0f}ms "
                f"— possible network congestion or distant server"
            )

        # TLS
        if self.tls_handshake_ms > 300:
            self.diagnosis.append(
                f"WARNING: TLS handshake took {self.tls_handshake_ms:.0f}ms "
                f"— slow cipher negotiation or certificate chain"
            )

        # TTFB
        if self.ttfb_ms > 500:
            self.diagnosis.append(
                f"WARNING: Server response time (TTFB) is {self.ttfb_ms:.0f}ms "
                f"— server may be overloaded or slow backend"
            )

        # Download
        if self.download_ms > 2000:
            self.diagnosis.append(
                f"INFO: Content download took {self.download_ms:.0f}ms "
                f"({self.content_length / 1024:.0f} KB)"
            )

        # HTTP error codes
        if self.status_code >= 500:
            self.diagnosis.append(
                f"CRITICAL: Server error — HTTP {self.status_code} {self.status_reason}"
            )
        elif self.status_code >= 400:
            self.diagnosis.append(
                f"WARNING: Client error — HTTP {self.status_code} {self.status_reason}"
            )
        elif 300 <= self.status_code < 400:
            location = self.response_headers.get("location", "unknown")
            self.diagnosis.append(
                f"INFO: Redirect — HTTP {self.status_code} → {location}"
            )

        # Total time
        if self.total_ms > 3000:
            self.diagnosis.append(
                f"CRITICAL: Total load time {self.total_ms:.0f}ms — very slow"
            )
        elif self.total_ms > 1000:
            self.diagnosis.append(
                f"WARNING: Total load time {self.total_ms:.0f}ms — noticeable delay"
            )

        if not self.diagnosis:
            self.diagnosis.append("OK: All phases within normal ranges")


# ---------------------------------------------------------------------------
# DNS resolution helpers
# ---------------------------------------------------------------------------

def _resolve_system_dns(hostname: str) -> DnsComparison:
    """Resolve using the system's configured DNS."""
    comp = DnsComparison(resolver_name="System Default", resolver_ip="")
    try:
        t0 = time.perf_counter()
        results = socket.getaddrinfo(hostname, None, socket.AF_INET)
        comp.time_ms = (time.perf_counter() - t0) * 1000
        if results:
            comp.resolved_ip = results[0][4][0]
    except Exception as exc:
        comp.error = str(exc)
        comp.time_ms = -1
    return comp


def _resolve_via_nslookup(hostname: str, server: str, name: str) -> DnsComparison:
    """Resolve using nslookup against a specific DNS server."""
    comp = DnsComparison(resolver_name=name, resolver_ip=server)
    try:
        t0 = time.perf_counter()
        result = subprocess.run(
            ["nslookup", hostname, server],
            capture_output=True, text=True, timeout=10,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        comp.time_ms = (time.perf_counter() - t0) * 1000
        # Parse the answer section for an IP
        output = result.stdout
        # Skip the first "Server" and "Address" lines (the DNS server itself)
        in_answer = False
        for line in output.splitlines():
            if "Name:" in line:
                in_answer = True
                continue
            if in_answer and "Address:" in line:
                ip = line.split(":", 1)[1].strip()
                if ip and not ip.startswith(server):
                    comp.resolved_ip = ip
                    break
        if not comp.resolved_ip and "Non-existent domain" in output:
            comp.error = "NXDOMAIN"
        elif not comp.resolved_ip and "can't find" in output.lower():
            comp.error = "DNS lookup failed"
    except subprocess.TimeoutExpired:
        comp.error = "Timeout"
        comp.time_ms = 10000
    except Exception as exc:
        comp.error = str(exc)
        comp.time_ms = -1
    return comp


# ---------------------------------------------------------------------------
# Web Probe Engine
# ---------------------------------------------------------------------------

class WebProbeMonitor:
    """
    Probes a URL with detailed timing breakdown of each connection phase.
    Optionally triggers a Wireshark capture during the probe.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._history: List[WebProbeResult] = []

    @property
    def history(self) -> List[WebProbeResult]:
        with self._lock:
            return list(self._history)

    def probe(
        self,
        url: str,
        timeout: float = 15.0,
        follow_redirects: bool = True,
        max_redirects: int = 5,
    ) -> WebProbeResult:
        """
        Execute a full URL probe with timing breakdown.
        This is blocking — run in a background thread from the GUI.
        """
        result = WebProbeResult(url=url, timestamp=datetime.now())

        # --- Parse URL ---
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
            result.url = url

        parsed = urlparse(url)
        result.scheme = parsed.scheme
        result.hostname = parsed.hostname or ""
        result.port = parsed.port or (443 if parsed.scheme == "https" else 80)
        result.path = parsed.path or "/"
        if parsed.query:
            result.path += "?" + parsed.query

        if not result.hostname:
            result.error = "Invalid URL — no hostname found"
            result.analyse()
            self._store(result)
            return result

        wall_start = time.perf_counter()

        # --- Phase 1: DNS Resolution (system + comparisons) ---
        logger.info("WebProbe: DNS lookup for %s", result.hostname)
        sys_dns = _resolve_system_dns(result.hostname)
        result.dns_comparisons.append(sys_dns)
        result.dns_ms = sys_dns.time_ms
        result.resolved_ip = sys_dns.resolved_ip

        if sys_dns.error:
            result.error = f"DNS resolution failed: {sys_dns.error}"
            result.total_ms = (time.perf_counter() - wall_start) * 1000
            result.analyse()
            self._store(result)
            return result

        # Compare against alternative DNS servers (in parallel)
        alt_servers = [
            ("8.8.8.8", "Google DNS"),
            ("1.1.1.1", "Cloudflare DNS"),
            ("9.9.9.9", "Quad9 DNS"),
        ]
        alt_threads: List[threading.Thread] = []
        alt_results: List[DnsComparison] = []
        alt_lock = threading.Lock()

        def _alt_resolve(server, name):
            comp = _resolve_via_nslookup(result.hostname, server, name)
            with alt_lock:
                alt_results.append(comp)

        for server, name in alt_servers:
            t = threading.Thread(target=_alt_resolve, args=(server, name), daemon=True)
            t.start()
            alt_threads.append(t)

        # Don't wait too long for comparisons
        for t in alt_threads:
            t.join(timeout=12)

        result.dns_comparisons.extend(sorted(alt_results, key=lambda d: d.time_ms if d.time_ms >= 0 else 99999))

        # --- Phase 2-5: HTTP connection with per-phase timing ---
        try:
            result = self._http_probe(result, timeout, follow_redirects, max_redirects)
        except Exception as exc:
            result.error = f"HTTP probe failed: {exc}"
            logger.error("WebProbe HTTP error: %s", exc, exc_info=True)

        result.total_ms = (time.perf_counter() - wall_start) * 1000
        result.analyse()
        self._store(result)
        return result

    def _http_probe(
        self,
        result: WebProbeResult,
        timeout: float,
        follow_redirects: bool,
        max_redirects: int,
    ) -> WebProbeResult:
        """Perform the TCP connect → TLS → TTFB → download phases."""
        hostname = result.hostname
        port = result.port
        use_ssl = result.scheme == "https"
        path = result.path
        resolved_ip = result.resolved_ip or hostname

        for redirect_count in range(max_redirects + 1):
            # TCP Connect
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)

            t0 = time.perf_counter()
            sock.connect((resolved_ip, port))
            result.tcp_connect_ms = (time.perf_counter() - t0) * 1000

            # TLS Handshake
            if use_ssl:
                ctx = ssl.create_default_context()
                t0 = time.perf_counter()
                sock = ctx.wrap_socket(sock, server_hostname=hostname)
                result.tls_handshake_ms = (time.perf_counter() - t0) * 1000
            else:
                result.tls_handshake_ms = 0

            # Send HTTP request and measure TTFB
            request_line = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {hostname}\r\n"
                f"User-Agent: NetProbe/1.5 WebProbe\r\n"
                f"Accept: */*\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )

            t0 = time.perf_counter()
            sock.sendall(request_line.encode("utf-8"))

            # Read until we get the first chunk of data (TTFB)
            first_data = sock.recv(8192)
            result.ttfb_ms = (time.perf_counter() - t0) * 1000

            # Download remaining content
            t0 = time.perf_counter()
            chunks = [first_data]
            while True:
                try:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    chunks.append(chunk)
                except socket.timeout:
                    break
            result.download_ms = (time.perf_counter() - t0) * 1000

            sock.close()

            # Parse the HTTP response
            raw = b"".join(chunks)
            header_end = raw.find(b"\r\n\r\n")
            if header_end == -1:
                header_end = raw.find(b"\n\n")
                sep_len = 2
            else:
                sep_len = 4

            if header_end >= 0:
                header_block = raw[:header_end].decode("utf-8", errors="replace")
                body = raw[header_end + sep_len:]
            else:
                header_block = raw.decode("utf-8", errors="replace")
                body = b""

            result.content_length = len(body)

            # Parse status line
            lines = header_block.split("\r\n") if "\r\n" in header_block else header_block.split("\n")
            if lines:
                status_match = re.match(r"HTTP/[\d.]+\s+(\d+)\s*(.*)", lines[0])
                if status_match:
                    result.status_code = int(status_match.group(1))
                    result.status_reason = status_match.group(2).strip()

            # Parse headers
            for line in lines[1:]:
                if ":" in line:
                    key, val = line.split(":", 1)
                    result.response_headers[key.strip().lower()] = val.strip()

            # Handle redirects
            if follow_redirects and 300 <= result.status_code < 400:
                location = result.response_headers.get("location", "")
                if not location:
                    break
                # Parse redirect URL
                if location.startswith("http"):
                    rp = urlparse(location)
                    hostname = rp.hostname or hostname
                    port = rp.port or (443 if rp.scheme == "https" else 80)
                    use_ssl = rp.scheme == "https"
                    path = rp.path or "/"
                    if rp.query:
                        path += "?" + rp.query
                    result.scheme = rp.scheme
                    result.hostname = hostname
                    result.port = port
                elif location.startswith("/"):
                    path = location
                else:
                    break
                # Re-resolve DNS for new hostname
                resolved_ip = socket.gethostbyname(hostname)
                result.resolved_ip = resolved_ip
                logger.info("WebProbe: Following redirect to %s", location)
                continue
            break

        return result

    def _store(self, result: WebProbeResult) -> None:
        with self._lock:
            self._history.append(result)
            # Keep last 100 probes
            if len(self._history) > 100:
                self._history = self._history[-100:]
