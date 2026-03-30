"""
netprobe/browser_probe.py - Browser-Simulated HTTP Probe
=========================================================
Uses curl.exe (bundled with Windows 10+) to probe URLs while simulating
real browser identities (Chrome, Firefox, Edge).  Curl provides precise
per-phase timing via its ``-w`` (write-out) feature and handles HTTP/1.1
with the same TLS stack as the OS.

Why curl instead of raw sockets?
  - Real browser User-Agents cause different CDN routing/compression/caching
  - curl reports timing phases directly (no manual socket instrumentation)
  - Zero extra Python dependencies

Note: Windows' built-in curl.exe typically does NOT include HTTP/2 (nghttp2).
The probe runs HTTP/1.1 but labels the actual protocol negotiated. To get
true HTTP/2, install curl with nghttp2 or use a browser dev-tools export.

Version: 1.6.0
"""

import logging
import os
import re
import shutil
import statistics
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("netprobe.browser_probe")

# ---------------------------------------------------------------------------
# Browser identity presets
# ---------------------------------------------------------------------------

# Real-world User-Agent strings (March 2026 era)
BROWSER_PROFILES: Dict[str, Dict[str, str]] = {
    "Chrome": {
        "user_agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/134.0.0.0 Safari/537.36"
        ),
        "accept": (
            "text/html,application/xhtml+xml,application/xml;"
            "q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"
        ),
        "accept_encoding": "gzip, deflate, br",
        "accept_language": "en-US,en;q=0.9",
        "color": "#4285f4",   # Google blue
    },
    "Firefox": {
        "user_agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:136.0) "
            "Gecko/20100101 Firefox/136.0"
        ),
        "accept": (
            "text/html,application/xhtml+xml,application/xml;"
            "q=0.9,image/avif,image/webp,*/*;q=0.8"
        ),
        "accept_encoding": "gzip, deflate, br, zstd",
        "accept_language": "en-US,en;q=0.5",
        "color": "#ff7139",   # Firefox orange
    },
    "Edge": {
        "user_agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0"
        ),
        "accept": (
            "text/html,application/xhtml+xml,application/xml;"
            "q=0.9,image/avif,image/webp,image/apng,*/*;"
            "q=0.8,application/signed-exchange;v=b3;q=0.7"
        ),
        "accept_encoding": "gzip, deflate, br",
        "accept_language": "en-US,en;q=0.9",
        "color": "#0078d4",   # Edge blue
    },
    "Raw (no UA)": {
        "user_agent": "",
        "accept": "*/*",
        "accept_encoding": "gzip, deflate",
        "accept_language": "en-US",
        "color": "#6c7086",   # dim grey
    },
}


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class BrowserProbeResult:
    """Timing result from a single curl-based probe."""
    browser_name: str = ""
    url: str = ""
    timestamp: datetime = field(default_factory=datetime.now)

    # Curl timing phases (all in milliseconds)
    dns_ms: float = -1
    tcp_connect_ms: float = -1
    tls_handshake_ms: float = -1
    ttfb_ms: float = -1          # time_starttransfer - time_pretransfer
    download_ms: float = -1      # time_total - time_starttransfer
    total_ms: float = -1

    # Response info
    http_code: int = 0
    http_version: str = ""       # "1.1", "2", "3"
    content_length: int = 0      # download size in bytes
    content_type: str = ""
    content_encoding: str = ""
    remote_ip: str = ""
    redirect_count: int = 0
    effective_url: str = ""      # final URL after redirects

    # Computed
    speed_mbps: float = 0.0
    speed_kbps: float = 0.0
    error: str = ""

    def compute_speed(self) -> None:
        """Calculate transfer speed from download phase."""
        if self.download_ms > 0 and self.content_length > 0:
            self.speed_kbps = (self.content_length / 1024) / (self.download_ms / 1000)
            self.speed_mbps = (self.content_length * 8) / (self.download_ms / 1000) / 1_000_000


@dataclass
class BrowserCompareResult:
    """Comparison of the same URL across multiple browser identities."""
    url: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    probes: List[BrowserProbeResult] = field(default_factory=list)
    fastest_browser: str = ""
    slowest_browser: str = ""
    diagnosis: List[str] = field(default_factory=list)

    def analyse(self) -> None:
        """Compare results and produce diagnosis."""
        self.diagnosis = []
        valid = [p for p in self.probes if not p.error and p.total_ms > 0]
        if not valid:
            self.diagnosis.append("FATAL: All probes failed")
            return

        # Find fastest / slowest
        by_total = sorted(valid, key=lambda p: p.total_ms)
        self.fastest_browser = by_total[0].browser_name
        self.slowest_browser = by_total[-1].browser_name

        fastest = by_total[0]
        slowest = by_total[-1]

        self.diagnosis.append(
            f"INFO: Fastest: {fastest.browser_name} at {fastest.total_ms:.0f}ms  |  "
            f"Slowest: {slowest.browser_name} at {slowest.total_ms:.0f}ms"
        )

        # Difference
        diff_ms = slowest.total_ms - fastest.total_ms
        if diff_ms > 500:
            self.diagnosis.append(
                f"WARNING: {diff_ms:.0f}ms difference between fastest and slowest — "
                f"the server may be treating browser identities differently"
            )
        elif diff_ms > 100:
            self.diagnosis.append(
                f"INFO: {diff_ms:.0f}ms variation — minor differences in "
                f"server response by browser identity"
            )
        else:
            self.diagnosis.append(
                f"OK: Only {diff_ms:.0f}ms variation — server treats all "
                f"browsers similarly"
            )

        # Compare content sizes (CDN may serve different content)
        sizes = {p.browser_name: p.content_length for p in valid if p.content_length > 0}
        if sizes:
            min_sz = min(sizes.values())
            max_sz = max(sizes.values())
            if max_sz > 0 and min_sz > 0 and (max_sz / min_sz) > 1.2:
                self.diagnosis.append(
                    f"WARNING: Content size varies by browser — "
                    f"from {min_sz / 1024:.0f} KB to {max_sz / 1024:.0f} KB. "
                    f"CDN may serve different page versions per User-Agent."
                )

        # Compare content encoding
        encodings = {p.browser_name: p.content_encoding for p in valid}
        unique = set(encodings.values())
        if len(unique) > 1:
            detail = ", ".join(f"{b}={e or 'none'}" for b, e in encodings.items())
            self.diagnosis.append(
                f"INFO: Different compression per browser: {detail}"
            )

        # HTTP version info
        versions = {p.browser_name: p.http_version for p in valid}
        version_str = ", ".join(f"{b}=HTTP/{v}" for b, v in versions.items())
        self.diagnosis.append(f"INFO: Protocol versions: {version_str}")

        # Per-phase comparison
        for phase_name, getter in [
            ("DNS", lambda p: p.dns_ms),
            ("TCP", lambda p: p.tcp_connect_ms),
            ("TLS", lambda p: p.tls_handshake_ms),
            ("TTFB", lambda p: p.ttfb_ms),
            ("Download", lambda p: p.download_ms),
        ]:
            vals = [(p.browser_name, getter(p)) for p in valid if getter(p) >= 0]
            if len(vals) >= 2:
                by_val = sorted(vals, key=lambda x: x[1])
                fastest_name, fastest_val = by_val[0]
                slowest_name, slowest_val = by_val[-1]
                if (slowest_val - fastest_val) > 100:
                    self.diagnosis.append(
                        f"INFO: {phase_name} — {fastest_name}: {fastest_val:.0f}ms vs "
                        f"{slowest_name}: {slowest_val:.0f}ms "
                        f"(Δ{slowest_val - fastest_val:.0f}ms)"
                    )

        # Speed comparison
        speeds = [(p.browser_name, p.speed_mbps) for p in valid if p.speed_mbps > 0]
        if speeds:
            by_speed = sorted(speeds, key=lambda x: x[1], reverse=True)
            speed_str = ", ".join(f"{b}: {s:.1f} Mbps" for b, s in by_speed)
            self.diagnosis.append(f"INFO: Download speeds: {speed_str}")

        # Errors
        for p in self.probes:
            if p.error:
                self.diagnosis.append(f"WARNING: {p.browser_name} failed: {p.error}")


@dataclass
class MultiRunSummary:
    """Per-browser averaged results across multiple runs."""
    browser_name: str = ""
    runs: int = 0
    # Averages
    avg_dns_ms: float = 0
    avg_tcp_ms: float = 0
    avg_tls_ms: float = 0
    avg_ttfb_ms: float = 0
    avg_download_ms: float = 0
    avg_total_ms: float = 0
    avg_speed_mbps: float = 0
    # Min / max
    min_total_ms: float = 0
    max_total_ms: float = 0
    # Standard deviation
    stdev_total_ms: float = 0
    # Individual totals for charting
    all_totals: List[float] = field(default_factory=list)
    # Error count
    errors: int = 0


@dataclass
class MultiRunResult:
    """Aggregated result from running compare() N times."""
    url: str = ""
    iterations: int = 0
    timestamp: datetime = field(default_factory=datetime.now)
    summaries: List[MultiRunSummary] = field(default_factory=list)
    all_runs: List[BrowserCompareResult] = field(default_factory=list)
    diagnosis: List[str] = field(default_factory=list)
    cache_cleared: bool = False

    def analyse(self) -> None:
        """Produce diagnosis from aggregated multi-run data."""
        self.diagnosis = []
        valid = [s for s in self.summaries if s.runs > 0]
        if not valid:
            self.diagnosis.append("FATAL: No successful runs")
            return

        self.diagnosis.append(
            f"INFO: {self.iterations} iterations completed "
            f"({'caches cleared before each run' if self.cache_cleared else 'caches NOT cleared — expect warm-cache speedup'})"
        )

        # Find fastest/slowest by average
        by_avg = sorted(valid, key=lambda s: s.avg_total_ms)
        fastest = by_avg[0]
        slowest = by_avg[-1]
        self.diagnosis.append(
            f"INFO: Fastest avg: {fastest.browser_name} at {fastest.avg_total_ms:.0f}ms  |  "
            f"Slowest avg: {slowest.browser_name} at {slowest.avg_total_ms:.0f}ms"
        )

        # Consistency analysis per browser
        for s in valid:
            if s.stdev_total_ms > 100:
                self.diagnosis.append(
                    f"WARNING: {s.browser_name} — high variability "
                    f"(stdev {s.stdev_total_ms:.0f}ms, range {s.min_total_ms:.0f}–{s.max_total_ms:.0f}ms)"
                )
            else:
                self.diagnosis.append(
                    f"OK: {s.browser_name} — consistent "
                    f"(stdev {s.stdev_total_ms:.0f}ms, range {s.min_total_ms:.0f}–{s.max_total_ms:.0f}ms)"
                )

        # Cache effect: compare run 1 vs runs 2+ if caches were NOT cleared
        if not self.cache_cleared and len(self.all_runs) >= 2:
            for s in valid:
                first_runs = [p.total_ms for r in self.all_runs[:1]
                              for p in r.probes
                              if p.browser_name == s.browser_name and not p.error and p.total_ms > 0]
                later_runs = [p.total_ms for r in self.all_runs[1:]
                              for p in r.probes
                              if p.browser_name == s.browser_name and not p.error and p.total_ms > 0]
                if first_runs and later_runs:
                    first_avg = statistics.mean(first_runs)
                    later_avg = statistics.mean(later_runs)
                    diff = first_avg - later_avg
                    if diff > 50:
                        self.diagnosis.append(
                            f"INFO: {s.browser_name} — caching effect: "
                            f"1st run {first_avg:.0f}ms → later avg {later_avg:.0f}ms "
                            f"(Δ{diff:.0f}ms faster due to DNS/TLS/ARP caches)"
                        )

        # Errors
        for s in valid:
            if s.errors > 0:
                self.diagnosis.append(
                    f"WARNING: {s.browser_name} — {s.errors}/{s.runs + s.errors} runs failed"
                )


def clear_network_caches() -> List[str]:
    """Flush DNS, ARP, and NetBIOS caches. Requires elevated privileges for ARP.
    Returns a list of status messages."""
    messages = []
    cmds = [
        (["ipconfig", "/flushdns"], "DNS cache"),
        (["netsh", "interface", "ip", "delete", "arpcache"], "ARP cache"),
        (["nbtstat", "-R"], "NetBIOS cache"),
    ]
    for cmd, label in cmds:
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            if proc.returncode == 0:
                messages.append(f"✓ {label} flushed")
            else:
                messages.append(f"⚠ {label}: {proc.stderr.strip() or 'failed (may need admin)'}")
        except Exception as exc:
            messages.append(f"⚠ {label}: {exc}")
    return messages


# ---------------------------------------------------------------------------
# Curl-based prober
# ---------------------------------------------------------------------------

def find_curl() -> Optional[str]:
    """Locate curl.exe on the system, preferring builds with HTTP/2 support."""
    # Check common locations that might have HTTP/2 (nghttp2) support
    # before falling back to the Windows built-in (which typically lacks it)
    h2_candidates = [
        r"C:\ProgramData\chocolatey\bin\curl.exe",
    ]
    for candidate in h2_candidates:
        if os.path.isfile(candidate):
            return candidate

    path = shutil.which("curl.exe") or shutil.which("curl")
    if path:
        return path
    for candidate in [
        r"C:\Windows\System32\curl.exe",
    ]:
        if os.path.isfile(candidate):
            return candidate
    return None


def _curl_supports_http2(curl_path: str) -> bool:
    """Check if this curl build supports HTTP/2."""
    try:
        out = subprocess.check_output(
            [curl_path, "--version"],
            text=True, timeout=5,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        return "nghttp2" in out.lower()
    except Exception:
        return False


# Curl write-out format: outputs timing + metadata as key=value pairs
# All times in seconds from curl, we convert to ms
_CURL_FORMAT = (
    "dns_time=%{time_namelookup}\\n"
    "connect_time=%{time_connect}\\n"
    "tls_time=%{time_appconnect}\\n"
    "starttransfer=%{time_starttransfer}\\n"
    "total_time=%{time_total}\\n"
    "http_code=%{http_code}\\n"
    "http_version=%{http_version}\\n"
    "size_download=%{size_download}\\n"
    "content_type=%{content_type}\\n"
    "remote_ip=%{remote_ip}\\n"
    "num_redirects=%{num_redirects}\\n"
    "url_effective=%{url_effective}\\n"
)


class BrowserProbeMonitor:
    """Runs curl-based probes simulating different browser identities."""

    def __init__(self) -> None:
        self.curl_path = find_curl()
        self.curl_available = self.curl_path is not None
        self.http2_supported = (
            _curl_supports_http2(self.curl_path) if self.curl_path else False
        )
        self._lock = threading.Lock()
        self._history: List[BrowserCompareResult] = []

    def probe_single(
        self,
        url: str,
        browser_name: str,
        follow_redirects: bool = True,
        timeout: float = 15.0,
        fresh: bool = False,
    ) -> BrowserProbeResult:
        """Probe a URL with a specific browser identity using curl.
        If fresh=True, disables TLS session tickets and connection reuse
        to simulate a cold start."""
        result = BrowserProbeResult(
            browser_name=browser_name, url=url, timestamp=datetime.now()
        )

        if not self.curl_path:
            result.error = "curl.exe not found on system"
            return result

        profile = BROWSER_PROFILES.get(browser_name, BROWSER_PROFILES["Raw (no UA)"])

        cmd = [
            self.curl_path,
            "-s",                     # silent (no progress bar)
            "-o", os.devnull,         # discard body
            "-w", _CURL_FORMAT,       # write-out timing format
            "--connect-timeout", str(int(timeout)),
            "--max-time", str(int(timeout + 5)),
        ]

        # Request HTTP/2 if curl supports it
        if self.http2_supported:
            cmd.append("--http2")

        # Fresh mode: disable TLS session reuse and connection keep-alive
        if fresh:
            cmd.append("--no-sessionid")

        cmd.extend([
            "-A", profile["user_agent"],
            "-H", f"Accept: {profile['accept']}",
            "-H", f"Accept-Encoding: {profile['accept_encoding']}",
            "-H", f"Accept-Language: {profile['accept_language']}",
            "-H", "Connection: close" if fresh else "Connection: keep-alive",
            "-H", f"Sec-Fetch-Dest: document",
            "-H", f"Sec-Fetch-Mode: navigate",
            "-H", f"Sec-Fetch-Site: none",
            "-H", f"Sec-Fetch-User: ?1",
            "-H", "Upgrade-Insecure-Requests: 1",
        ])

        if follow_redirects:
            cmd.extend(["-L", "--max-redirs", "10"])

        cmd.append(url)

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout + 10,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            output = proc.stdout
        except subprocess.TimeoutExpired:
            result.error = f"curl timed out after {timeout}s"
            return result
        except FileNotFoundError:
            result.error = "curl.exe not found"
            return result
        except Exception as exc:
            result.error = f"curl error: {exc}"
            return result

        # Parse curl write-out output
        values = {}
        for line in output.strip().split("\n"):
            if "=" in line:
                key, _, val = line.partition("=")
                values[key.strip()] = val.strip()

        try:
            dns_s = float(values.get("dns_time", 0))
            connect_s = float(values.get("connect_time", 0))
            tls_s = float(values.get("tls_time", 0))
            start_s = float(values.get("starttransfer", 0))
            total_s = float(values.get("total_time", 0))

            result.dns_ms = dns_s * 1000
            result.tcp_connect_ms = (connect_s - dns_s) * 1000
            result.tls_handshake_ms = (tls_s - connect_s) * 1000 if tls_s > 0 else 0
            pretransfer = tls_s if tls_s > 0 else connect_s
            result.ttfb_ms = (start_s - pretransfer) * 1000
            result.download_ms = (total_s - start_s) * 1000
            result.total_ms = total_s * 1000

            result.http_code = int(float(values.get("http_code", 0)))
            # curl http_version: "1.1", "2", "3"
            raw_ver = values.get("http_version", "")
            result.http_version = raw_ver.replace("HTTP/", "") if raw_ver else "?"
            result.content_length = int(float(values.get("size_download", 0)))
            result.content_type = values.get("content_type", "")
            result.remote_ip = values.get("remote_ip", "")
            result.redirect_count = int(float(values.get("num_redirects", 0)))
            result.effective_url = values.get("url_effective", url)

            result.compute_speed()

        except (ValueError, KeyError) as exc:
            result.error = f"Failed to parse curl output: {exc}"
            logger.error("Curl parse error: %s\nOutput: %s", exc, output)

        # Check for curl-level errors
        if result.http_code == 0 and not result.error:
            stderr = proc.stderr.strip() if proc.stderr else "unknown error"
            result.error = f"curl failed: {stderr}"

        return result

    def compare(
        self,
        url: str,
        browsers: Optional[List[str]] = None,
        follow_redirects: bool = True,
        timeout: float = 15.0,
        fresh: bool = False,
    ) -> BrowserCompareResult:
        """
        Probe a URL with multiple browser identities in parallel
        and compare the results.
        """
        if browsers is None:
            browsers = ["Chrome", "Firefox", "Edge", "Raw (no UA)"]

        compare_result = BrowserCompareResult(url=url, timestamp=datetime.now())

        # Run all probes in parallel threads
        results: List[BrowserProbeResult] = []
        lock = threading.Lock()

        def _probe(bname):
            r = self.probe_single(url, bname, follow_redirects, timeout, fresh=fresh)
            with lock:
                results.append(r)

        threads = []
        for bname in browsers:
            t = threading.Thread(target=_probe, args=(bname,), daemon=True)
            t.start()
            threads.append(t)

        for t in threads:
            t.join(timeout=timeout + 15)

        # Sort results in original browser order
        order = {b: i for i, b in enumerate(browsers)}
        results.sort(key=lambda r: order.get(r.browser_name, 999))

        compare_result.probes = results
        compare_result.analyse()

        with self._lock:
            self._history.append(compare_result)
            if len(self._history) > 50:
                self._history = self._history[-50:]

        return compare_result

    def compare_multi(
        self,
        url: str,
        iterations: int = 10,
        browsers: Optional[List[str]] = None,
        follow_redirects: bool = True,
        timeout: float = 15.0,
        clear_caches: bool = False,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> MultiRunResult:
        """
        Run compare() *iterations* times and aggregate averages,
        min, max, stdev per browser.
        """
        multi = MultiRunResult(
            url=url, iterations=iterations,
            timestamp=datetime.now(), cache_cleared=clear_caches,
        )

        for i in range(iterations):
            if clear_caches:
                clear_network_caches()
            result = self.compare(url, browsers=browsers,
                                  follow_redirects=follow_redirects,
                                  timeout=timeout,
                                  fresh=clear_caches)
            multi.all_runs.append(result)
            if progress_callback:
                progress_callback(i + 1, iterations)

        # Aggregate per browser
        browser_data: Dict[str, List[BrowserProbeResult]] = {}
        for run in multi.all_runs:
            for p in run.probes:
                browser_data.setdefault(p.browser_name, []).append(p)

        for bname, probes in browser_data.items():
            valid = [p for p in probes if not p.error and p.total_ms > 0]
            s = MultiRunSummary(browser_name=bname)
            s.runs = len(valid)
            s.errors = len(probes) - len(valid)
            if valid:
                totals = [p.total_ms for p in valid]
                s.all_totals = totals
                s.avg_dns_ms = statistics.mean([p.dns_ms for p in valid])
                s.avg_tcp_ms = statistics.mean([p.tcp_connect_ms for p in valid])
                s.avg_tls_ms = statistics.mean([p.tls_handshake_ms for p in valid])
                s.avg_ttfb_ms = statistics.mean([p.ttfb_ms for p in valid])
                s.avg_download_ms = statistics.mean([p.download_ms for p in valid])
                s.avg_total_ms = statistics.mean(totals)
                s.min_total_ms = min(totals)
                s.max_total_ms = max(totals)
                s.stdev_total_ms = statistics.stdev(totals) if len(totals) >= 2 else 0
                speeds = [p.speed_mbps for p in valid if p.speed_mbps > 0]
                s.avg_speed_mbps = statistics.mean(speeds) if speeds else 0
            multi.summaries.append(s)

        multi.analyse()
        return multi

    @property
    def history(self) -> List[BrowserCompareResult]:
        with self._lock:
            return list(self._history)
