"""
netprobe/ping_monitor.py - ICMP Ping & Traceroute Module
=========================================================
Provides continuous ICMP ping monitoring and hop-by-hop traceroute
analysis similar to WinMTR. Uses the Windows 'ping' and 'tracert'
commands as backends, parsing their output to compute per-hop statistics
including min/avg/max latency, jitter, and packet loss percentage.

Design Decisions:
  - We shell out to 'ping.exe' and 'tracert.exe' rather than requiring
    raw sockets (which need Administrator on Windows) so the tool works
    without elevation for basic monitoring. Raw-socket ICMP is used
    only when psutil/scapy are available AND the process is elevated.
  - All results are timestamped and stored in thread-safe deques for
    the reporter module to consume.

Version: 1.0.0
"""

import logging
import re
import subprocess
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Deque

logger = logging.getLogger("netprobe.ping")


# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------

@dataclass
class PingResult:
    """A single ping measurement to a target."""
    timestamp: datetime
    target: str
    latency_ms: Optional[float]  # None if timed out / unreachable
    ttl: Optional[int]
    packet_size: int = 32
    is_timeout: bool = False
    error_message: str = ""

    @property
    def is_spike(self) -> bool:
        """Quick check used by the reporter (threshold applied externally)."""
        return False  # Determined by caller using config threshold


@dataclass
class HopStats:
    """
    Accumulated statistics for a single traceroute hop, updated across
    multiple traceroute sweeps to build a WinMTR-like rolling view.
    """
    hop_number: int
    ip_address: str = "*"
    hostname: str = "*"
    sent: int = 0
    received: int = 0
    latencies: List[float] = field(default_factory=list)

    @property
    def loss_pct(self) -> float:
        """Packet loss percentage for this hop."""
        if self.sent == 0:
            return 0.0
        return ((self.sent - self.received) / self.sent) * 100.0

    @property
    def avg_ms(self) -> float:
        """Average latency in milliseconds."""
        return sum(self.latencies) / len(self.latencies) if self.latencies else 0.0

    @property
    def min_ms(self) -> float:
        """Minimum observed latency."""
        return min(self.latencies) if self.latencies else 0.0

    @property
    def max_ms(self) -> float:
        """Maximum observed latency."""
        return max(self.latencies) if self.latencies else 0.0

    @property
    def jitter_ms(self) -> float:
        """Jitter = max - min latency (simple measure of variance)."""
        return self.max_ms - self.min_ms

    @property
    def last_ms(self) -> float:
        """Most recent latency sample."""
        return self.latencies[-1] if self.latencies else 0.0


# ---------------------------------------------------------------------------
# Ping Monitor
# ---------------------------------------------------------------------------

class PingMonitor:
    """
    Continuously pings one or more targets and records latency results.
    Results are stored in a thread-safe deque for consumption by the
    reporter. Spike detection is done by comparing against a threshold.

    Usage:
        monitor = PingMonitor(targets=["8.8.8.8"], interval=1.0)
        monitor.start()
        ...
        monitor.stop()
        results = monitor.get_results("8.8.8.8")
    """

    def __init__(
        self,
        targets: List[str],
        interval: float = 1.0,
        timeout: float = 2.0,
        count: int = 1,
        spike_threshold_ms: float = 100.0,
    ):
        """
        Args:
            targets:            List of hostnames or IP addresses to ping.
            interval:           Seconds between ping cycles.
            timeout:            Seconds to wait for each ping reply.
            count:              Number of echo requests per cycle.
            spike_threshold_ms: Latency above this value triggers a spike warning.
        """
        self.targets = targets
        self.interval = interval
        self.timeout = timeout
        self.count = count
        self.spike_threshold_ms = spike_threshold_ms

        # Per-target results stored in bounded deques (keep last 10000 samples)
        self._results: Dict[str, Deque[PingResult]] = {
            t: deque(maxlen=10000) for t in targets
        }
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

        logger.info(
            "PingMonitor initialized — targets=%s, interval=%.1fs, timeout=%.1fs, "
            "spike_threshold=%.1fms",
            targets, interval, timeout, spike_threshold_ms,
        )

    # ----- Public API -----

    def start(self) -> None:
        """Start the ping monitoring loop in a background thread."""
        if self._thread and self._thread.is_alive():
            logger.warning("PingMonitor already running — ignoring start()")
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_loop, daemon=True, name="PingMonitor")
        self._thread.start()
        logger.info("PingMonitor started")

    def stop(self) -> None:
        """Signal the monitoring loop to stop and wait for the thread to exit."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=self.timeout + 2)
            logger.info("PingMonitor stopped")

    def get_results(self, target: str) -> List[PingResult]:
        """Return a snapshot of all stored results for a target (thread-safe)."""
        with self._lock:
            return list(self._results.get(target, []))

    def get_latest(self, target: str) -> Optional[PingResult]:
        """Return the most recent ping result for a target."""
        with self._lock:
            dq = self._results.get(target)
            return dq[-1] if dq else None

    def get_stats(self, target: str) -> Dict:
        """
        Compute summary statistics for a target over the stored window.
        Returns a dict with keys: sent, received, loss_pct, min, avg, max, jitter.
        """
        results = self.get_results(target)
        if not results:
            return {"sent": 0, "received": 0, "loss_pct": 0, "min": 0, "avg": 0, "max": 0, "jitter": 0}

        latencies = [r.latency_ms for r in results if r.latency_ms is not None]
        sent = len(results)
        received = len(latencies)
        loss_pct = ((sent - received) / sent) * 100.0 if sent > 0 else 0.0

        if latencies:
            return {
                "sent": sent,
                "received": received,
                "loss_pct": round(loss_pct, 2),
                "min": round(min(latencies), 2),
                "avg": round(sum(latencies) / len(latencies), 2),
                "max": round(max(latencies), 2),
                "jitter": round(max(latencies) - min(latencies), 2),
            }
        return {"sent": sent, "received": received, "loss_pct": round(loss_pct, 2),
                "min": 0, "avg": 0, "max": 0, "jitter": 0}

    # ----- Internal -----

    def _run_loop(self) -> None:
        """Main monitoring loop — pings all targets, sleeps, repeats."""
        logger.debug("Ping monitoring loop started")
        while not self._stop_event.is_set():
            cycle_start = time.monotonic()
            for target in self.targets:
                if self._stop_event.is_set():
                    break
                result = self._ping_target(target)
                with self._lock:
                    self._results[target].append(result)

                # Log the result with appropriate severity
                if result.is_timeout:
                    logger.warning(
                        "PING TIMEOUT — target=%s | %s",
                        target, result.error_message or "Request timed out",
                    )
                elif result.latency_ms is not None and result.latency_ms > self.spike_threshold_ms:
                    logger.warning(
                        "LATENCY SPIKE — target=%s | latency=%.1fms (threshold=%.1fms)",
                        target, result.latency_ms, self.spike_threshold_ms,
                    )
                else:
                    logger.debug(
                        "PING OK — target=%s | latency=%.1fms | ttl=%s",
                        target, result.latency_ms or 0, result.ttl,
                    )

            # Sleep for the remainder of the interval (subtract elapsed time)
            elapsed = time.monotonic() - cycle_start
            sleep_time = max(0, self.interval - elapsed)
            if sleep_time > 0:
                self._stop_event.wait(sleep_time)

    def _ping_target(self, target: str) -> PingResult:
        """
        Execute a single ping to the target using Windows ping.exe.
        Parses the output to extract latency and TTL values.

        Args:
            target: Hostname or IP address to ping.

        Returns:
            A PingResult with the measured latency or timeout information.
        """
        timestamp = datetime.now()
        try:
            # Windows ping command: -n count, -w timeout (ms), -l packet size
            timeout_ms = int(self.timeout * 1000)
            cmd = ["ping", "-n", str(self.count), "-w", str(timeout_ms), target]
            logger.debug("Executing: %s", " ".join(cmd))

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout + 5,  # Extra buffer for subprocess overhead
                creationflags=subprocess.CREATE_NO_WINDOW,
            )

            output = result.stdout
            logger.debug("Ping output for %s:\n%s", target, output)

            # Parse the average latency from the summary line
            # Example: "Minimum = 10ms, Maximum = 15ms, Average = 12ms"
            avg_match = re.search(r"Average\s*=\s*(\d+)\s*ms", output)
            # Also try to get individual reply latency for single-ping mode
            # Example: "Reply from 8.8.8.8: bytes=32 time=12ms TTL=118"
            reply_match = re.search(
                r"Reply from .+?:\s*bytes=(\d+)\s+time[=<](\d+)\s*ms\s+TTL=(\d+)",
                output,
            )

            if reply_match:
                packet_size = int(reply_match.group(1))
                latency = float(reply_match.group(2))
                ttl = int(reply_match.group(3))
                return PingResult(
                    timestamp=timestamp,
                    target=target,
                    latency_ms=latency,
                    ttl=ttl,
                    packet_size=packet_size,
                )
            elif avg_match:
                latency = float(avg_match.group(1))
                return PingResult(
                    timestamp=timestamp,
                    target=target,
                    latency_ms=latency,
                    ttl=None,
                )
            else:
                # Check for explicit timeout / unreachable messages
                if "Request timed out" in output or "could not find host" in output.lower():
                    return PingResult(
                        timestamp=timestamp,
                        target=target,
                        latency_ms=None,
                        ttl=None,
                        is_timeout=True,
                        error_message=output.strip().split("\n")[-1],
                    )
                # Destination unreachable or other error
                return PingResult(
                    timestamp=timestamp,
                    target=target,
                    latency_ms=None,
                    ttl=None,
                    is_timeout=True,
                    error_message=f"Unexpected ping output: {output[:200]}",
                )

        except subprocess.TimeoutExpired:
            logger.error("Ping subprocess timed out for target=%s", target)
            return PingResult(
                timestamp=timestamp,
                target=target,
                latency_ms=None,
                ttl=None,
                is_timeout=True,
                error_message="Subprocess timed out",
            )
        except FileNotFoundError:
            logger.error("ping.exe not found — is this Windows?")
            return PingResult(
                timestamp=timestamp,
                target=target,
                latency_ms=None,
                ttl=None,
                is_timeout=True,
                error_message="ping.exe not found",
            )
        except Exception as exc:
            logger.error("Unexpected error pinging %s: %s", target, exc, exc_info=True)
            return PingResult(
                timestamp=timestamp,
                target=target,
                latency_ms=None,
                ttl=None,
                is_timeout=True,
                error_message=str(exc),
            )


# ---------------------------------------------------------------------------
# Traceroute Monitor (WinMTR-style rolling statistics)
# ---------------------------------------------------------------------------

class TracerouteMonitor:
    """
    Periodically runs traceroute to each target and accumulates per-hop
    statistics over time, building a WinMTR-like rolling view of the
    network path. Each sweep updates the HopStats for every hop along
    the route.

    Usage:
        tracer = TracerouteMonitor(targets=["8.8.8.8"], interval=30.0)
        tracer.start()
        ...
        hops = tracer.get_hops("8.8.8.8")  # List[HopStats]
        tracer.stop()
    """

    def __init__(
        self,
        targets: List[str],
        interval: float = 30.0,
        max_hops: int = 30,
        timeout: float = 2.0,
    ):
        """
        Args:
            targets:   List of hostnames or IPs to trace.
            interval:  Seconds between traceroute sweeps.
            max_hops:  Maximum TTL (hops) for each trace.
            timeout:   Per-hop timeout in seconds.
        """
        self.targets = targets
        self.interval = interval
        self.max_hops = max_hops
        self.timeout = timeout

        # Per-target, per-hop cumulative stats: {target: {hop_num: HopStats}}
        self._hops: Dict[str, Dict[int, HopStats]] = defaultdict(dict)
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

        logger.info(
            "TracerouteMonitor initialized — targets=%s, interval=%.0fs, max_hops=%d",
            targets, interval, max_hops,
        )

    def start(self) -> None:
        """Start the traceroute sweep loop in a background thread."""
        if self._thread and self._thread.is_alive():
            logger.warning("TracerouteMonitor already running")
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop, daemon=True, name="TracerouteMonitor"
        )
        self._thread.start()
        logger.info("TracerouteMonitor started")

    def stop(self) -> None:
        """Stop the traceroute sweep loop."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=10)
            logger.info("TracerouteMonitor stopped")

    def get_hops(self, target: str) -> List[HopStats]:
        """Return an ordered list of HopStats for a target."""
        with self._lock:
            hops = self._hops.get(target, {})
            return [hops[k] for k in sorted(hops.keys())]

    def get_display_table(self, target: str) -> str:
        """
        Format a WinMTR-style text table for console display.

        Example output:
          Hop  Host              Loss%  Sent  Recv  Avg   Min   Max   Jitter
            1  192.168.1.1        0.0%    10    10  1.2   0.8   2.1      1.3
            2  10.0.0.1           0.0%    10    10  5.4   4.1   8.2      4.1
            3  8.8.8.8            0.0%    10    10 11.3   9.8  14.2      4.4
        """
        hops = self.get_hops(target)
        if not hops:
            return f"  No traceroute data for {target} yet.\n"

        header = (
            f"  {'Hop':>3}  {'Host':<40} {'Loss%':>6}  {'Sent':>5} {'Recv':>5} "
            f"{'Avg':>7} {'Min':>7} {'Max':>7} {'Jitter':>7}"
        )
        lines = [header, "  " + "-" * len(header)]
        for hop in hops:
            host = hop.hostname if hop.hostname != "*" else hop.ip_address
            lines.append(
                f"  {hop.hop_number:>3}  {host:<40} {hop.loss_pct:>5.1f}%  "
                f"{hop.sent:>5} {hop.received:>5} "
                f"{hop.avg_ms:>6.1f} {hop.min_ms:>6.1f} {hop.max_ms:>6.1f} {hop.jitter_ms:>6.1f}"
            )
        return "\n".join(lines) + "\n"

    # ----- Internal -----

    def _run_loop(self) -> None:
        """Periodically trace each target and accumulate hop stats."""
        # Run immediately on start, then at intervals
        while not self._stop_event.is_set():
            for target in self.targets:
                if self._stop_event.is_set():
                    break
                logger.info("Running traceroute to %s ...", target)
                self._trace_target(target)
            # Wait for next sweep
            self._stop_event.wait(self.interval)

    def _trace_target(self, target: str) -> None:
        """
        Execute 'tracert' to the target and parse each hop's latency.
        Updates accumulated HopStats for the target.
        """
        try:
            timeout_ms = int(self.timeout * 1000)
            cmd = ["tracert", "-d", "-w", str(timeout_ms), "-h", str(self.max_hops), target]
            logger.debug("Executing: %s", " ".join(cmd))

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.max_hops * (self.timeout + 1) + 10,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )

            output = result.stdout
            logger.debug("Traceroute output for %s:\n%s", target, output)

            # Parse tracert output line by line
            # Typical line: "  3    12 ms    11 ms    13 ms  10.0.0.1"
            # Timeout hop:  "  4     *        *        *     Request timed out."
            hop_pattern = re.compile(
                r"^\s*(\d+)"                       # Hop number
                r"\s+([<\d]+\s*ms|\*)"             # Probe 1
                r"\s+([<\d]+\s*ms|\*)"             # Probe 2
                r"\s+([<\d]+\s*ms|\*)"             # Probe 3
                r"\s+([\d.]+\S*|Request timed out\.?)" # IP or timeout msg
            )

            for line in output.splitlines():
                match = hop_pattern.match(line)
                if not match:
                    continue

                hop_num = int(match.group(1))
                probes_raw = [match.group(2), match.group(3), match.group(4)]
                ip_or_msg = match.group(5).strip()

                # Determine the IP address for this hop
                ip_addr = "*"
                if re.match(r"^\d+\.\d+\.\d+\.\d+", ip_or_msg):
                    ip_addr = ip_or_msg

                # Parse individual probe latencies
                probe_latencies = []
                for p in probes_raw:
                    p = p.strip()
                    if p == "*":
                        continue
                    # Handle "<1 ms" as 0.5ms and "12 ms" as 12.0ms
                    lat_match = re.match(r"[<]?(\d+)\s*ms", p)
                    if lat_match:
                        val = float(lat_match.group(1))
                        if p.startswith("<"):
                            val = max(0.5, val - 0.5)  # "<1 ms" → 0.5ms
                        probe_latencies.append(val)

                # Update accumulated stats
                with self._lock:
                    if hop_num not in self._hops[target]:
                        self._hops[target][hop_num] = HopStats(hop_number=hop_num)

                    hop = self._hops[target][hop_num]
                    hop.ip_address = ip_addr if ip_addr != "*" else hop.ip_address
                    hop.sent += 3  # 3 probes per tracert hop
                    hop.received += len(probe_latencies)
                    hop.latencies.extend(probe_latencies)

                    # Keep latencies list bounded (last 300 samples)
                    if len(hop.latencies) > 300:
                        hop.latencies = hop.latencies[-300:]

            logger.info("Traceroute to %s completed — %d hops recorded", target, len(self._hops.get(target, {})))

        except subprocess.TimeoutExpired:
            logger.error("Traceroute subprocess timed out for target=%s", target)
        except FileNotFoundError:
            logger.error("tracert.exe not found — is this Windows?")
        except Exception as exc:
            logger.error("Traceroute error for %s: %s", target, exc, exc_info=True)
