"""
netprobe/capture_monitor.py - Wireshark Packet Capture & Analysis
==================================================================
Integrates with Wireshark's CLI tools (tshark / dumpcap) to:

  1. Capture live traffic to a .pcap file
  2. Analyse the capture for common network problems:
     - TCP retransmissions
     - Duplicate ACKs
     - TCP RST floods
     - Zero-window events (receiver buffer full)
     - Out-of-order packets
     - DNS failures (NXDOMAIN, SERVFAIL, timeouts)
     - ICMP unreachables
     - Possible packet loss indicators

The module auto-detects the Wireshark install path, validates that
tshark.exe is available, and runs captures in a background thread
so the GUI stays responsive.

Version: 1.2.0

Dependencies:
  - Wireshark installed (tshark.exe on PATH or in default location)
"""

import logging
import os
import re
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("netprobe.capture")


# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------

@dataclass
class CaptureAnalysis:
    """Results of analysing a pcap file for network problems."""
    pcap_path: str = ""
    capture_duration_sec: float = 0.0
    total_packets: int = 0
    timestamp: datetime = field(default_factory=datetime.now)

    # ----- TCP problems -----
    tcp_retransmissions: int = 0
    tcp_duplicate_acks: int = 0
    tcp_resets: int = 0
    tcp_zero_window: int = 0
    tcp_out_of_order: int = 0
    tcp_window_full: int = 0

    # ----- DNS problems -----
    dns_queries: int = 0
    dns_failures: int = 0          # NXDOMAIN, SERVFAIL, REFUSED
    dns_detail: List[str] = field(default_factory=list)

    # ----- ICMP -----
    icmp_unreachable: int = 0
    icmp_ttl_exceeded: int = 0

    # ----- Computed assessments -----
    problems: List[str] = field(default_factory=list)
    severity: str = "OK"          # "OK", "Warning", "Critical"

    def assess(self) -> None:
        """Run health assessment based on counters."""
        self.problems = []

        if self.total_packets == 0:
            self.severity = "OK"
            self.problems.append("No packets captured — check interface selection")
            return

        # TCP retransmission rate
        if self.tcp_retransmissions > 0:
            pct = (self.tcp_retransmissions / max(self.total_packets, 1)) * 100
            if pct > 5:
                self.problems.append(
                    f"CRITICAL: {self.tcp_retransmissions} TCP retransmissions "
                    f"({pct:.1f}% of traffic) — severe packet loss"
                )
            elif pct > 1:
                self.problems.append(
                    f"WARNING: {self.tcp_retransmissions} TCP retransmissions "
                    f"({pct:.1f}%) — moderate packet loss"
                )
            else:
                self.problems.append(
                    f"INFO: {self.tcp_retransmissions} TCP retransmissions "
                    f"({pct:.1f}%) — minor"
                )

        if self.tcp_duplicate_acks > 50:
            self.problems.append(
                f"WARNING: {self.tcp_duplicate_acks} duplicate ACKs — "
                f"network congestion or out-of-order delivery"
            )

        if self.tcp_resets > 20:
            self.problems.append(
                f"WARNING: {self.tcp_resets} TCP RSTs — "
                f"connection refusals, timeouts, or firewall drops"
            )

        if self.tcp_zero_window > 0:
            self.problems.append(
                f"WARNING: {self.tcp_zero_window} TCP zero-window events — "
                f"receiver buffer full, application not reading fast enough"
            )

        if self.tcp_out_of_order > 10:
            self.problems.append(
                f"INFO: {self.tcp_out_of_order} out-of-order packets — "
                f"multi-path routing or congestion"
            )

        if self.tcp_window_full > 0:
            self.problems.append(
                f"WARNING: {self.tcp_window_full} TCP window-full events — "
                f"sender throttled by slow receiver"
            )

        if self.dns_failures > 0:
            self.problems.append(
                f"WARNING: {self.dns_failures} DNS failures out of "
                f"{self.dns_queries} queries"
            )

        if self.icmp_unreachable > 0:
            self.problems.append(
                f"INFO: {self.icmp_unreachable} ICMP destination unreachable — "
                f"host/port down or blocked"
            )

        if self.icmp_ttl_exceeded > 0:
            self.problems.append(
                f"INFO: {self.icmp_ttl_exceeded} ICMP TTL exceeded — "
                f"routing loops or excessive hops"
            )

        # Overall severity
        if any("CRITICAL" in p for p in self.problems):
            self.severity = "Critical"
        elif any("WARNING" in p for p in self.problems):
            self.severity = "Warning"
        elif self.problems:
            self.severity = "Info"
        else:
            self.problems.append("No significant problems detected")
            self.severity = "OK"


# ---------------------------------------------------------------------------
# Wireshark / tshark Path Detection
# ---------------------------------------------------------------------------

# Standard Wireshark install locations
_WIRESHARK_PATHS = [
    r"C:\Program Files\Wireshark",
    r"C:\Program Files (x86)\Wireshark",
]


def find_tshark() -> Optional[str]:
    """
    Locate tshark.exe on the system.
    Checks PATH first, then common install directories.
    Returns full path to tshark.exe or None.
    """
    # Check PATH
    try:
        result = subprocess.run(
            ["where", "tshark.exe"],
            capture_output=True, text=True, timeout=5,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        if result.returncode == 0:
            path = result.stdout.strip().splitlines()[0]
            if os.path.isfile(path):
                logger.info("Found tshark on PATH: %s", path)
                return path
    except Exception:
        pass

    # Check standard install locations
    for base in _WIRESHARK_PATHS:
        tshark = os.path.join(base, "tshark.exe")
        if os.path.isfile(tshark):
            logger.info("Found tshark at: %s", tshark)
            return tshark

    logger.warning("tshark.exe not found — Wireshark may not be installed")
    return None


def find_dumpcap() -> Optional[str]:
    """Locate dumpcap.exe (lightweight capture tool bundled with Wireshark)."""
    try:
        result = subprocess.run(
            ["where", "dumpcap.exe"],
            capture_output=True, text=True, timeout=5,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        if result.returncode == 0:
            path = result.stdout.strip().splitlines()[0]
            if os.path.isfile(path):
                return path
    except Exception:
        pass

    for base in _WIRESHARK_PATHS:
        dumpcap = os.path.join(base, "dumpcap.exe")
        if os.path.isfile(dumpcap):
            return dumpcap
    return None


def list_interfaces(tshark_path: str) -> List[Tuple[str, str]]:
    """
    List available capture interfaces.
    Returns list of (interface_id, description) tuples.
    """
    interfaces = []
    try:
        result = subprocess.run(
            [tshark_path, "-D"],
            capture_output=True, text=True, timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        for line in result.stdout.strip().splitlines():
            # Format: "1. \Device\NPF_{...} (Ethernet)"
            match = re.match(r"(\d+)\.\s+(.+?)(?:\s+\((.+?)\))?\s*$", line)
            if match:
                iface_id = match.group(1)
                desc = match.group(3) or match.group(2)
                interfaces.append((iface_id, desc))
    except Exception as exc:
        logger.error("Failed to list interfaces: %s", exc)
    return interfaces


# ---------------------------------------------------------------------------
# Capture Monitor
# ---------------------------------------------------------------------------

class CaptureMonitor:
    """
    Manages Wireshark packet captures and analysis.

    Supports two modes:
      1. Live capture: Start tshark, capture for N seconds, then analyse
      2. File analysis: Analyse an existing .pcap file

    Usage:
        monitor = CaptureMonitor()
        if monitor.tshark_available:
            monitor.start_capture(interface="1", duration=30,
                                  callback=on_analysis_done)
        # Or analyse an existing file:
        analysis = monitor.analyse_pcap("capture.pcap")
    """

    def __init__(self):
        self.tshark_path = find_tshark()
        self.dumpcap_path = find_dumpcap()
        self.tshark_available = self.tshark_path is not None

        self._capture_thread: Optional[threading.Thread] = None
        self._capture_process: Optional[subprocess.Popen] = None
        self._capturing = False
        self._lock = threading.Lock()
        self._latest_analysis: Optional[CaptureAnalysis] = None

        # Status text for GUI display
        self.status: str = "Idle"
        self.progress: str = ""

        if self.tshark_available:
            logger.info("CaptureMonitor ready — tshark: %s", self.tshark_path)
        else:
            logger.warning(
                "CaptureMonitor: tshark not found. Install Wireshark to "
                "enable packet capture analysis."
            )

    @property
    def is_capturing(self) -> bool:
        return self._capturing

    def get_interfaces(self) -> List[Tuple[str, str]]:
        """Get available capture interfaces."""
        if not self.tshark_path:
            return []
        return list_interfaces(self.tshark_path)

    def start_capture(
        self,
        interface: str = "1",
        duration: int = 30,
        output_dir: str = "",
        callback: Optional[Callable[[CaptureAnalysis], None]] = None,
        capture_filter: str = "",
    ) -> None:
        """
        Start a live packet capture in a background thread.

        Args:
            interface: Interface ID (from list_interfaces) or name
            duration: Capture duration in seconds
            output_dir: Directory to save pcap file (default: CWD)
            callback: Called with CaptureAnalysis when capture+analysis is done
            capture_filter: BPF filter expression (e.g. 'host 1.2.3.4')
        """
        if self._capturing:
            logger.warning("Capture already in progress")
            return
        if not self.tshark_path:
            logger.error("Cannot capture: tshark not found")
            return

        if not output_dir:
            output_dir = os.getcwd()

        self._capturing = True
        self._capture_thread = threading.Thread(
            target=self._capture_and_analyse,
            args=(interface, duration, output_dir, callback, capture_filter),
            daemon=True,
            name="CaptureMonitor",
        )
        self._capture_thread.start()

    def stop_capture(self) -> None:
        """Stop an in-progress capture early."""
        if self._capture_process:
            try:
                self._capture_process.terminate()
                logger.info("Capture process terminated")
            except Exception:
                pass
        self._capturing = False

    def get_latest_analysis(self) -> Optional[CaptureAnalysis]:
        with self._lock:
            return self._latest_analysis

    def analyse_pcap(self, pcap_path: str) -> CaptureAnalysis:
        """
        Analyse an existing pcap file for network problems.
        This runs synchronously — call from a thread if needed.
        """
        if not self.tshark_path:
            analysis = CaptureAnalysis(pcap_path=pcap_path)
            analysis.problems = ["tshark not available — cannot analyse"]
            analysis.severity = "Unknown"
            return analysis

        self.status = f"Analysing {os.path.basename(pcap_path)}..."
        logger.info("Analysing pcap: %s", pcap_path)

        analysis = CaptureAnalysis(pcap_path=pcap_path, timestamp=datetime.now())

        # Run multiple tshark queries to extract problem indicators
        analysis.total_packets = self._count_packets(pcap_path)
        self._analyse_tcp_problems(pcap_path, analysis)
        self._analyse_dns(pcap_path, analysis)
        self._analyse_icmp(pcap_path, analysis)
        analysis.assess()

        with self._lock:
            self._latest_analysis = analysis

        self.status = "Analysis complete"
        logger.info(
            "Capture analysis: %d packets, severity=%s, %d problems",
            analysis.total_packets, analysis.severity, len(analysis.problems),
        )
        return analysis

    # ----- Internal capture -----

    def _capture_and_analyse(
        self,
        interface: str,
        duration: int,
        output_dir: str,
        callback: Optional[Callable],
        capture_filter: str = "",
    ) -> None:
        """Background thread: capture → analyse → callback."""
        try:
            # Generate unique filename
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            pcap_path = os.path.join(output_dir, f"netprobe_capture_{ts}.pcap")

            self.status = f"Capturing on interface {interface} for {duration}s..."
            self.progress = f"0/{duration}s"
            logger.info(
                "Starting capture: interface=%s, duration=%ds, file=%s",
                interface, duration, pcap_path,
            )

            # Use dumpcap if available (lower overhead), else tshark
            capture_exe = self.dumpcap_path or self.tshark_path
            cmd = [
                capture_exe,
                "-i", interface,
                "-a", f"duration:{duration}",
                "-w", pcap_path,
            ]
            if capture_filter:
                cmd.extend(["-f", capture_filter])

            self._capture_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )

            # Wait for capture to complete, updating progress
            start_time = time.monotonic()
            while self._capture_process.poll() is None and self._capturing:
                elapsed = int(time.monotonic() - start_time)
                self.progress = f"{min(elapsed, duration)}/{duration}s"
                time.sleep(1)

            if self._capture_process.poll() is None:
                self._capture_process.terminate()

            self._capture_process = None

            if not os.path.isfile(pcap_path):
                self.status = "Capture failed — no output file"
                logger.error("Capture produced no output file")
                return

            # Analyse the capture
            analysis = self.analyse_pcap(pcap_path)
            analysis.capture_duration_sec = duration

            if callback:
                callback(analysis)

        except Exception as exc:
            self.status = f"Capture error: {exc}"
            logger.error("Capture failed: %s", exc, exc_info=True)
        finally:
            self._capturing = False
            self._capture_process = None

    # ----- tshark analysis queries -----

    def _count_packets(self, pcap_path: str) -> int:
        """Count total packets in pcap."""
        output = self._run_tshark(pcap_path, ["-q", "-z", "io,stat,0"])
        # Look for the total line in io,stat output
        for line in output.splitlines():
            # Format: "|  0.000 <>   30.000 |     12345 |"
            match = re.search(r"\|\s*[\d.]+\s*<>\s*[\d.]+\s*\|\s*(\d+)", line)
            if match:
                return int(match.group(1))
        # Fallback: count lines from basic tshark read
        output2 = self._run_tshark(pcap_path, ["-T", "fields", "-e", "frame.number"])
        lines = [l for l in output2.strip().splitlines() if l.strip()]
        return len(lines)

    def _analyse_tcp_problems(self, pcap_path: str, analysis: CaptureAnalysis) -> None:
        """Count TCP retransmissions, dup-acks, RSTs, zero-window, OOO."""
        # Use tshark's expert info to count TCP analysis flags
        tcp_checks = {
            "tcp.analysis.retransmission": "tcp_retransmissions",
            "tcp.analysis.duplicate_ack": "tcp_duplicate_acks",
            "tcp.flags.reset == 1": "tcp_resets",
            "tcp.analysis.zero_window": "tcp_zero_window",
            "tcp.analysis.out_of_order": "tcp_out_of_order",
            "tcp.analysis.window_full": "tcp_window_full",
        }

        for display_filter, attr in tcp_checks.items():
            count = self._count_filtered(pcap_path, display_filter)
            setattr(analysis, attr, count)

    def _analyse_dns(self, pcap_path: str, analysis: CaptureAnalysis) -> None:
        """Analyse DNS queries and failures."""
        analysis.dns_queries = self._count_filtered(pcap_path, "dns.flags.response == 0")

        # DNS failures: NXDOMAIN (rcode 3), SERVFAIL (rcode 2), REFUSED (rcode 5)
        analysis.dns_failures = self._count_filtered(
            pcap_path,
            "dns.flags.rcode > 0 and dns.flags.response == 1"
        )

        # Get details of failed DNS queries
        if analysis.dns_failures > 0:
            output = self._run_tshark(
                pcap_path,
                [
                    "-Y", "dns.flags.rcode > 0 and dns.flags.response == 1",
                    "-T", "fields",
                    "-e", "dns.qry.name",
                    "-e", "dns.flags.rcode",
                ],
            )
            seen = set()
            for line in output.strip().splitlines()[:20]:  # Limit detail lines
                parts = line.split("\t")
                if len(parts) >= 2 and parts[0] not in seen:
                    seen.add(parts[0])
                    rcode_map = {"2": "SERVFAIL", "3": "NXDOMAIN", "5": "REFUSED"}
                    rcode = rcode_map.get(parts[1], f"rcode={parts[1]}")
                    analysis.dns_detail.append(f"{parts[0]} → {rcode}")

    def _analyse_icmp(self, pcap_path: str, analysis: CaptureAnalysis) -> None:
        """Count ICMP error messages."""
        analysis.icmp_unreachable = self._count_filtered(
            pcap_path, "icmp.type == 3"
        )
        analysis.icmp_ttl_exceeded = self._count_filtered(
            pcap_path, "icmp.type == 11"
        )

    def _count_filtered(self, pcap_path: str, display_filter: str) -> int:
        """Count packets matching a display filter."""
        output = self._run_tshark(
            pcap_path,
            ["-Y", display_filter, "-T", "fields", "-e", "frame.number"],
        )
        lines = [l for l in output.strip().splitlines() if l.strip()]
        return len(lines)

    def _run_tshark(self, pcap_path: str, extra_args: List[str]) -> str:
        """Run tshark with given arguments on a pcap file."""
        if not self.tshark_path:
            return ""
        cmd = [self.tshark_path, "-r", pcap_path] + extra_args
        try:
            result = subprocess.run(
                cmd,
                capture_output=True, text=True, timeout=60,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            return result.stdout
        except subprocess.TimeoutExpired:
            logger.warning("tshark analysis timed out")
        except Exception as exc:
            logger.error("tshark error: %s", exc)
        return ""
