"""
netprobe/process_monitor.py - Per-Process Network I/O Monitor
==============================================================
Uses psutil to track per-process network I/O counters (bytes sent/received,
packets sent/received) and identify processes that are consuming significant
bandwidth or generating unusual network activity.

This module helps answer questions like:
  - "Which process is saturating my connection?"
  - "Is a background process causing network spikes?"
  - "Are there processes with abnormally high packet error rates?"

The monitor takes periodic snapshots of per-process network I/O and
computes deltas (bytes/sec, packets/sec) between snapshots to identify
active network consumers.

Version: 1.0.0

Dependencies:
    - psutil (pip install psutil)
"""

import logging
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Deque, Dict, List, Optional

logger = logging.getLogger("netprobe.process")

# Attempt to import psutil; gracefully degrade if unavailable
try:
    import psutil
    PSUTIL_AVAILABLE = True
    logger.debug("psutil is available — process monitoring enabled")
except ImportError:
    PSUTIL_AVAILABLE = False
    logger.warning(
        "psutil is not installed — process network monitoring disabled. "
        "Install with: pip install psutil"
    )


# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------

@dataclass
class ProcessNetIO:
    """
    Network I/O snapshot for a single process, including computed rates
    (bytes/sec) when compared against a previous snapshot.
    """
    pid: int
    name: str
    bytes_sent: int = 0
    bytes_recv: int = 0
    packets_sent: int = 0
    packets_recv: int = 0
    connections: int = 0          # Number of active network connections
    bytes_sent_per_sec: float = 0.0
    bytes_recv_per_sec: float = 0.0
    packets_sent_per_sec: float = 0.0
    packets_recv_per_sec: float = 0.0


@dataclass
class SystemNetIO:
    """
    System-wide network I/O snapshot with per-interface and aggregate stats.
    """
    timestamp: datetime
    bytes_sent: int = 0
    bytes_recv: int = 0
    packets_sent: int = 0
    packets_recv: int = 0
    errin: int = 0       # Inbound errors
    errout: int = 0      # Outbound errors
    dropin: int = 0      # Inbound drops
    dropout: int = 0     # Outbound drops
    bytes_sent_per_sec: float = 0.0
    bytes_recv_per_sec: float = 0.0


@dataclass
class ProcessSnapshot:
    """
    A point-in-time capture of all process network I/O, plus system-wide
    counters. The top_talkers list is sorted by total bytes/sec descending.
    """
    timestamp: datetime
    system_io: SystemNetIO = field(default_factory=lambda: SystemNetIO(timestamp=datetime.now()))
    top_talkers: List[ProcessNetIO] = field(default_factory=list)
    total_processes_with_net: int = 0


# ---------------------------------------------------------------------------
# Bandwidth formatting helper
# ---------------------------------------------------------------------------

def _format_bytes_rate(bps: float) -> str:
    """
    Convert bytes/sec to a human-readable string (e.g., '1.2 MB/s').
    """
    if bps >= 1_073_741_824:
        return f"{bps / 1_073_741_824:.1f} GB/s"
    elif bps >= 1_048_576:
        return f"{bps / 1_048_576:.1f} MB/s"
    elif bps >= 1024:
        return f"{bps / 1024:.1f} KB/s"
    else:
        return f"{bps:.0f} B/s"


# ---------------------------------------------------------------------------
# Process Network Monitor
# ---------------------------------------------------------------------------

class ProcessMonitor:
    """
    Periodically samples per-process network I/O via psutil and computes
    bandwidth usage rates. Identifies "top talkers" — processes with the
    highest network throughput.

    Usage:
        monitor = ProcessMonitor(interval=5.0)
        monitor.start()
        ...
        snapshot = monitor.get_latest()
        monitor.stop()
    """

    # Number of top-bandwidth processes to track per snapshot
    TOP_N = 15

    def __init__(self, interval: float = 5.0):
        """
        Args:
            interval: Seconds between process network I/O snapshots.
        """
        self.interval = interval
        self._snapshots: Deque[ProcessSnapshot] = deque(maxlen=500)
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

        # Cached previous readings for delta computation
        self._prev_system_io: Optional[dict] = None
        self._prev_process_io: Dict[int, dict] = {}
        self._prev_timestamp: Optional[float] = None

        if PSUTIL_AVAILABLE:
            logger.info("ProcessMonitor initialized — interval=%.1fs", interval)
        else:
            logger.warning("ProcessMonitor — psutil unavailable, monitor will be inactive")

    # ----- Public API -----

    def start(self) -> None:
        """Start the process monitoring loop."""
        if not PSUTIL_AVAILABLE:
            logger.warning("Cannot start ProcessMonitor — psutil not installed")
            return
        if self._thread and self._thread.is_alive():
            logger.warning("ProcessMonitor already running")
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop, daemon=True, name="ProcessMonitor"
        )
        self._thread.start()
        logger.info("ProcessMonitor started")

    def stop(self) -> None:
        """Stop the process monitoring loop."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=10)
            logger.info("ProcessMonitor stopped")

    def get_latest(self) -> Optional[ProcessSnapshot]:
        """Return the most recent process snapshot."""
        with self._lock:
            return self._snapshots[-1] if self._snapshots else None

    def get_history(self) -> List[ProcessSnapshot]:
        """Return all stored snapshots."""
        with self._lock:
            return list(self._snapshots)

    def get_display_table(self) -> str:
        """
        Format a human-readable table of the top network-consuming processes.
        """
        snap = self.get_latest()
        if not snap:
            return "  No process network data collected yet.\n"

        sio = snap.system_io
        lines = [
            f"  System Network I/O at {snap.timestamp.strftime('%H:%M:%S')}",
            f"  Total: ↑ {_format_bytes_rate(sio.bytes_sent_per_sec)} | "
            f"↓ {_format_bytes_rate(sio.bytes_recv_per_sec)}",
            f"  Errors: in={sio.errin} out={sio.errout} | "
            f"Drops: in={sio.dropin} out={sio.dropout}",
            "",
            f"  {'PID':>7}  {'Process':<25} {'↑ Send':>12} {'↓ Recv':>12} {'Conns':>6}",
            "  " + "-" * 70,
        ]

        for proc in snap.top_talkers[:self.TOP_N]:
            lines.append(
                f"  {proc.pid:>7}  {proc.name:<25} "
                f"{_format_bytes_rate(proc.bytes_sent_per_sec):>12} "
                f"{_format_bytes_rate(proc.bytes_recv_per_sec):>12} "
                f"{proc.connections:>6}"
            )

        if not snap.top_talkers:
            lines.append("  (no active network processes detected)")

        return "\n".join(lines) + "\n"

    # ----- Internal -----

    def _run_loop(self) -> None:
        """Main loop: sample, compute deltas, detect anomalies, sleep."""
        while not self._stop_event.is_set():
            try:
                snapshot = self._capture_snapshot()
                if snapshot:
                    self._detect_anomalies(snapshot)
                    with self._lock:
                        self._snapshots.append(snapshot)
                    logger.debug(
                        "Process snapshot: %d network processes, system ↑%.0f B/s ↓%.0f B/s",
                        snapshot.total_processes_with_net,
                        snapshot.system_io.bytes_sent_per_sec,
                        snapshot.system_io.bytes_recv_per_sec,
                    )
            except Exception as exc:
                logger.error("Process monitor error: %s", exc, exc_info=True)

            self._stop_event.wait(self.interval)

    def _capture_snapshot(self) -> Optional[ProcessSnapshot]:
        """
        Capture system-wide and per-process network I/O, compute deltas
        against the previous snapshot to derive rates.
        """
        now = time.monotonic()
        timestamp = datetime.now()

        # ----- System-wide counters -----
        sys_counters = psutil.net_io_counters()
        sys_io = SystemNetIO(
            timestamp=timestamp,
            bytes_sent=sys_counters.bytes_sent,
            bytes_recv=sys_counters.bytes_recv,
            packets_sent=sys_counters.packets_sent,
            packets_recv=sys_counters.packets_recv,
            errin=sys_counters.errin,
            errout=sys_counters.errout,
            dropin=sys_counters.dropin,
            dropout=sys_counters.dropout,
        )

        # Compute system-wide rates if we have a previous reading
        if self._prev_system_io and self._prev_timestamp:
            dt = now - self._prev_timestamp
            if dt > 0:
                sys_io.bytes_sent_per_sec = (
                    sys_counters.bytes_sent - self._prev_system_io["bytes_sent"]
                ) / dt
                sys_io.bytes_recv_per_sec = (
                    sys_counters.bytes_recv - self._prev_system_io["bytes_recv"]
                ) / dt

        # Save current system-wide counters for next delta
        self._prev_system_io = {
            "bytes_sent": sys_counters.bytes_sent,
            "bytes_recv": sys_counters.bytes_recv,
        }

        # ----- Per-process I/O -----
        current_process_io: Dict[int, dict] = {}
        process_results: List[ProcessNetIO] = []

        for proc in psutil.process_iter(attrs=["pid", "name"]):
            try:
                pid = proc.info["pid"]
                pname = proc.info["name"] or f"PID-{pid}"

                # Get per-process I/O counters (may raise AccessDenied)
                try:
                    io = proc.io_counters()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    continue

                # Count active network connections for this process
                try:
                    conns = proc.net_connections(kind="inet")
                    conn_count = len(conns)
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    conn_count = 0

                # Skip processes with zero network activity
                if io.read_bytes == 0 and io.write_bytes == 0 and conn_count == 0:
                    continue

                current_process_io[pid] = {
                    "write_bytes": io.write_bytes,
                    "read_bytes": io.read_bytes,
                    "write_count": io.write_count,
                    "read_count": io.read_count,
                }

                # Compute per-process rates using previous reading
                prev = self._prev_process_io.get(pid)
                if prev and self._prev_timestamp:
                    dt = now - self._prev_timestamp
                    if dt > 0:
                        sent_rate = max(0, (io.write_bytes - prev["write_bytes"])) / dt
                        recv_rate = max(0, (io.read_bytes - prev["read_bytes"])) / dt
                    else:
                        sent_rate = recv_rate = 0.0
                else:
                    sent_rate = recv_rate = 0.0

                proc_entry = ProcessNetIO(
                    pid=pid,
                    name=pname[:25],  # Truncate long names for display
                    bytes_sent=io.write_bytes,
                    bytes_recv=io.read_bytes,
                    packets_sent=io.write_count,
                    packets_recv=io.read_count,
                    connections=conn_count,
                    bytes_sent_per_sec=sent_rate,
                    bytes_recv_per_sec=recv_rate,
                )
                process_results.append(proc_entry)

            except (psutil.NoSuchProcess, psutil.ZombieProcess):
                continue

        # Save current per-process data for next delta computation
        self._prev_process_io = current_process_io
        self._prev_timestamp = now

        # Sort by total bandwidth (send + recv rate) descending
        process_results.sort(
            key=lambda p: p.bytes_sent_per_sec + p.bytes_recv_per_sec,
            reverse=True,
        )

        return ProcessSnapshot(
            timestamp=timestamp,
            system_io=sys_io,
            top_talkers=process_results[:self.TOP_N],
            total_processes_with_net=len(process_results),
        )

    def _detect_anomalies(self, snapshot: ProcessSnapshot) -> None:
        """
        Log warnings for anomalous network I/O conditions such as
        excessive error rates or sudden bandwidth spikes.
        """
        sio = snapshot.system_io

        # Warn if packet errors or drops are non-zero (they should normally be 0)
        if sio.errin > 0 or sio.errout > 0:
            logger.warning(
                "NETWORK ERRORS DETECTED — inbound_errors=%d, outbound_errors=%d. "
                "This may indicate NIC or driver issues.",
                sio.errin, sio.errout,
            )

        if sio.dropin > 0 or sio.dropout > 0:
            logger.warning(
                "PACKET DROPS DETECTED — inbound_drops=%d, outbound_drops=%d. "
                "This may indicate buffer overflows or QoS throttling.",
                sio.dropin, sio.dropout,
            )

        # Flag any single process using > 50 MB/s as potentially anomalous
        for proc in snapshot.top_talkers:
            total_rate = proc.bytes_sent_per_sec + proc.bytes_recv_per_sec
            if total_rate > 50 * 1024 * 1024:  # 50 MB/s
                logger.warning(
                    "HIGH BANDWIDTH PROCESS — PID=%d (%s) using %s total",
                    proc.pid, proc.name,
                    _format_bytes_rate(total_rate),
                )
