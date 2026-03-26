"""
netprobe/netstat_monitor.py - Connection State Monitor
========================================================
Periodically snapshots the system's TCP/UDP connection table using
Windows 'netstat -ano' and tracks changes over time. This helps
detect:

  - Connections stuck in abnormal states (TIME_WAIT floods, SYN_SENT
    buildup, CLOSE_WAIT leaks)
  - Sudden spikes in connection count (possible SYN flood or resource
    exhaustion)
  - Connections to unexpected remote endpoints
  - Port exhaustion (high number of ephemeral port allocations)

All state transitions are logged, and per-state counts are recorded
for the reporter to graph over time.

Version: 1.0.0
"""

import logging
import re
import subprocess
import threading
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Deque, Dict, List, Optional, Tuple

logger = logging.getLogger("netprobe.netstat")


# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------

@dataclass
class ConnectionEntry:
    """Represents a single row from netstat output."""
    protocol: str        # TCP or UDP
    local_address: str   # e.g., "192.168.1.5:443"
    remote_address: str  # e.g., "142.250.80.46:443"
    state: str           # e.g., "ESTABLISHED", "TIME_WAIT", "" for UDP
    pid: int             # Process ID owning the connection


@dataclass
class ConnectionSnapshot:
    """
    A point-in-time snapshot of all network connections, along with
    computed summary metrics useful for anomaly detection.
    """
    timestamp: datetime
    connections: List[ConnectionEntry] = field(default_factory=list)

    # Pre-computed summaries (populated after parsing)
    total_count: int = 0
    state_counts: Dict[str, int] = field(default_factory=dict)
    protocol_counts: Dict[str, int] = field(default_factory=dict)

    def summarize(self) -> None:
        """Compute summary counters from the raw connection list."""
        self.total_count = len(self.connections)
        self.state_counts = dict(Counter(c.state for c in self.connections if c.state))
        self.protocol_counts = dict(Counter(c.protocol for c in self.connections))


# ---------------------------------------------------------------------------
# Anomaly thresholds (configurable defaults)
# ---------------------------------------------------------------------------

# If TIME_WAIT count exceeds this, warn about possible connection churn
TIME_WAIT_WARN_THRESHOLD = 500

# If CLOSE_WAIT count exceeds this, warn about possible socket leak
CLOSE_WAIT_WARN_THRESHOLD = 50

# If SYN_SENT count exceeds this, warn about possible connectivity issues
SYN_SENT_WARN_THRESHOLD = 20

# If total connections jump by more than this % between snapshots, warn
CONNECTION_SPIKE_PCT = 25.0


# ---------------------------------------------------------------------------
# Netstat Monitor
# ---------------------------------------------------------------------------

class NetstatMonitor:
    """
    Periodically captures netstat output, parses it, and logs anomalies.
    Keeps a rolling history of snapshots for trend analysis.

    Usage:
        monitor = NetstatMonitor(interval=10.0)
        monitor.start()
        ...
        snapshot = monitor.get_latest()
        monitor.stop()
    """

    def __init__(self, interval: float = 10.0):
        """
        Args:
            interval: Seconds between netstat snapshots.
        """
        self.interval = interval

        # Rolling history of snapshots (keep last 1000)
        self._snapshots: Deque[ConnectionSnapshot] = deque(maxlen=1000)
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

        logger.info("NetstatMonitor initialized — interval=%.1fs", interval)

    # ----- Public API -----

    def start(self) -> None:
        """Start the netstat monitoring loop in a background thread."""
        if self._thread and self._thread.is_alive():
            logger.warning("NetstatMonitor already running")
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop, daemon=True, name="NetstatMonitor"
        )
        self._thread.start()
        logger.info("NetstatMonitor started")

    def stop(self) -> None:
        """Stop the netstat monitoring loop."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=10)
            logger.info("NetstatMonitor stopped")

    def get_latest(self) -> Optional[ConnectionSnapshot]:
        """Return the most recent connection snapshot."""
        with self._lock:
            return self._snapshots[-1] if self._snapshots else None

    def get_history(self) -> List[ConnectionSnapshot]:
        """Return all stored snapshots."""
        with self._lock:
            return list(self._snapshots)

    def get_state_summary(self) -> str:
        """
        Format a human-readable summary of the latest connection states.
        Useful for console display.
        """
        snap = self.get_latest()
        if not snap:
            return "  No netstat data collected yet.\n"

        lines = [
            f"  Connection Snapshot at {snap.timestamp.strftime('%H:%M:%S')}",
            f"  Total connections: {snap.total_count}",
            f"  By protocol: {snap.protocol_counts}",
            f"  By state:",
        ]
        for state, count in sorted(snap.state_counts.items(), key=lambda x: -x[1]):
            # Highlight problematic states
            marker = ""
            if state == "TIME_WAIT" and count > TIME_WAIT_WARN_THRESHOLD:
                marker = " ⚠ HIGH"
            elif state == "CLOSE_WAIT" and count > CLOSE_WAIT_WARN_THRESHOLD:
                marker = " ⚠ LEAK?"
            elif state == "SYN_SENT" and count > SYN_SENT_WARN_THRESHOLD:
                marker = " ⚠ STALLED"
            lines.append(f"    {state:<20} {count:>6}{marker}")

        return "\n".join(lines) + "\n"

    # ----- Internal -----

    def _run_loop(self) -> None:
        """Main loop: capture, parse, analyze, sleep, repeat."""
        while not self._stop_event.is_set():
            snapshot = self._capture_netstat()
            if snapshot:
                snapshot.summarize()
                self._detect_anomalies(snapshot)
                with self._lock:
                    self._snapshots.append(snapshot)
                logger.debug(
                    "Netstat snapshot: %d connections — states=%s",
                    snapshot.total_count, snapshot.state_counts,
                )
            self._stop_event.wait(self.interval)

    def _capture_netstat(self) -> Optional[ConnectionSnapshot]:
        """
        Run 'netstat -ano' and parse the output into a ConnectionSnapshot.

        Returns:
            A ConnectionSnapshot, or None if the command failed.
        """
        timestamp = datetime.now()
        try:
            cmd = ["netstat", "-ano"]
            logger.debug("Executing: %s", " ".join(cmd))

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )

            output = result.stdout
            connections = self._parse_netstat_output(output)

            return ConnectionSnapshot(
                timestamp=timestamp,
                connections=connections,
            )

        except subprocess.TimeoutExpired:
            logger.error("netstat command timed out")
        except FileNotFoundError:
            logger.error("netstat.exe not found")
        except Exception as exc:
            logger.error("netstat error: %s", exc, exc_info=True)
        return None

    def _parse_netstat_output(self, output: str) -> List[ConnectionEntry]:
        """
        Parse the text output of 'netstat -ano' into ConnectionEntry objects.

        Expected format (after header lines):
          TCP    192.168.1.5:49732    142.250.80.46:443    ESTABLISHED     1234
          UDP    0.0.0.0:5353         *:*                                  5678

        Returns:
            List of parsed ConnectionEntry objects.
        """
        entries = []
        # Regex to match TCP and UDP lines from netstat -ano
        # TCP lines have a state field; UDP lines do not
        pattern = re.compile(
            r"^\s*(TCP|UDP)\s+"        # Protocol
            r"(\S+)\s+"               # Local address
            r"(\S+)\s+"              # Foreign address
            r"(\S+)?\s+"             # State (optional for UDP)
            r"(\d+)\s*$",            # PID
            re.MULTILINE,
        )

        for match in pattern.finditer(output):
            protocol = match.group(1)
            local_addr = match.group(2)
            remote_addr = match.group(3)
            state_or_pid = match.group(4) or ""
            pid_str = match.group(5)

            # For UDP entries, the "state" capture group may actually be the PID
            # because UDP has no state. We handle this by checking if state_or_pid
            # looks like a known TCP state.
            known_states = {
                "LISTENING", "ESTABLISHED", "TIME_WAIT", "CLOSE_WAIT",
                "FIN_WAIT_1", "FIN_WAIT_2", "SYN_SENT", "SYN_RECEIVED",
                "LAST_ACK", "CLOSING", "BOUND",
            }

            if state_or_pid in known_states:
                state = state_or_pid
                pid = int(pid_str)
            else:
                state = ""
                # The PID might have been captured as state_or_pid
                try:
                    pid = int(pid_str)
                except ValueError:
                    pid = 0

            entries.append(ConnectionEntry(
                protocol=protocol,
                local_address=local_addr,
                remote_address=remote_addr,
                state=state,
                pid=pid,
            ))

        logger.debug("Parsed %d connections from netstat output", len(entries))
        return entries

    def _detect_anomalies(self, snapshot: ConnectionSnapshot) -> None:
        """
        Analyze a snapshot for anomalous conditions and log warnings.
        Compares against the previous snapshot for trend detection.
        """
        states = snapshot.state_counts

        # Check for excessive TIME_WAIT connections (connection churn)
        tw_count = states.get("TIME_WAIT", 0)
        if tw_count > TIME_WAIT_WARN_THRESHOLD:
            logger.warning(
                "NETSTAT ANOMALY — %d TIME_WAIT connections (threshold: %d). "
                "Possible connection churn or port exhaustion.",
                tw_count, TIME_WAIT_WARN_THRESHOLD,
            )

        # Check for CLOSE_WAIT accumulation (socket leak indicator)
        cw_count = states.get("CLOSE_WAIT", 0)
        if cw_count > CLOSE_WAIT_WARN_THRESHOLD:
            logger.warning(
                "NETSTAT ANOMALY — %d CLOSE_WAIT connections (threshold: %d). "
                "Possible socket leak in an application.",
                cw_count, CLOSE_WAIT_WARN_THRESHOLD,
            )

        # Check for stalled outbound connections
        ss_count = states.get("SYN_SENT", 0)
        if ss_count > SYN_SENT_WARN_THRESHOLD:
            logger.warning(
                "NETSTAT ANOMALY — %d SYN_SENT connections (threshold: %d). "
                "Possible firewall blocking or remote host unreachable.",
                ss_count, SYN_SENT_WARN_THRESHOLD,
            )

        # Check for sudden connection count spike vs previous snapshot
        with self._lock:
            if len(self._snapshots) >= 2:
                prev = self._snapshots[-1]  # Most recent already stored
                if prev.total_count > 0:
                    change_pct = (
                        (snapshot.total_count - prev.total_count)
                        / prev.total_count
                    ) * 100.0
                    if abs(change_pct) > CONNECTION_SPIKE_PCT:
                        logger.warning(
                            "NETSTAT ANOMALY — Connection count changed by %.1f%% "
                            "(%d → %d) in %.0f seconds.",
                            change_pct, prev.total_count, snapshot.total_count,
                            self.interval,
                        )
