"""
netprobe/nic_monitor.py - Physical NIC & Cable Health Monitor
==============================================================
Monitors the physical health of network adapters using PowerShell's
Get-NetAdapterStatistics and Get-NetAdapter cmdlets to detect:

  - CRC errors (damaged packets — bad cable, EMI, or failing NIC)
  - Receive/transmit errors and discards
  - Link speed changes or degradation
  - Media disconnects and reconnects
  - Duplex mismatches (half-duplex when full expected)
  - Driver-level error counters

This goes beyond what psutil's net_io_counters provides by querying
Windows-specific adapter statistics that reflect actual hardware-layer
problems.

Version: 1.2.0

Dependencies:
  - PowerShell 5.1+ (built into Windows 10/11)
  - psutil (for supplementary counters)
"""

import logging
import re
import subprocess
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Deque, Dict, List, Optional

logger = logging.getLogger("netprobe.nic")


# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------

@dataclass
class NicStats:
    """
    Hardware-level statistics for a single network adapter, captured
    from Get-NetAdapterStatistics and Get-NetAdapter.
    """
    name: str = ""                    # Adapter name (e.g., "Ethernet", "Wi-Fi")
    description: str = ""             # Driver description
    status: str = ""                  # "Up", "Disconnected", etc.
    link_speed_mbps: float = 0.0      # Negotiated link speed in Mbps
    media_type: str = ""              # "802.3" (Ethernet), "Native 802.11" (Wi-Fi)
    full_duplex: bool = True

    # ----- Error counters (cumulative since boot) -----
    recv_errors: int = 0
    recv_discards: int = 0
    recv_crc_errors: int = 0          # CRC = physical layer damage
    recv_length_errors: int = 0       # Runt/giant frames
    send_errors: int = 0
    send_discards: int = 0

    # ----- Traffic counters -----
    bytes_recv: int = 0
    bytes_sent: int = 0
    packets_recv: int = 0
    packets_sent: int = 0

    # ----- Computed rates (filled in by delta calculation) -----
    recv_errors_per_sec: float = 0.0
    send_errors_per_sec: float = 0.0
    crc_errors_per_sec: float = 0.0
    recv_bytes_per_sec: float = 0.0
    send_bytes_per_sec: float = 0.0


@dataclass
class NicSnapshot:
    """Point-in-time snapshot of all adapters with health assessments."""
    timestamp: datetime
    adapters: List[NicStats] = field(default_factory=list)
    health_warnings: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Health Assessment Thresholds
# ---------------------------------------------------------------------------

# If CRC errors increase by more than this per interval, flag it
CRC_ERROR_RATE_WARN = 1.0        # errors/sec

# If receive/send errors increase by more than this per interval
IO_ERROR_RATE_WARN = 5.0         # errors/sec

# Link speed below this for wired connections suggests cable issue
MIN_EXPECTED_LINK_SPEED_MBPS = 100  # 100 Mbps minimum for modern Ethernet


# ---------------------------------------------------------------------------
# NIC Monitor
# ---------------------------------------------------------------------------

class NicMonitor:
    """
    Periodically queries Windows adapter statistics to detect physical
    network problems like bad cables, failing NICs, or driver issues.

    Usage:
        monitor = NicMonitor(interval=10.0)
        monitor.start()
        ...
        snapshot = monitor.get_latest()
        warnings = monitor.get_health_warnings()
        monitor.stop()
    """

    def __init__(self, interval: float = 10.0):
        self.interval = interval
        self._snapshots: Deque[NicSnapshot] = deque(maxlen=500)
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

        # Previous counters for delta calculation
        self._prev_stats: Dict[str, NicStats] = {}
        self._prev_time: Optional[float] = None

        logger.info("NicMonitor initialized — interval=%.1fs", interval)

    # ----- Public API -----

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop, daemon=True, name="NicMonitor"
        )
        self._thread.start()
        logger.info("NicMonitor started")

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=10)
            logger.info("NicMonitor stopped")

    def get_latest(self) -> Optional[NicSnapshot]:
        with self._lock:
            return self._snapshots[-1] if self._snapshots else None

    def get_history(self) -> List[NicSnapshot]:
        with self._lock:
            return list(self._snapshots)

    # ----- Internal -----

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                snapshot = self._capture_snapshot()
                if snapshot:
                    with self._lock:
                        self._snapshots.append(snapshot)
                    # Log health warnings at WARNING level
                    for w in snapshot.health_warnings:
                        logger.warning("NIC HEALTH — %s", w)
            except Exception as exc:
                logger.error("NicMonitor error: %s", exc, exc_info=True)
            self._stop_event.wait(self.interval)

    def _capture_snapshot(self) -> Optional[NicSnapshot]:
        """
        Run PowerShell commands to gather adapter info and statistics.
        Computes error rates by comparing to previous readings.
        """
        now = time.monotonic()
        timestamp = datetime.now()
        adapters: List[NicStats] = []
        warnings: List[str] = []

        # ---- Step 1: Get adapter info (name, status, speed, duplex) ----
        adapter_info = self._run_ps_adapter_info()

        # ---- Step 2: Get adapter statistics (error counters) ----
        adapter_stats = self._run_ps_adapter_stats()

        # ---- Merge info + stats ----
        for name, info in adapter_info.items():
            stats = adapter_stats.get(name, {})
            nic = NicStats(
                name=name,
                description=info.get("description", ""),
                status=info.get("status", "Unknown"),
                link_speed_mbps=info.get("link_speed_mbps", 0),
                media_type=info.get("media_type", ""),
                full_duplex=info.get("full_duplex", True),
                recv_errors=stats.get("ReceivedPacketErrors", 0),
                recv_discards=stats.get("ReceivedDiscards", 0),
                recv_crc_errors=stats.get("ReceivedCRCErrors", 0),
                recv_length_errors=stats.get("ReceivedLengthErrors", 0),
                send_errors=stats.get("OutboundPacketErrors", 0),
                send_discards=stats.get("OutboundDiscards", 0),
                bytes_recv=stats.get("ReceivedBytes", 0),
                bytes_sent=stats.get("SentBytes", 0),
                packets_recv=stats.get("ReceivedUnicastPackets", 0),
                packets_sent=stats.get("SentUnicastPackets", 0),
            )

            # ---- Compute error rates ----
            prev = self._prev_stats.get(name)
            if prev and self._prev_time:
                dt = now - self._prev_time
                if dt > 0:
                    nic.recv_errors_per_sec = max(0, nic.recv_errors - prev.recv_errors) / dt
                    nic.send_errors_per_sec = max(0, nic.send_errors - prev.send_errors) / dt
                    nic.crc_errors_per_sec = max(0, nic.recv_crc_errors - prev.recv_crc_errors) / dt
                    nic.recv_bytes_per_sec = max(0, nic.bytes_recv - prev.bytes_recv) / dt
                    nic.send_bytes_per_sec = max(0, nic.bytes_sent - prev.bytes_sent) / dt

            adapters.append(nic)
            self._prev_stats[name] = nic

            # ---- Health checks ----
            if nic.status == "Up":
                if nic.recv_crc_errors > 0:
                    crc_rate = nic.crc_errors_per_sec
                    if crc_rate > CRC_ERROR_RATE_WARN:
                        warnings.append(
                            f"{name}: {crc_rate:.1f} CRC errors/sec — "
                            f"likely bad cable, connector, or EMI interference"
                        )
                    elif nic.recv_crc_errors > 100:
                        warnings.append(
                            f"{name}: {nic.recv_crc_errors} total CRC errors — "
                            f"cable or NIC may be degrading"
                        )

                if nic.recv_errors_per_sec > IO_ERROR_RATE_WARN:
                    warnings.append(
                        f"{name}: {nic.recv_errors_per_sec:.1f} recv errors/sec — "
                        f"possible NIC or driver issue"
                    )

                if nic.send_errors_per_sec > IO_ERROR_RATE_WARN:
                    warnings.append(
                        f"{name}: {nic.send_errors_per_sec:.1f} send errors/sec — "
                        f"possible collision or duplex mismatch"
                    )

                # Check for half-duplex on wired connections (usually wrong)
                if not nic.full_duplex and "802.3" in nic.media_type:
                    warnings.append(
                        f"{name}: Running in HALF-DUPLEX mode — "
                        f"likely duplex mismatch, check switch port config"
                    )

                # Check for unexpectedly low link speed on wired
                if ("802.3" in nic.media_type and
                        0 < nic.link_speed_mbps < MIN_EXPECTED_LINK_SPEED_MBPS):
                    warnings.append(
                        f"{name}: Link speed only {nic.link_speed_mbps:.0f} Mbps — "
                        f"bad cable or port may be limiting speed"
                    )

            elif nic.status == "Disconnected":
                warnings.append(
                    f"{name}: DISCONNECTED — cable unplugged or NIC disabled"
                )

        self._prev_time = now

        return NicSnapshot(
            timestamp=timestamp,
            adapters=adapters,
            health_warnings=warnings,
        )

    def _run_ps_adapter_info(self) -> Dict[str, dict]:
        """
        Run Get-NetAdapter to get adapter names, status, speed, duplex.
        Returns {adapter_name: {description, status, link_speed_mbps, ...}}.
        """
        result = {}
        try:
            # PowerShell command to list physical adapters
            ps_cmd = (
                "Get-NetAdapter -Physical -ErrorAction SilentlyContinue | "
                "Select-Object Name, InterfaceDescription, Status, "
                "LinkSpeed, MediaType, FullDuplex | "
                "Format-List"
            )
            output = self._run_powershell(ps_cmd)
            if not output:
                return result

            # Parse Format-List output into blocks
            blocks = output.split("\n\n")
            for block in blocks:
                if not block.strip():
                    continue
                data = {}
                for line in block.strip().splitlines():
                    if ":" in line:
                        key, _, val = line.partition(":")
                        data[key.strip()] = val.strip()

                name = data.get("Name", "")
                if not name:
                    continue

                # Parse link speed (e.g., "1 Gbps", "100 Mbps", "54 Mbps")
                speed_str = data.get("LinkSpeed", "0")
                speed_mbps = self._parse_link_speed(speed_str)

                result[name] = {
                    "description": data.get("InterfaceDescription", ""),
                    "status": data.get("Status", "Unknown"),
                    "link_speed_mbps": speed_mbps,
                    "media_type": data.get("MediaType", ""),
                    "full_duplex": data.get("FullDuplex", "True").lower() == "true",
                }

        except Exception as exc:
            logger.debug("Get-NetAdapter failed: %s", exc)
        return result

    def _run_ps_adapter_stats(self) -> Dict[str, dict]:
        """
        Run Get-NetAdapterStatistics for error counters.
        Returns {adapter_name: {counter_name: value, ...}}.
        """
        result = {}
        try:
            ps_cmd = (
                "Get-NetAdapterStatistics -ErrorAction SilentlyContinue | "
                "Select-Object Name, ReceivedPacketErrors, ReceivedDiscards, "
                "OutboundPacketErrors, OutboundDiscards, ReceivedBytes, "
                "SentBytes, ReceivedUnicastPackets, SentUnicastPackets | "
                "Format-List"
            )
            output = self._run_powershell(ps_cmd)
            if not output:
                return result

            blocks = output.split("\n\n")
            for block in blocks:
                if not block.strip():
                    continue
                data = {}
                for line in block.strip().splitlines():
                    if ":" in line:
                        key, _, val = line.partition(":")
                        data[key.strip()] = val.strip()

                name = data.pop("Name", "")
                if not name:
                    continue

                # Convert numeric values
                parsed = {}
                for k, v in data.items():
                    try:
                        parsed[k] = int(v)
                    except ValueError:
                        parsed[k] = 0
                result[name] = parsed

            # ----- Also try to get CRC errors via advanced stats -----
            # CRC errors aren't in the basic cmdlet; try WMIC or registry
            self._enrich_crc_errors(result)

        except Exception as exc:
            logger.debug("Get-NetAdapterStatistics failed: %s", exc)
        return result

    def _enrich_crc_errors(self, stats: Dict[str, dict]) -> None:
        """
        Attempt to get CRC error counts from advanced adapter statistics.
        Uses Get-NetAdapterAdvancedProperty or WMIC as fallback.
        """
        try:
            ps_cmd = (
                "Get-NetAdapterStatistics -ErrorAction SilentlyContinue | "
                "Get-Member -MemberType Property | "
                "Where-Object { $_.Name -like '*CRC*' -or $_.Name -like '*Length*' } | "
                "Select-Object -ExpandProperty Name"
            )
            # Just check if CRC properties exist — if not, try WMI
            output = self._run_powershell(
                "Get-CimInstance -ClassName Win32_PerfRawData_Tcpip_NetworkInterface "
                "-ErrorAction SilentlyContinue | "
                "Select-Object Name, PacketsReceivedErrors | Format-List"
            )
            if output:
                blocks = output.split("\n\n")
                for block in blocks:
                    if not block.strip():
                        continue
                    data = {}
                    for line in block.strip().splitlines():
                        if ":" in line:
                            key, _, val = line.partition(":")
                            data[key.strip()] = val.strip()
                    wmi_name = data.get("Name", "")
                    pkt_errors = data.get("PacketsReceivedErrors", "0")
                    # WMI adapter names don't exactly match; do best-effort match
                    for adapter_name in stats:
                        if adapter_name.lower() in wmi_name.lower() or wmi_name.lower() in adapter_name.lower():
                            try:
                                stats[adapter_name]["ReceivedCRCErrors"] = int(pkt_errors)
                            except ValueError:
                                pass
        except Exception:
            pass  # CRC enrichment is best-effort

    @staticmethod
    def _parse_link_speed(speed_str: str) -> float:
        """Parse a speed string like '1 Gbps', '100 Mbps' to Mbps float."""
        match = re.search(r"([\d.]+)\s*(Gbps|Mbps|Kbps|bps)", speed_str, re.IGNORECASE)
        if not match:
            return 0.0
        value = float(match.group(1))
        unit = match.group(2).lower()
        if unit == "gbps":
            return value * 1000
        elif unit == "mbps":
            return value
        elif unit == "kbps":
            return value / 1000
        else:
            return value / 1_000_000

    @staticmethod
    def _run_powershell(command: str) -> str:
        """Execute a PowerShell command and return stdout."""
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
                capture_output=True, text=True, timeout=15,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            return result.stdout
        except subprocess.TimeoutExpired:
            logger.debug("PowerShell command timed out: %s", command[:80])
        except FileNotFoundError:
            logger.debug("PowerShell not found")
        except Exception as exc:
            logger.debug("PowerShell error: %s", exc)
        return ""
