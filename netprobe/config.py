"""
netprobe/config.py - Configuration Management
===============================================
Centralizes all tunable parameters for the monitoring tool. Values can be
overridden via CLI arguments or a JSON config file. This module provides
sane defaults that work well for most Windows environments.

Version: 1.0.0
"""

import json
import os
from dataclasses import dataclass, field, asdict
from typing import List


@dataclass
class ProbeConfig:
    """
    Master configuration for all NetProbe subsystems.

    Attributes:
        targets:              List of hostnames/IPs to monitor.
        ping_interval:        Seconds between ping cycles to each target.
        ping_timeout:         Seconds to wait for a ping reply before marking lost.
        ping_count:           Number of ICMP echo requests per cycle (averaged).
        traceroute_max_hops:  Maximum TTL for traceroute hop discovery.
        traceroute_interval:  Seconds between full traceroute sweeps.
        netstat_interval:     Seconds between netstat connection snapshots.
        process_interval:     Seconds between per-process network I/O snapshots.
        spike_threshold_ms:   Latency (ms) above which a reading is flagged as a spike.
        spike_loss_pct:       Packet loss % above which a hop is flagged.
        report_interval:      Seconds between summary reports written to disk.
        report_format:        Output format for periodic reports ("csv", "html", or "both").
        output_dir:           Directory for reports and log files.
        duration:             Total monitoring duration in seconds (0 = infinite).
        verbose:              Enable extra-verbose console output (DEBUG level).
        monitor_processes:    Enable per-process network I/O monitoring.
        monitor_netstat:      Enable netstat connection state tracking.
        monitor_traceroute:   Enable hop-by-hop traceroute analysis.
    """

    # ----- Targets -----
    targets: List[str] = field(default_factory=lambda: ["8.8.8.8", "1.1.1.1"])

    # ----- Ping Settings -----
    ping_interval: float = 1.0
    ping_timeout: float = 2.0
    ping_count: int = 1

    # ----- Traceroute Settings -----
    traceroute_max_hops: int = 30
    traceroute_interval: float = 30.0

    # ----- Netstat Settings -----
    netstat_interval: float = 10.0

    # ----- Process Monitor Settings -----
    process_interval: float = 5.0

    # ----- Spike Detection -----
    spike_threshold_ms: float = 100.0
    spike_loss_pct: float = 5.0

    # ----- Reporting -----
    report_interval: float = 60.0
    report_format: str = "both"
    output_dir: str = "output"

    # ----- Session -----
    duration: float = 0.0  # 0 = run forever until Ctrl+C
    verbose: bool = False

    # ----- Feature Toggles -----
    monitor_processes: bool = True
    monitor_netstat: bool = True
    monitor_traceroute: bool = True

    def save(self, filepath: str) -> None:
        """Serialize the current config to a JSON file for later reuse."""
        os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(asdict(self), f, indent=2)

    @classmethod
    def load(cls, filepath: str) -> "ProbeConfig":
        """
        Load configuration from a JSON file. Unknown keys are silently
        ignored so older config files remain forward-compatible.
        """
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        # Only pass keys that match known fields
        known_keys = {fld for fld in cls.__dataclass_fields__}
        filtered = {k: v for k, v in data.items() if k in known_keys}
        return cls(**filtered)
