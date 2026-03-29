"""
NetProbe - Windows Network Latency Monitor
===========================================
A comprehensive network diagnostic tool for Windows that measures latency
over time, performs hop-by-hop traceroute analysis (similar to WinMTR),
monitors connections via netstat, and tracks per-process network activity
to help troubleshoot random network errors and latency spikes.

Version History:
    1.6.0 (2026-03-29) - Browser Compare
        - New Browser Compare tab: probe URLs as Chrome, Firefox, Edge
        - Side-by-side timing comparison with stacked phase bar chart
        - Transfer speed gauges with red/yellow/green ratings
        - Content size and compression comparison across browsers
        - Automatic analysis of per-browser server behavior differences
        - curl.exe based probing (no extra dependencies)
        - Save comparison results for sharing

    1.5.0 (2026-03-27) - Web Probe & URL Load Analyser
        - New Web Probe tab: per-phase URL load timing (DNS, TCP, TLS, TTFB, download)
        - Visual waterfall chart highlighting the bottleneck phase
        - Multi-resolver DNS comparison (System vs Google vs Cloudflare vs Quad9)
        - Automatic diagnosis with severity-rated findings
        - Optional Wireshark capture during probes
        - Probe history table for comparing attempts

    1.4.0 (2026-03-24) - Report Charts & Event Log Correlation
        - Inline SVG latency chart embedded in HTML reports
        - Windows Event Log cross-referencing: queries System & Application
          logs for errors/warnings during the monitoring session
        - Spike-to-event-log correlation (±30 second window) to identify
          system-level causes of latency spikes
        - Correlated events table and full session event log in report

    1.3.0 (2026-03-24) - Copyable Fields & Stability
        - Right-click context menu on all tables: Copy Cell, Copy Row, Copy All
        - Ctrl+C keyboard shortcut copies selected row
        - Fixed PID name resolution showing PID number instead of process name
        - Fixed refresh loop crash resilience (errors no longer kill updates)
        - Process tab reliability improvements

    1.2.0 (2026-03-24) - NIC Health & Wireshark Integration
        - Physical NIC/cable health monitoring via PowerShell
          (CRC errors, link speed, duplex, adapter status)
        - Wireshark/tshark packet capture integration with
          automated analysis of TCP retransmissions, dup ACKs,
          RSTs, zero-window, DNS failures, ICMP errors
        - "Open pcap file" button for offline capture analysis
        - NIC Health tab with error rate tracking and warnings
        - Wireshark tab with capture controls and problem display
        - Auto-detection of Wireshark/tshark install path
        - Cable and NIC degradation warnings

    1.1.0 (2026-03-24) - GUI Release
        - Full tkinter dark-themed graphical dashboard
        - Live scrolling latency chart with spike markers
        - WinMTR-style traceroute hop table in GUI
        - Netstat connection panel with anomaly highlighting
        - Per-process top-talkers table
        - Scrollable spike/anomaly event log
        - Settings panel with save/load config
        - Start/Stop controls and on-demand report generation

    1.0.0 (2026-03-24) - Initial release
        - ICMP ping monitoring with continuous latency tracking
        - Hop-by-hop traceroute with packet loss statistics (WinMTR-style)
        - Netstat connection state monitoring and anomaly detection
        - Per-process network I/O tracking via psutil
        - Spike detection with configurable thresholds
        - CSV and HTML report generation
        - Verbose file and console logging
        - CLI interface with full configuration options

Author: NetProbe Contributors
License: MIT
"""

__version__ = "1.6.0"
__app_name__ = "NetProbe"
