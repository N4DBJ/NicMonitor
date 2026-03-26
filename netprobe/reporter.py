"""
netprobe/reporter.py - Reporting & Spike Detection Module
==========================================================
Aggregates data from all monitoring subsystems (ping, traceroute, netstat,
process monitor) and produces periodic reports in CSV and HTML formats.
Also provides real-time console summary rendering with spike detection.

Report contents:
  - Ping latency time-series with spike annotations
  - Hop-by-hop traceroute statistics (WinMTR-style table)
  - Connection state distribution over time
  - Top bandwidth-consuming processes
  - Detected anomalies and warnings timeline

Version: 1.0.0
"""

import csv
import json
import logging
import os
import subprocess
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from netprobe.ping_monitor import PingMonitor, TracerouteMonitor, PingResult
from netprobe.netstat_monitor import NetstatMonitor
from netprobe.process_monitor import ProcessMonitor, PSUTIL_AVAILABLE
from netprobe.config import ProbeConfig

logger = logging.getLogger("netprobe.reporter")


# ---------------------------------------------------------------------------
# Spike event log
# ---------------------------------------------------------------------------

class SpikeEvent:
    """Records a detected spike or anomaly for the timeline report."""

    def __init__(self, timestamp: datetime, category: str, message: str, severity: str = "WARNING"):
        self.timestamp = timestamp
        self.category = category   # "ping", "traceroute", "netstat", "process"
        self.message = message
        self.severity = severity   # "INFO", "WARNING", "CRITICAL"

    def __repr__(self) -> str:
        return (
            f"[{self.timestamp.strftime('%H:%M:%S')}] "
            f"{self.severity} [{self.category}] {self.message}"
        )


# ---------------------------------------------------------------------------
# Reporter
# ---------------------------------------------------------------------------

class Reporter:
    """
    Periodically generates summary reports from all monitoring subsystems.
    Detects latency spikes and anomalies, writes CSV/HTML output files.

    Usage:
        reporter = Reporter(config, ping_mon, trace_mon, netstat_mon, proc_mon)
        reporter.start()
        ...
        reporter.stop()
        reporter.write_final_report()
    """

    def __init__(
        self,
        config: ProbeConfig,
        ping_monitor: PingMonitor,
        traceroute_monitor: Optional[TracerouteMonitor],
        netstat_monitor: Optional[NetstatMonitor],
        process_monitor: Optional[ProcessMonitor],
        capture_analyses: Optional[List] = None,
    ):
        self.config = config
        self.ping_monitor = ping_monitor
        self.traceroute_monitor = traceroute_monitor
        self.netstat_monitor = netstat_monitor
        self.process_monitor = process_monitor
        # Shared list — GUI appends to this as captures are done
        self.capture_analyses: List = capture_analyses if capture_analyses is not None else []

        # Collected spike events for the timeline
        self.spike_events: List[SpikeEvent] = []
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._csv_initialized = False

        # Ensure output directory exists
        os.makedirs(config.output_dir, exist_ok=True)

        # Session timestamp for filenames
        self._session_ts = datetime.now().strftime("%Y%m%d_%H%M%S")

        logger.info(
            "Reporter initialized — output_dir=%s, report_interval=%.0fs, format=%s",
            config.output_dir, config.report_interval, config.report_format,
        )

    # ----- Public API -----

    def start(self) -> None:
        """Start the periodic reporting loop."""
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop, daemon=True, name="Reporter"
        )
        self._thread.start()
        logger.info("Reporter started — writing reports every %.0fs", self.config.report_interval)

    def stop(self) -> None:
        """Stop the reporting loop."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=10)
            logger.info("Reporter stopped")

    def record_spike(self, category: str, message: str, severity: str = "WARNING") -> None:
        """Manually record a spike event (called by monitoring threads)."""
        event = SpikeEvent(datetime.now(), category, message, severity)
        with self._lock:
            self.spike_events.append(event)
        logger.debug("Spike recorded: %s", event)

    def get_console_summary(self) -> str:
        """
        Build a comprehensive console summary string combining data from
        all active monitoring subsystems. This is displayed periodically
        in the main loop.
        """
        lines = []
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        lines.append("")
        lines.append("=" * 80)
        lines.append(f"  NETPROBE MONITOR — {now}")
        lines.append("=" * 80)

        # ----- Ping Summary -----
        lines.append("")
        lines.append("  [PING LATENCY]")
        lines.append("  " + "-" * 76)
        for target in self.config.targets:
            stats = self.ping_monitor.get_stats(target)
            latest = self.ping_monitor.get_latest(target)
            latest_ms = f"{latest.latency_ms:.1f}ms" if latest and latest.latency_ms else "TIMEOUT"
            lines.append(
                f"  {target:<20} | Last: {latest_ms:<10} | "
                f"Avg: {stats['avg']:.1f}ms | Min: {stats['min']:.1f}ms | "
                f"Max: {stats['max']:.1f}ms | Loss: {stats['loss_pct']:.1f}% | "
                f"Jitter: {stats['jitter']:.1f}ms  ({stats['sent']} sent)"
            )

        # ----- Traceroute Summary -----
        if self.traceroute_monitor:
            lines.append("")
            lines.append("  [TRACEROUTE — WinMTR-style]")
            lines.append("  " + "-" * 76)
            for target in self.config.targets:
                lines.append(f"  Route to {target}:")
                lines.append(self.traceroute_monitor.get_display_table(target))

        # ----- Netstat Summary -----
        if self.netstat_monitor:
            lines.append("")
            lines.append("  [CONNECTION STATES]")
            lines.append("  " + "-" * 76)
            lines.append(self.netstat_monitor.get_state_summary())

        # ----- Process Summary -----
        if self.process_monitor and PSUTIL_AVAILABLE:
            lines.append("")
            lines.append("  [TOP NETWORK PROCESSES]")
            lines.append("  " + "-" * 76)
            lines.append(self.process_monitor.get_display_table())

        # ----- Recent Spikes -----
        with self._lock:
            recent_spikes = self.spike_events[-10:]  # Last 10 events
        if recent_spikes:
            lines.append("")
            lines.append("  [RECENT ANOMALIES]")
            lines.append("  " + "-" * 76)
            for spike in recent_spikes:
                lines.append(f"  {spike}")

        lines.append("")
        lines.append("=" * 80)
        lines.append("  Press Ctrl+C to stop monitoring and generate final report.")
        lines.append("=" * 80)
        lines.append("")

        return "\n".join(lines)

    def write_final_report(self) -> None:
        """
        Generate the final summary reports at the end of the monitoring
        session. Writes both CSV and HTML based on the config format.
        """
        logger.info("Generating final report...")

        fmt = self.config.report_format.lower()
        if fmt in ("csv", "both"):
            self._write_csv_report()
        if fmt in ("html", "both"):
            self._write_html_report()

        logger.info("Final reports written to %s/", self.config.output_dir)

    # ----- Internal -----

    def _run_loop(self) -> None:
        """Periodically scan for spikes and append to CSV."""
        while not self._stop_event.is_set():
            try:
                self._scan_for_spikes()
                self._append_csv_data()
            except Exception as exc:
                logger.error("Reporter loop error: %s", exc, exc_info=True)
            self._stop_event.wait(self.config.report_interval)

    def _scan_for_spikes(self) -> None:
        """
        Check latest readings from all monitors for spike conditions
        and record them as SpikeEvents.
        """
        threshold = self.config.spike_threshold_ms

        # Check ping results for latency spikes
        for target in self.config.targets:
            latest = self.ping_monitor.get_latest(target)
            if latest and latest.latency_ms is not None and latest.latency_ms > threshold:
                self.record_spike(
                    "ping",
                    f"{target}: {latest.latency_ms:.1f}ms (threshold: {threshold:.0f}ms)",
                )
            elif latest and latest.is_timeout:
                self.record_spike("ping", f"{target}: TIMEOUT", severity="CRITICAL")

        # Check traceroute hops for packet loss
        if self.traceroute_monitor:
            for target in self.config.targets:
                hops = self.traceroute_monitor.get_hops(target)
                for hop in hops:
                    if hop.loss_pct > self.config.spike_loss_pct and hop.sent >= 6:
                        self.record_spike(
                            "traceroute",
                            f"Hop {hop.hop_number} ({hop.ip_address}) to {target}: "
                            f"{hop.loss_pct:.1f}% packet loss",
                        )

    def _append_csv_data(self) -> None:
        """
        Append the latest ping latency readings to a running CSV file.
        Creates the file with headers on first call.
        """
        csv_path = os.path.join(
            self.config.output_dir,
            f"latency_{self._session_ts}.csv",
        )

        try:
            write_header = not self._csv_initialized
            with open(csv_path, "a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                if write_header:
                    writer.writerow([
                        "timestamp", "target", "latency_ms", "ttl",
                        "is_timeout", "is_spike",
                    ])
                    self._csv_initialized = True

                # Write recent ping results for each target
                for target in self.config.targets:
                    results = self.ping_monitor.get_results(target)
                    # Only write results from the last reporting interval
                    cutoff = time.time() - self.config.report_interval
                    for r in results:
                        if r.timestamp.timestamp() >= cutoff:
                            is_spike = (
                                r.latency_ms is not None
                                and r.latency_ms > self.config.spike_threshold_ms
                            )
                            writer.writerow([
                                r.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f"),
                                r.target,
                                f"{r.latency_ms:.2f}" if r.latency_ms is not None else "",
                                r.ttl or "",
                                r.is_timeout,
                                is_spike,
                            ])

            logger.debug("CSV data appended to %s", csv_path)
        except Exception as exc:
            logger.error("CSV write error: %s", exc)

    def _write_csv_report(self) -> None:
        """Write a comprehensive CSV summary report with all ping data."""
        csv_path = os.path.join(
            self.config.output_dir,
            f"summary_{self._session_ts}.csv",
        )

        try:
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)

                # Ping statistics summary
                writer.writerow(["=== PING STATISTICS ==="])
                writer.writerow(["target", "sent", "received", "loss_pct",
                                 "min_ms", "avg_ms", "max_ms", "jitter_ms"])
                for target in self.config.targets:
                    stats = self.ping_monitor.get_stats(target)
                    writer.writerow([
                        target, stats["sent"], stats["received"],
                        stats["loss_pct"], stats["min"], stats["avg"],
                        stats["max"], stats["jitter"],
                    ])
                writer.writerow([])

                # Spike events
                writer.writerow(["=== SPIKE EVENTS ==="])
                writer.writerow(["timestamp", "category", "severity", "message"])
                with self._lock:
                    for spike in self.spike_events:
                        writer.writerow([
                            spike.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                            spike.category,
                            spike.severity,
                            spike.message,
                        ])

            logger.info("CSV summary report written: %s", csv_path)
        except Exception as exc:
            logger.error("CSV summary write error: %s", exc)

    def _write_html_report(self) -> None:
        """
        Generate an HTML report with styled tables and inline CSS.
        Includes ping stats, traceroute hops, and spike timeline.
        """
        html_path = os.path.join(
            self.config.output_dir,
            f"report_{self._session_ts}.html",
        )

        try:
            # Build the HTML content
            html_parts = [self._html_header()]

            # Ping statistics table
            html_parts.append("<h2>Ping Latency Statistics</h2>")
            html_parts.append(self._html_ping_table())

            # Traceroute tables
            if self.traceroute_monitor:
                html_parts.append("<h2>Traceroute Analysis (WinMTR-style)</h2>")
                for target in self.config.targets:
                    html_parts.append(f"<h3>Route to {_html_escape(target)}</h3>")
                    html_parts.append(self._html_traceroute_table(target))

            # Netstat summary
            if self.netstat_monitor:
                html_parts.append("<h2>Connection States (Latest Snapshot)</h2>")
                html_parts.append(self._html_netstat_table())

            # Spike timeline
            html_parts.append("<h2>Anomaly Timeline</h2>")
            html_parts.append(self._html_spike_table())

            # Latency chart (SVG)
            html_parts.append("<h2>Latency Chart</h2>")
            html_parts.append(self._html_latency_chart_svg())

            # Wireshark capture analysis
            if self.capture_analyses:
                html_parts.append("<h2>Wireshark Capture Analysis</h2>")
                html_parts.append(self._html_capture_section())

            # Windows Event Log correlation
            html_parts.append("<h2>Windows Event Log Correlation</h2>")
            html_parts.append(self._html_event_log_section())

            # Full ping time-series (last 500 samples per target)
            html_parts.append("<h2>Latency Time Series (Recent)</h2>")
            html_parts.append(self._html_latency_timeseries())

            html_parts.append(self._html_footer())

            with open(html_path, "w", encoding="utf-8") as f:
                f.write("\n".join(html_parts))

            logger.info("HTML report written: %s", html_path)
        except Exception as exc:
            logger.error("HTML report write error: %s", exc)

    # ----- HTML Helpers -----

    def _html_header(self) -> str:
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>NetProbe Report — {self._session_ts}</title>
<style>
  body {{ font-family: 'Segoe UI', Tahoma, sans-serif; margin: 20px; background: #1e1e2e; color: #cdd6f4; }}
  h1 {{ color: #89b4fa; border-bottom: 2px solid #45475a; padding-bottom: 8px; }}
  h2 {{ color: #a6e3a1; margin-top: 30px; }}
  h3 {{ color: #f9e2af; }}
  table {{ border-collapse: collapse; width: 100%; margin: 10px 0; }}
  th {{ background: #313244; color: #cdd6f4; padding: 8px 12px; text-align: left; }}
  td {{ padding: 6px 12px; border-bottom: 1px solid #45475a; }}
  tr:hover {{ background: #313244; }}
  .spike {{ background: #f38ba833; }}
  .timeout {{ background: #f3767733; color: #f38ba8; font-weight: bold; }}
  .warning {{ color: #f9e2af; }}
  .critical {{ color: #f38ba8; font-weight: bold; }}
  .good {{ color: #a6e3a1; }}
  .meta {{ color: #6c7086; font-size: 0.9em; margin-bottom: 20px; }}
  details {{ margin: 10px 0; }}
  summary {{ cursor: pointer; color: #89b4fa; font-size: 0.95em; padding: 6px 0; }}
  summary:hover {{ color: #cdd6f4; }}
  .ts-summary {{ color: #cdd6f4; font-size: 1em; margin: 8px 0; padding: 6px 12px; background: #313244; border-radius: 4px; }}
</style>
</head>
<body>
<h1>NetProbe Network Latency Report</h1>
<p class="meta">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} |
   Session started: {self._session_ts} |
   Targets: {', '.join(self.config.targets)}</p>
"""

    def _html_footer(self) -> str:
        return """
<hr>
<p class="meta">Report generated by NetProbe v1.4.0</p>
</body>
</html>"""

    def _html_ping_table(self) -> str:
        rows = []
        for target in self.config.targets:
            stats = self.ping_monitor.get_stats(target)
            loss_class = "good" if stats["loss_pct"] < 1 else (
                "warning" if stats["loss_pct"] < 5 else "critical"
            )
            rows.append(f"""<tr>
  <td>{_html_escape(target)}</td>
  <td>{stats['sent']}</td>
  <td>{stats['received']}</td>
  <td class="{loss_class}">{stats['loss_pct']:.1f}%</td>
  <td>{stats['min']:.1f}</td>
  <td>{stats['avg']:.1f}</td>
  <td>{stats['max']:.1f}</td>
  <td>{stats['jitter']:.1f}</td>
</tr>""")

        return f"""<table>
<tr><th>Target</th><th>Sent</th><th>Received</th><th>Loss %</th>
    <th>Min (ms)</th><th>Avg (ms)</th><th>Max (ms)</th><th>Jitter (ms)</th></tr>
{''.join(rows)}
</table>"""

    def _html_traceroute_table(self, target: str) -> str:
        hops = self.traceroute_monitor.get_hops(target)
        if not hops:
            return "<p><em>No traceroute data available.</em></p>"

        rows = []
        for hop in hops:
            loss_class = "good" if hop.loss_pct < 1 else (
                "warning" if hop.loss_pct < 5 else "critical"
            )
            host = _html_escape(hop.hostname if hop.hostname != "*" else hop.ip_address)
            rows.append(f"""<tr>
  <td>{hop.hop_number}</td>
  <td>{host}</td>
  <td class="{loss_class}">{hop.loss_pct:.1f}%</td>
  <td>{hop.sent}</td><td>{hop.received}</td>
  <td>{hop.avg_ms:.1f}</td><td>{hop.min_ms:.1f}</td>
  <td>{hop.max_ms:.1f}</td><td>{hop.jitter_ms:.1f}</td>
</tr>""")

        return f"""<table>
<tr><th>Hop</th><th>Host</th><th>Loss %</th><th>Sent</th><th>Recv</th>
    <th>Avg (ms)</th><th>Min (ms)</th><th>Max (ms)</th><th>Jitter (ms)</th></tr>
{''.join(rows)}
</table>"""

    def _html_netstat_table(self) -> str:
        snap = self.netstat_monitor.get_latest() if self.netstat_monitor else None
        if not snap:
            return "<p><em>No netstat data available.</em></p>"

        rows = []
        for state, count in sorted(snap.state_counts.items(), key=lambda x: -x[1]):
            rows.append(f"<tr><td>{_html_escape(state)}</td><td>{count}</td></tr>")

        return f"""<p>Total connections: {snap.total_count} (at {snap.timestamp.strftime('%H:%M:%S')})</p>
<table>
<tr><th>State</th><th>Count</th></tr>
{''.join(rows)}
</table>"""

    def _html_spike_table(self) -> str:
        with self._lock:
            events = list(self.spike_events)

        if not events:
            return "<p class='good'>No anomalies detected during this session.</p>"

        rows = []
        for e in events:
            css = "warning" if e.severity == "WARNING" else (
                "critical" if e.severity == "CRITICAL" else ""
            )
            rows.append(f"""<tr class="{css}">
  <td>{e.timestamp.strftime('%H:%M:%S')}</td>
  <td>{_html_escape(e.category)}</td>
  <td>{_html_escape(e.severity)}</td>
  <td>{_html_escape(e.message)}</td>
</tr>""")

        return f"""<table>
<tr><th>Time</th><th>Category</th><th>Severity</th><th>Details</th></tr>
{''.join(rows)}
</table>"""

    def _html_latency_chart_svg(self) -> str:
        """Generate inline SVG latency charts for all targets."""
        parts = []
        for target in self.config.targets:
            results = self.ping_monitor.get_results(target)
            recent = results[-300:]  # Last 300 samples, matching GUI chart

            if not recent:
                parts.append(f"<p><em>No chart data for {_html_escape(target)}</em></p>")
                continue

            parts.append(f"<h3>{_html_escape(target)}</h3>")
            parts.append(self._build_svg_chart(target, recent))

        return "\n".join(parts)

    def _build_svg_chart(self, target: str, results: list) -> str:
        """Build an SVG chart for a single target's ping results."""
        # Chart dimensions
        W, H = 900, 280
        ML, MR, MT, MB = 60, 20, 20, 40  # margins
        pw = W - ML - MR  # plot width
        ph = H - MT - MB  # plot height
        threshold = self.config.spike_threshold_ms

        # Extract data points
        data: List[Tuple[str, Optional[float]]] = []
        for r in results:
            ts = r.timestamp.strftime("%H:%M:%S")
            data.append((ts, r.latency_ms))

        valid = [v for _, v in data if v is not None]
        if not valid:
            return "<p><em>No valid latency readings.</em></p>"

        y_min = 0.0
        y_max = max(valid) * 1.2
        y_max = max(y_max, 10.0)
        avg_val = sum(valid) / len(valid)

        n = len(data)
        x_step = pw / max(n - 1, 1)

        # Color constants matching the GUI theme
        C_BG = "#181825"
        C_GRID = "#45475a"
        C_LINE = "#89b4fa"
        C_SPIKE = "#f38ba8"
        C_RED = "#f38ba8"
        C_GREEN = "#a6e3a1"
        C_DIM = "#6c7086"
        C_TEXT = "#cdd6f4"

        svg_parts = [
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" '
            f'style="width:100%;max-width:{W}px;height:auto;background:{C_BG};border-radius:8px;margin:8px 0;">'
        ]

        # Plot background
        svg_parts.append(
            f'<rect x="{ML}" y="{MT}" width="{pw}" height="{ph}" '
            f'fill="{C_BG}" stroke="{C_GRID}" stroke-width="1"/>'
        )

        # Horizontal grid lines + Y-axis labels
        num_grid = 5
        for i in range(num_grid + 1):
            y_val = y_min + (y_max - y_min) * (i / num_grid)
            y_px = MT + ph - (i / num_grid) * ph
            svg_parts.append(
                f'<line x1="{ML}" y1="{y_px:.1f}" x2="{ML + pw}" y2="{y_px:.1f}" '
                f'stroke="{C_GRID}" stroke-dasharray="2,4" stroke-width="0.5"/>'
            )
            svg_parts.append(
                f'<text x="{ML - 5}" y="{y_px:.1f}" text-anchor="end" '
                f'fill="{C_DIM}" font-size="10" font-family="Consolas" '
                f'dominant-baseline="middle">{y_val:.0f}</text>'
            )

        # Y-axis title
        svg_parts.append(
            f'<text x="14" y="{MT + ph / 2}" fill="{C_DIM}" font-size="11" '
            f'font-family="Consolas" transform="rotate(-90, 14, {MT + ph / 2})" '
            f'text-anchor="middle">ms</text>'
        )

        # Spike threshold line
        if y_min <= threshold <= y_max:
            th_px = MT + ph - ((threshold - y_min) / (y_max - y_min)) * ph
            svg_parts.append(
                f'<line x1="{ML}" y1="{th_px:.1f}" x2="{ML + pw}" y2="{th_px:.1f}" '
                f'stroke="{C_RED}" stroke-dasharray="6,3" stroke-width="1"/>'
            )
            svg_parts.append(
                f'<text x="{ML + pw - 2}" y="{th_px - 5:.1f}" text-anchor="end" '
                f'fill="{C_RED}" font-size="9" font-family="Consolas">'
                f'spike: {threshold:.0f}ms</text>'
            )

        # Average line
        if y_min <= avg_val <= y_max:
            avg_px = MT + ph - ((avg_val - y_min) / (y_max - y_min)) * ph
            svg_parts.append(
                f'<line x1="{ML}" y1="{avg_px:.1f}" x2="{ML + pw}" y2="{avg_px:.1f}" '
                f'stroke="{C_GREEN}" stroke-dasharray="4,6" stroke-width="1"/>'
            )
            svg_parts.append(
                f'<text x="{ML + 4}" y="{avg_px - 5:.1f}" text-anchor="start" '
                f'fill="{C_GREEN}" font-size="9" font-family="Consolas">'
                f'avg: {avg_val:.1f}ms</text>'
            )

        # Build polyline and spike/timeout markers
        line_segments: List[List[str]] = [[]]  # list of segments (broken at timeouts)
        spike_markers: List[str] = []
        timeout_markers: List[str] = []

        for i, (ts, val) in enumerate(data):
            x = ML + i * x_step
            if val is not None:
                y_frac = (val - y_min) / (y_max - y_min) if (y_max - y_min) > 0 else 0
                y = MT + ph - y_frac * ph
                line_segments[-1].append(f"{x:.1f},{y:.1f}")
                if val > threshold:
                    spike_markers.append(
                        f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3" '
                        f'fill="{C_SPIKE}" stroke="{C_RED}" stroke-width="1"/>'
                    )
            else:
                # Timeout — break the line
                if line_segments[-1]:
                    line_segments.append([])
                sz = 5
                timeout_markers.append(
                    f'<line x1="{x - sz:.1f}" y1="{MT + 5}" x2="{x + sz:.1f}" y2="{MT + 15}" '
                    f'stroke="{C_RED}" stroke-width="2"/>'
                )
                timeout_markers.append(
                    f'<line x1="{x - sz:.1f}" y1="{MT + 15}" x2="{x + sz:.1f}" y2="{MT + 5}" '
                    f'stroke="{C_RED}" stroke-width="2"/>'
                )

        # Draw polyline segments
        for seg in line_segments:
            if len(seg) >= 2:
                svg_parts.append(
                    f'<polyline points="{" ".join(seg)}" fill="none" '
                    f'stroke="{C_LINE}" stroke-width="1.5" stroke-linejoin="round"/>'
                )

        # Draw markers
        svg_parts.extend(spike_markers)
        svg_parts.extend(timeout_markers)

        # X-axis time labels
        label_step = max(1, n // 8)
        for i in range(0, n, label_step):
            ts_label, _ = data[i]
            x = ML + i * x_step
            svg_parts.append(
                f'<text x="{x:.1f}" y="{MT + ph + 18}" text-anchor="middle" '
                f'fill="{C_DIM}" font-size="8" font-family="Consolas">{ts_label}</text>'
            )

        # Stats text in top-right
        stats_text = f"avg={avg_val:.1f}ms  min={min(valid):.1f}ms  max={max(valid):.1f}ms"
        svg_parts.append(
            f'<text x="{ML + pw - 5}" y="{MT + 14}" text-anchor="end" '
            f'fill="{C_DIM}" font-size="10" font-family="Consolas">{stats_text}</text>'
        )

        svg_parts.append("</svg>")
        return "\n".join(svg_parts)

    # ----- Windows Event Log Correlation -----

    def _query_event_logs(self) -> List[Dict]:
        """
        Query Windows Event Logs (System + Application) for errors/warnings
        during the monitoring session. Returns parsed event dicts.
        """
        events: List[Dict] = []

        # Determine time range from spike events or session start
        session_start = datetime.strptime(self._session_ts, "%Y%m%d_%H%M%S")
        now = datetime.now()

        # Format times for PowerShell
        start_str = session_start.strftime("%Y-%m-%dT%H:%M:%S")
        end_str = now.strftime("%Y-%m-%dT%H:%M:%S")

        # PowerShell script to query event logs for errors/warnings
        ps_script = (
            f"$start = [datetime]'{start_str}';"
            f"$end = [datetime]'{end_str}';"
            "try {"
            "  $events = @();"
            "  foreach ($logName in @('System','Application')) {"
            "    try {"
            "      $events += Get-WinEvent -FilterHashtable @{"
            "        LogName=$logName; Level=@(1,2,3); StartTime=$start; EndTime=$end"
            "      } -MaxEvents 200 -ErrorAction SilentlyContinue"
            "    } catch {}"
            "  };"
            "  $events | Select-Object TimeCreated,LevelDisplayName,ProviderName,"
            "    Id,Message,LogName | ConvertTo-Json -Depth 2 -Compress"
            "} catch { Write-Output '[]' }"
        )

        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_script],
                capture_output=True, text=True, timeout=30,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            if result.returncode == 0 and result.stdout.strip():
                raw = result.stdout.strip()
                if not raw or raw == "[]":
                    return []
                parsed = json.loads(raw)
                # PowerShell returns a single dict if only one event, list otherwise
                if isinstance(parsed, dict):
                    parsed = [parsed]
                for ev in parsed:
                    # Parse the /Date(...)/ format PowerShell uses for JSON dates
                    tc = ev.get("TimeCreated", "")
                    if isinstance(tc, str) and "/Date(" in tc:
                        ms = int(tc.split("(")[1].split(")")[0].split("-")[0].split("+")[0])
                        dt = datetime.fromtimestamp(ms / 1000.0)
                    elif isinstance(tc, str):
                        try:
                            dt = datetime.fromisoformat(tc)
                        except (ValueError, TypeError):
                            dt = now
                    else:
                        dt = now

                    msg = ev.get("Message", "") or ""
                    # Truncate very long messages
                    if len(msg) > 300:
                        msg = msg[:300] + "..."
                    events.append({
                        "timestamp": dt,
                        "level": ev.get("LevelDisplayName", "Unknown"),
                        "source": ev.get("ProviderName", "Unknown"),
                        "event_id": ev.get("Id", 0),
                        "message": msg,
                        "log": ev.get("LogName", ""),
                    })
            logger.info("Retrieved %d Windows Event Log entries", len(events))
        except subprocess.TimeoutExpired:
            logger.warning("Event log query timed out")
        except Exception as exc:
            logger.error("Event log query failed: %s", exc)

        return events

    def _correlate_events_with_spikes(
        self, win_events: List[Dict], window_secs: int = 30
    ) -> List[Dict]:
        """
        Find Windows events that occurred within ±window_secs of any spike.
        Returns events annotated with correlation info.
        """
        with self._lock:
            spikes = list(self.spike_events)

        if not spikes or not win_events:
            return []

        correlated = []
        seen = set()  # avoid duplicates
        for ev in win_events:
            ev_ts = ev["timestamp"]
            for spike in spikes:
                delta = abs((ev_ts - spike.timestamp).total_seconds())
                if delta <= window_secs:
                    key = (ev_ts, ev.get("event_id"), ev.get("source"))
                    if key not in seen:
                        seen.add(key)
                        correlated.append({
                            **ev,
                            "correlated_spike": str(spike),
                            "time_offset_sec": delta,
                        })
                    break  # Only correlate with closest spike

        # Sort by timestamp
        correlated.sort(key=lambda e: e["timestamp"])
        return correlated

    def _html_capture_section(self) -> str:
        """Build HTML section for Wireshark capture analysis results."""
        if not self.capture_analyses:
            return "<p class='good'>No packet captures taken during this session.</p>"

        parts = [f"<p>{len(self.capture_analyses)} capture(s) analysed during this session.</p>"]

        for idx, analysis in enumerate(self.capture_analyses, 1):
            pcap_name = os.path.basename(analysis.pcap_path) if analysis.pcap_path else f"Capture {idx}"
            ts_str = analysis.timestamp.strftime("%H:%M:%S") if hasattr(analysis, 'timestamp') else ""

            sev = analysis.severity
            sev_css = "good" if sev == "OK" else ("warning" if sev == "Warning" else "critical")

            parts.append(f"<h3>Capture {idx}: {_html_escape(pcap_name)}"
                         f" <span class='{sev_css}'>({sev})</span></h3>")

            # Summary stats table
            parts.append(f"""<table>
<tr><th>Metric</th><th>Value</th></tr>
<tr><td>Time</td><td>{ts_str}</td></tr>
<tr><td>Total Packets</td><td>{analysis.total_packets:,}</td></tr>
<tr><td>Duration</td><td>{analysis.capture_duration_sec:.0f}s</td></tr>
<tr><td>TCP Retransmissions</td><td class="{'critical' if analysis.tcp_retransmissions > 50 else 'warning' if analysis.tcp_retransmissions > 0 else ''}">{analysis.tcp_retransmissions}</td></tr>
<tr><td>TCP Duplicate ACKs</td><td class="{'warning' if analysis.tcp_duplicate_acks > 50 else ''}">{analysis.tcp_duplicate_acks}</td></tr>
<tr><td>TCP RSTs</td><td class="{'warning' if analysis.tcp_resets > 20 else ''}">{analysis.tcp_resets}</td></tr>
<tr><td>TCP Zero-Window</td><td class="{'warning' if analysis.tcp_zero_window > 0 else ''}">{analysis.tcp_zero_window}</td></tr>
<tr><td>TCP Out-of-Order</td><td class="{'warning' if analysis.tcp_out_of_order > 10 else ''}">{analysis.tcp_out_of_order}</td></tr>
<tr><td>TCP Window Full</td><td class="{'warning' if analysis.tcp_window_full > 0 else ''}">{analysis.tcp_window_full}</td></tr>
<tr><td>DNS Queries</td><td>{analysis.dns_queries}</td></tr>
<tr><td>DNS Failures</td><td class="{'critical' if analysis.dns_failures > 0 else ''}">{analysis.dns_failures}</td></tr>
<tr><td>ICMP Unreachable</td><td class="{'warning' if analysis.icmp_unreachable > 0 else ''}">{analysis.icmp_unreachable}</td></tr>
<tr><td>ICMP TTL Exceeded</td><td class="{'warning' if analysis.icmp_ttl_exceeded > 0 else ''}">{analysis.icmp_ttl_exceeded}</td></tr>
</table>""")

            # Problems / findings
            if analysis.problems:
                parts.append("<h4>Findings</h4><ul>")
                for problem in analysis.problems:
                    if "CRITICAL" in problem:
                        parts.append(f"<li class='critical'>{_html_escape(problem)}</li>")
                    elif "WARNING" in problem:
                        parts.append(f"<li class='warning'>{_html_escape(problem)}</li>")
                    else:
                        parts.append(f"<li>{_html_escape(problem)}</li>")
                parts.append("</ul>")

            # DNS failure details
            if analysis.dns_detail:
                parts.append("<h4>Failed DNS Lookups</h4><ul>")
                for detail in analysis.dns_detail:
                    parts.append(f"<li class='warning'>{_html_escape(detail)}</li>")
                parts.append("</ul>")

        return "\n".join(parts)

    def _html_event_log_section(self) -> str:
        """Build HTML section for Windows Event Log correlation."""
        win_events = self._query_event_logs()
        if not win_events:
            return (
                "<p class='good'>No Windows Event Log errors/warnings found "
                "during this monitoring session.</p>"
            )

        # Full event table
        parts = [
            f"<p>Found {len(win_events)} error/warning events in Windows "
            f"Event Logs during this session.</p>"
        ]

        # Correlation analysis
        correlated = self._correlate_events_with_spikes(win_events)
        if correlated:
            parts.append(f"<h3>Correlated Events ({len(correlated)} events within "
                         f"&plusmn;30s of a spike)</h3>")
            parts.append('<table>')
            parts.append(
                '<tr><th>Time</th><th>Log</th><th>Level</th><th>Source</th>'
                '<th>Event ID</th><th>Message</th><th>Correlated Spike</th>'
                '<th>Offset</th></tr>'
            )
            for ev in correlated:
                css = "critical" if ev["level"] in ("Error", "Critical") else "warning"
                parts.append(
                    f'<tr class="{css}">'
                    f'<td>{ev["timestamp"].strftime("%H:%M:%S")}</td>'
                    f'<td>{_html_escape(ev["log"])}</td>'
                    f'<td>{_html_escape(ev["level"])}</td>'
                    f'<td>{_html_escape(ev["source"])}</td>'
                    f'<td>{ev["event_id"]}</td>'
                    f'<td>{_html_escape(ev["message"])}</td>'
                    f'<td>{_html_escape(ev["correlated_spike"])}</td>'
                    f'<td>&plusmn;{ev["time_offset_sec"]:.0f}s</td>'
                    f'</tr>'
                )
            parts.append('</table>')
        else:
            parts.append(
                "<p>No Windows events correlated with detected spikes "
                "(within &plusmn;30s window).</p>"
            )

        # Summary table of all events
        parts.append(f"<h3>All Session Events ({len(win_events)})</h3>")
        parts.append('<table>')
        parts.append(
            '<tr><th>Time</th><th>Log</th><th>Level</th><th>Source</th>'
            '<th>Event ID</th><th>Message</th></tr>'
        )
        for ev in win_events[:100]:  # Cap at 100 to keep report reasonable
            css = "critical" if ev["level"] in ("Error", "Critical") else "warning"
            parts.append(
                f'<tr class="{css}">'
                f'<td>{ev["timestamp"].strftime("%H:%M:%S")}</td>'
                f'<td>{_html_escape(ev["log"])}</td>'
                f'<td>{_html_escape(ev["level"])}</td>'
                f'<td>{_html_escape(ev["source"])}</td>'
                f'<td>{ev["event_id"]}</td>'
                f'<td>{_html_escape(ev["message"])}</td>'
                f'</tr>'
            )
        if len(win_events) > 100:
            parts.append(
                f'<tr><td colspan="6" class="meta">... and {len(win_events) - 100} '
                f'more events (truncated)</td></tr>'
            )
        parts.append('</table>')

        return "\n".join(parts)

    def _html_latency_timeseries(self) -> str:
        """Build an HTML table of recent latency readings per target, collapsed."""
        parts = []
        for target in self.config.targets:
            results = self.ping_monitor.get_results(target)
            recent = results[-200:]  # Last 200 samples

            if not recent:
                parts.append(f"<p><em>No data for {_html_escape(target)}</em></p>")
                continue

            parts.append(f"<h3>{_html_escape(target)}</h3>")

            # Compute summary stats for the non-collapsible line
            valid_ms = [r.latency_ms for r in recent if r.latency_ms is not None]
            timeouts = sum(1 for r in recent if r.is_timeout)
            avg_ms = sum(valid_ms) / len(valid_ms) if valid_ms else 0.0
            parts.append(
                f'<p class="ts-summary">{len(recent)} entries &nbsp;|&nbsp; '
                f'Avg: {avg_ms:.1f}ms &nbsp;|&nbsp; '
                f'Timeouts: {timeouts}</p>'
            )

            rows = []
            for r in recent:
                css = ""
                if r.is_timeout:
                    css = "timeout"
                elif r.latency_ms and r.latency_ms > self.config.spike_threshold_ms:
                    css = "spike"
                lat = f"{r.latency_ms:.1f}" if r.latency_ms is not None else "TIMEOUT"
                rows.append(
                    f'<tr class="{css}"><td>{r.timestamp.strftime("%H:%M:%S.%f")[:-3]}</td>'
                    f'<td>{lat}</td><td>{r.ttl or ""}</td></tr>'
                )

            parts.append(f"""<details>
<summary>Expand {len(recent)} time-series entries</summary>
<table>
<tr><th>Time</th><th>Latency (ms)</th><th>TTL</th></tr>
{''.join(rows)}
</table>
</details>""")

        return "\n".join(parts)


def _html_escape(text: str) -> str:
    """Escape HTML special characters to prevent XSS in generated reports."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )
