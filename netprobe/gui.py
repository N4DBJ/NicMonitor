"""
netprobe/gui.py - Graphical User Interface (Dark-themed Dashboard)
===================================================================
A full-featured tkinter GUI for NetProbe that provides:

  - Live latency graph drawn on a Canvas (scrolling time-series)
  - WinMTR-style traceroute hop table with color-coded loss
  - Netstat connection state summary panel
  - Per-process top-talkers table
  - Scrollable spike/anomaly event log
  - Settings panel to configure targets, intervals, thresholds
  - Start/Stop controls and report generation buttons

The GUI runs all monitors in background threads (same as CLI mode) and
polls their results from the tkinter main loop via `after()` callbacks,
keeping the UI responsive.

Version: 1.1.0

Design Notes:
  - Uses only tkinter + tkinter.ttk (ships with Python, no extra deps)
  - Dark Monokai-inspired color scheme for comfortable long-term monitoring
  - Canvas-based latency chart avoids matplotlib dependency
  - All monitor interactions are thread-safe (monitors use locks internally)
"""

import logging
import os
import socket
import sys
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
from collections import deque
from datetime import datetime
from typing import Dict, List, Optional, Deque

from netprobe import __version__, __app_name__
from netprobe.config import ProbeConfig
from netprobe.logger import setup_logger
from netprobe.ping_monitor import PingMonitor, TracerouteMonitor
from netprobe.netstat_monitor import NetstatMonitor
from netprobe.process_monitor import ProcessMonitor, PSUTIL_AVAILABLE
from netprobe.reporter import Reporter
from netprobe.nic_monitor import NicMonitor
from netprobe.capture_monitor import CaptureMonitor
from netprobe.web_monitor import WebProbeMonitor, WebProbeResult

logger = logging.getLogger("netprobe.gui")

# ---------------------------------------------------------------------------
# Color Palette (dark theme)
# ---------------------------------------------------------------------------
# A cohesive dark palette loosely inspired by Catppuccin Mocha / VS Code dark
COLORS = {
    "bg":           "#1e1e2e",   # Main background
    "bg_secondary": "#181825",   # Slightly darker panels
    "bg_card":      "#313244",   # Card / frame background
    "bg_input":     "#45475a",   # Input field backgrounds
    "fg":           "#cdd6f4",   # Primary text
    "fg_dim":       "#6c7086",   # Dimmed / secondary text
    "accent":       "#89b4fa",   # Blue accent (headers, links)
    "green":        "#a6e3a1",   # Good / success
    "yellow":       "#f9e2af",   # Warning
    "red":          "#f38ba8",   # Error / critical
    "orange":       "#fab387",   # Spike highlight
    "teal":         "#94e2d5",   # Traceroute hops
    "mauve":        "#cba6f7",   # Process monitor accent
    "surface0":     "#313244",   # Borders / separators
    "grid":         "#45475a",   # Chart grid lines
    "chart_line":   "#89b4fa",   # Primary chart line (latency)
    "chart_spike":  "#f38ba8",   # Spike markers on chart
    "chart_fill":   "#89b4fa22", # Fill under the latency curve
}

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
CHART_WIDTH = 800        # Pixels wide for the latency canvas
CHART_HEIGHT = 250       # Pixels tall for the latency canvas
CHART_MARGIN_L = 55      # Left margin for Y-axis labels
CHART_MARGIN_R = 15      # Right margin
CHART_MARGIN_T = 15      # Top margin
CHART_MARGIN_B = 30      # Bottom margin for X-axis labels
CHART_MAX_POINTS = 300   # Maximum data points displayed on the chart

UI_REFRESH_MS = 1000     # Milliseconds between UI data refreshes
CHART_REFRESH_MS = 500   # Milliseconds between chart redraws


# ============================================================================
#  Main GUI Application
# ============================================================================

class NetProbeGUI:
    """
    The main GUI application window. Creates a tabbed dashboard with panels
    for each monitoring subsystem and manages the lifecycle of all monitors.
    """

    def __init__(self) -> None:
        """Initialize the root window, style, tabs, and control state."""

        # ----- Root Window -----
        self.root = tk.Tk()
        self.root.title(f"{__app_name__} v{__version__} — Network Latency Monitor")
        self.root.geometry("1100x750")
        self.root.minsize(900, 600)
        self.root.configure(bg=COLORS["bg"])

        # Set the window icon if we can (silently skip if the ico doesn't exist)
        try:
            self.root.iconbitmap(default="")
        except Exception:
            pass

        # ----- Application State -----
        self.config = ProbeConfig()
        self.is_running = False

        # Monitor instances (created on Start, destroyed on Stop)
        self.ping_monitor: Optional[PingMonitor] = None
        self.traceroute_monitor: Optional[TracerouteMonitor] = None
        self.netstat_monitor: Optional[NetstatMonitor] = None
        self.process_monitor: Optional[ProcessMonitor] = None
        self.reporter: Optional[Reporter] = None

        # v1.2.0: NIC health + Wireshark capture monitors
        self.nic_monitor: Optional[NicMonitor] = None
        self.capture_monitor: Optional[CaptureMonitor] = None

        # v1.5.0: Web Probe monitor
        self.web_probe: WebProbeMonitor = WebProbeMonitor()

        # Wireshark capture analysis results collected during the session
        self._capture_analyses: list = []

        # Chart data: per-target rolling latency history for the canvas graph
        self._chart_data: Dict[str, Deque[Optional[float]]] = {}
        self._chart_timestamps: Deque[str] = deque(maxlen=CHART_MAX_POINTS)

        # Track which NIC disconnect warnings we've already logged (to avoid spam)
        self._logged_nic_disconnects: set = set()

        # DNS reverse-lookup cache {ip: hostname} and PID name cache {pid: name}
        self._dns_cache: Dict[str, str] = {}
        self._dns_pending: set = set()  # IPs currently being resolved
        self._pid_name_cache: Dict[int, str] = {}

        # ----- Build the UI -----
        self._setup_styles()
        self._build_toolbar()
        self._build_notebook()
        self._build_status_bar()

        # Handle window close
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        logger.info("GUI initialized — %s v%s", __app_name__, __version__)

    # -----------------------------------------------------------------------
    #  Styles
    # -----------------------------------------------------------------------

    def _setup_styles(self) -> None:
        """Configure ttk styles for the dark theme across all widget types."""
        style = ttk.Style()

        # Try to use 'clam' theme as a base (modern look, supports custom colors)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass  # Fall back to default

        # General
        style.configure(".", background=COLORS["bg"], foreground=COLORS["fg"],
                         fieldbackground=COLORS["bg_input"])
        style.configure("TFrame", background=COLORS["bg"])
        style.configure("Card.TFrame", background=COLORS["bg_card"])
        style.configure("TLabel", background=COLORS["bg"], foreground=COLORS["fg"],
                         font=("Segoe UI", 10))
        style.configure("Header.TLabel", font=("Segoe UI", 12, "bold"),
                         foreground=COLORS["accent"])
        style.configure("Stat.TLabel", font=("Consolas", 11),
                         foreground=COLORS["green"])
        style.configure("Warning.TLabel", font=("Consolas", 11),
                         foreground=COLORS["yellow"])
        style.configure("Error.TLabel", font=("Consolas", 11),
                         foreground=COLORS["red"])
        style.configure("Dim.TLabel", font=("Segoe UI", 9),
                         foreground=COLORS["fg_dim"])

        # Notebook (tabs)
        style.configure("TNotebook", background=COLORS["bg"], borderwidth=0)
        style.configure("TNotebook.Tab", background=COLORS["bg_card"],
                         foreground=COLORS["fg"], padding=[12, 6],
                         font=("Segoe UI", 10))
        style.map("TNotebook.Tab",
                  background=[("selected", COLORS["bg"]), ("active", COLORS["bg_input"])],
                  foreground=[("selected", COLORS["accent"])])

        # Buttons
        style.configure("TButton", background=COLORS["bg_card"],
                         foreground=COLORS["fg"], padding=[10, 5],
                         font=("Segoe UI", 10))
        style.map("TButton",
                  background=[("active", COLORS["bg_input"]),
                              ("disabled", COLORS["bg_secondary"])],
                  foreground=[("disabled", COLORS["fg_dim"])])
        style.configure("Start.TButton", foreground=COLORS["green"],
                         font=("Segoe UI", 10, "bold"))
        style.configure("Stop.TButton", foreground=COLORS["red"],
                         font=("Segoe UI", 10, "bold"))

        # Entry
        style.configure("TEntry", fieldbackground=COLORS["bg_input"],
                         foreground=COLORS["fg"], insertcolor=COLORS["fg"])

        # Treeview (tables)
        style.configure("Treeview", background=COLORS["bg_card"],
                         foreground=COLORS["fg"], fieldbackground=COLORS["bg_card"],
                         rowheight=24, font=("Consolas", 10))
        style.configure("Treeview.Heading", background=COLORS["bg_input"],
                         foreground=COLORS["accent"], font=("Segoe UI", 10, "bold"))
        style.map("Treeview",
                  background=[("selected", COLORS["bg_input"])],
                  foreground=[("selected", COLORS["accent"])])

        # Checkbutton
        style.configure("TCheckbutton", background=COLORS["bg"],
                         foreground=COLORS["fg"], font=("Segoe UI", 10))

        # Separator
        style.configure("TSeparator", background=COLORS["surface0"])

        # Labelframe
        style.configure("TLabelframe", background=COLORS["bg"],
                         foreground=COLORS["accent"])
        style.configure("TLabelframe.Label", background=COLORS["bg"],
                         foreground=COLORS["accent"], font=("Segoe UI", 10, "bold"))

        # Combobox
        style.configure("TCombobox", fieldbackground=COLORS["bg_input"],
                         foreground=COLORS["fg"], background=COLORS["bg_card"])

    # -----------------------------------------------------------------------
    #  Toolbar (Start / Stop / Report / Settings summary)
    # -----------------------------------------------------------------------

    def _build_toolbar(self) -> None:
        """Build the top toolbar with start/stop buttons and target entry."""
        toolbar = ttk.Frame(self.root)
        toolbar.pack(fill=tk.X, padx=10, pady=(8, 2))

        # Target entry
        ttk.Label(toolbar, text="Targets:", style="Header.TLabel").pack(side=tk.LEFT, padx=(0, 5))
        self._target_var = tk.StringVar(value=", ".join(self.config.targets))
        self._target_entry = ttk.Entry(toolbar, textvariable=self._target_var, width=40,
                                        font=("Consolas", 10))
        self._target_entry.pack(side=tk.LEFT, padx=(0, 10))

        # Start button
        self._start_btn = ttk.Button(toolbar, text="▶  Start Monitoring",
                                      style="Start.TButton", command=self._on_start)
        self._start_btn.pack(side=tk.LEFT, padx=3)

        # Stop button
        self._stop_btn = ttk.Button(toolbar, text="■  Stop",
                                     style="Stop.TButton", command=self._on_stop,
                                     state=tk.DISABLED)
        self._stop_btn.pack(side=tk.LEFT, padx=3)

        # Report button
        self._report_btn = ttk.Button(toolbar, text="📄 Save Report",
                                       command=self._on_save_report, state=tk.DISABLED)
        self._report_btn.pack(side=tk.LEFT, padx=3)

        # Open latest report button
        self._open_report_btn = ttk.Button(toolbar, text="📂 Open Report",
                                            command=self._on_open_report, state=tk.DISABLED)
        self._open_report_btn.pack(side=tk.LEFT, padx=3)

        # Running time label on the right
        self._time_var = tk.StringVar(value="Stopped")
        ttk.Label(toolbar, textvariable=self._time_var, style="Dim.TLabel").pack(side=tk.RIGHT, padx=5)
        self._start_ts: Optional[float] = None

    # -----------------------------------------------------------------------
    #  Notebook (tabs)
    # -----------------------------------------------------------------------

    def _build_notebook(self) -> None:
        """Create the tabbed notebook with all monitoring panels."""
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Tab 1: Latency Dashboard (chart + per-target stats)
        self._build_latency_tab()

        # Tab 2: Traceroute (WinMTR table)
        self._build_traceroute_tab()

        # Tab 3: Connections (netstat)
        self._build_netstat_tab()

        # Tab 4: Processes
        self._build_process_tab()

        # Tab 5: NIC Health (physical adapter & cable errors)
        self._build_nic_tab()

        # Tab 6: Wireshark Capture & Analysis
        self._build_capture_tab()

        # Tab 7: Web Probe (URL load timing & DNS diagnostics)
        self._build_web_probe_tab()

        # Tab 8: Event Log (spikes & anomalies)
        self._build_log_tab()

        # Tab 9: Settings
        self._build_settings_tab()

    # --- Tab 1: Latency ---

    def _build_latency_tab(self) -> None:
        """Build the main latency dashboard with a live canvas chart and stats cards."""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="  📊 Latency  ")

        # ----- Canvas chart -----
        chart_frame = ttk.LabelFrame(tab, text="  Live Latency (ms)  ")
        chart_frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=(8, 4))

        self.chart_canvas = tk.Canvas(chart_frame, bg=COLORS["bg_secondary"],
                                       highlightthickness=0, height=CHART_HEIGHT)
        self.chart_canvas.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        # Bind resize so the chart re-renders at the new size
        self.chart_canvas.bind("<Configure>", lambda e: self._draw_chart())

        # Target selector for the chart
        selector_frame = ttk.Frame(chart_frame)
        selector_frame.pack(fill=tk.X, padx=4, pady=(0, 4))
        ttk.Label(selector_frame, text="Show target:").pack(side=tk.LEFT, padx=(4, 5))
        self._chart_target_var = tk.StringVar()
        self._chart_target_combo = ttk.Combobox(
            selector_frame, textvariable=self._chart_target_var,
            state="readonly", width=30
        )
        self._chart_target_combo.pack(side=tk.LEFT)

        # ----- Stats cards row -----
        stats_frame = ttk.Frame(tab)
        stats_frame.pack(fill=tk.X, padx=8, pady=(4, 8))

        # We'll build stat cards dynamically when monitoring starts
        self._stat_frames: Dict[str, Dict[str, tk.StringVar]] = {}
        self._stats_container = stats_frame

    def _rebuild_stat_cards(self) -> None:
        """(Re)build the per-target stat cards below the chart."""
        # Clear existing cards
        for w in self._stats_container.winfo_children():
            w.destroy()
        self._stat_frames.clear()

        targets = self.config.targets
        for i, target in enumerate(targets):
            card = ttk.LabelFrame(self._stats_container, text=f"  {target}  ")
            card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=4, pady=2)

            vars_dict = {}
            labels = [
                ("Last", "—"), ("Avg", "—"), ("Min", "—"),
                ("Max", "—"), ("Loss", "—"), ("Jitter", "—"), ("Sent", "—"),
            ]
            for row, (name, default) in enumerate(labels):
                ttk.Label(card, text=f"{name}:", style="Dim.TLabel").grid(
                    row=row, column=0, sticky=tk.W, padx=(8, 4), pady=1)
                sv = tk.StringVar(value=default)
                lbl_style = "Stat.TLabel"
                ttk.Label(card, textvariable=sv, style=lbl_style).grid(
                    row=row, column=1, sticky=tk.E, padx=(4, 8), pady=1)
                vars_dict[name.lower()] = sv

            self._stat_frames[target] = vars_dict

    # --- Tab 2: Traceroute ---

    def _build_traceroute_tab(self) -> None:
        """Build the WinMTR-style traceroute table."""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="  🌐 Traceroute  ")

        # Target selector
        sel_frame = ttk.Frame(tab)
        sel_frame.pack(fill=tk.X, padx=8, pady=6)
        ttk.Label(sel_frame, text="Target:", style="Header.TLabel").pack(side=tk.LEFT, padx=(0, 5))
        self._trace_target_var = tk.StringVar()
        self._trace_target_combo = ttk.Combobox(
            sel_frame, textvariable=self._trace_target_var,
            state="readonly", width=30
        )
        self._trace_target_combo.pack(side=tk.LEFT)
        ttk.Button(sel_frame, text="↺ Reset Counters",
                   command=self._reset_traceroute).pack(side=tk.LEFT, padx=(15, 0))

        # Treeview table for hops
        columns = ("hop", "host", "loss", "sent", "recv", "avg", "min", "max", "jitter")
        self._trace_tree = ttk.Treeview(tab, columns=columns, show="headings", height=20)

        headings = {
            "hop": ("Hop", 45), "host": ("Host / IP", 280), "loss": ("Loss %", 70),
            "sent": ("Sent", 60), "recv": ("Recv", 60),
            "avg": ("Avg (ms)", 80), "min": ("Min (ms)", 80),
            "max": ("Max (ms)", 80), "jitter": ("Jitter", 70),
        }
        for col, (text, width) in headings.items():
            self._trace_tree.heading(col, text=text)
            anchor = tk.CENTER if col != "host" else tk.W
            self._trace_tree.column(col, width=width, anchor=anchor, minwidth=40)

        # Scrollbar
        trace_scroll = ttk.Scrollbar(tab, orient=tk.VERTICAL, command=self._trace_tree.yview)
        self._trace_tree.configure(yscrollcommand=trace_scroll.set)
        self._trace_tree.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8), side=tk.LEFT)
        trace_scroll.pack(fill=tk.Y, side=tk.RIGHT, pady=(0, 8), padx=(0, 8))
        self._bind_treeview_copy(self._trace_tree)

    # --- Tab 3: Netstat ---

    def _build_netstat_tab(self) -> None:
        """Build the connection state summary panel."""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="  🔌 Connections  ")

        # Summary labels
        summary = ttk.LabelFrame(tab, text="  Connection Summary  ")
        summary.pack(fill=tk.X, padx=8, pady=8)

        self._ns_total_var = tk.StringVar(value="Total: —")
        self._ns_proto_var = tk.StringVar(value="TCP: —  |  UDP: —")
        ttk.Label(summary, textvariable=self._ns_total_var, style="Header.TLabel").pack(
            anchor=tk.W, padx=8, pady=2)
        ttk.Label(summary, textvariable=self._ns_proto_var, style="Stat.TLabel").pack(
            anchor=tk.W, padx=8, pady=2)

        # Options row: nslookup toggle
        opts_frame = ttk.Frame(tab)
        opts_frame.pack(fill=tk.X, padx=8, pady=(0, 4))
        self._ns_nslookup_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(opts_frame, text="Resolve hostnames (nslookup)",
                         variable=self._ns_nslookup_var).pack(side=tk.LEFT)
        self._ns_lookup_status = tk.StringVar(value="")
        ttk.Label(opts_frame, textvariable=self._ns_lookup_status,
                  style="Dim.TLabel").pack(side=tk.LEFT, padx=10)

        # State breakdown table (expandable — click to show individual connections)
        columns = ("state", "count", "indicator")
        tree_frame = ttk.Frame(tab)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))

        self._ns_tree = ttk.Treeview(tree_frame, columns=columns, show="tree headings", height=16)
        self._ns_tree.heading("#0", text="")
        self._ns_tree.heading("state", text="State")
        self._ns_tree.heading("count", text="Count")
        self._ns_tree.heading("indicator", text="Status")
        self._ns_tree.column("#0", width=30, stretch=False)
        self._ns_tree.column("state", width=200)
        self._ns_tree.column("count", width=100, anchor=tk.CENTER)
        self._ns_tree.column("indicator", width=500)

        ns_scroll = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self._ns_tree.yview)
        self._ns_tree.configure(yscrollcommand=ns_scroll.set)
        self._ns_tree.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)
        ns_scroll.pack(fill=tk.Y, side=tk.RIGHT)
        self._bind_treeview_copy(self._ns_tree)

    # --- Tab 4: Processes ---

    def _build_process_tab(self) -> None:
        """Build the per-process network I/O top-talkers table."""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="  ⚙ Processes  ")

        # System-wide I/O summary
        sys_frame = ttk.LabelFrame(tab, text="  System Network I/O  ")
        sys_frame.pack(fill=tk.X, padx=8, pady=8)

        self._sys_send_var = tk.StringVar(value="↑ Send: —")
        self._sys_recv_var = tk.StringVar(value="↓ Recv: —")
        self._sys_errors_var = tk.StringVar(value="Errors: — | Drops: —")
        ttk.Label(sys_frame, textvariable=self._sys_send_var, style="Stat.TLabel").pack(
            anchor=tk.W, padx=8, pady=1)
        ttk.Label(sys_frame, textvariable=self._sys_recv_var, style="Stat.TLabel").pack(
            anchor=tk.W, padx=8, pady=1)
        ttk.Label(sys_frame, textvariable=self._sys_errors_var, style="Warning.TLabel").pack(
            anchor=tk.W, padx=8, pady=1)

        # Status / count label
        self._proc_status_var = tk.StringVar(value="Waiting for monitoring to start...")
        ttk.Label(tab, textvariable=self._proc_status_var, style="Dim.TLabel").pack(
            anchor=tk.W, padx=12, pady=(0, 2))

        # Process table inside a wrapper frame for reliable layout
        tree_frame = ttk.Frame(tab)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))

        columns = ("pid", "name", "send_rate", "recv_rate", "total_rate", "conns")
        self._proc_tree = ttk.Treeview(tree_frame, columns=columns, show="headings", height=15)
        proc_headings = {
            "pid": ("PID", 70), "name": ("Process", 200),
            "send_rate": ("↑ Send/s", 110), "recv_rate": ("↓ Recv/s", 110),
            "total_rate": ("⇅ Total/s", 110),
            "conns": ("Connections", 90),
        }
        for col, (text, width) in proc_headings.items():
            self._proc_tree.heading(col, text=text,
                                    command=lambda c=col: self._sort_proc_tree(c))
            anchor = tk.W if col == "name" else tk.CENTER
            self._proc_tree.column(col, width=width, anchor=anchor, minwidth=50)

        self._proc_sort_col = "total_rate"
        self._proc_sort_asc = False

        proc_scroll = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self._proc_tree.yview)
        self._proc_tree.configure(yscrollcommand=proc_scroll.set)
        self._proc_tree.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)
        proc_scroll.pack(fill=tk.Y, side=tk.RIGHT)
        self._bind_treeview_copy(self._proc_tree)

    # --- Tab 5: NIC Health ---

    def _build_nic_tab(self) -> None:
        """Build the NIC/cable health monitoring tab showing adapter stats and warnings."""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="  🔧 NIC Health  ")

        # Health warnings panel at top
        warn_frame = ttk.LabelFrame(tab, text="  Health Warnings  ")
        warn_frame.pack(fill=tk.X, padx=8, pady=(8, 4))

        self._nic_warn_var = tk.StringVar(value="Waiting for data...")
        self._nic_warn_label = ttk.Label(warn_frame, textvariable=self._nic_warn_var,
                                          style="Stat.TLabel", wraplength=900)
        self._nic_warn_label.pack(anchor=tk.W, padx=8, pady=6)

        # Clear counters button
        btn_frame = ttk.Frame(tab)
        btn_frame.pack(fill=tk.X, padx=8, pady=(0, 4))
        ttk.Button(btn_frame, text="↺ Clear Counters",
                   command=self._clear_nic_counters).pack(side=tk.LEFT)
        self._nic_baseline_note = tk.StringVar(value="")
        ttk.Label(btn_frame, textvariable=self._nic_baseline_note,
                  style="Dim.TLabel").pack(side=tk.LEFT, padx=10)

        # Baseline for counter subtraction (set when user clicks Clear)
        self._nic_baseline: Dict[str, Dict[str, int]] = {}

        # Adapter details table
        columns = ("name", "status", "speed", "duplex",
                   "rx_rate", "tx_rate", "total_rate",
                   "rx_err", "tx_err", "crc", "rx_disc", "tx_disc")
        self._nic_tree = ttk.Treeview(tab, columns=columns, show="headings", height=8)

        nic_headings = {
            "name": ("Adapter", 130), "status": ("Status", 80),
            "speed": ("Link Speed", 90), "duplex": ("Duplex", 60),
            "rx_rate": ("↓ Rx Rate", 90), "tx_rate": ("↑ Tx Rate", 90),
            "total_rate": ("Total", 90),
            "rx_err": ("Rx Err", 65), "tx_err": ("Tx Err", 65),
            "crc": ("CRC", 60),
            "rx_disc": ("Rx Disc", 65), "tx_disc": ("Tx Disc", 65),
        }
        for col, (text, width) in nic_headings.items():
            self._nic_tree.heading(col, text=text)
            anchor = tk.W if col == "name" else tk.CENTER
            self._nic_tree.column(col, width=width, anchor=anchor, minwidth=40)

        nic_scroll = ttk.Scrollbar(tab, orient=tk.VERTICAL, command=self._nic_tree.yview)
        self._nic_tree.configure(yscrollcommand=nic_scroll.set)
        self._nic_tree.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 4), side=tk.LEFT)
        nic_scroll.pack(fill=tk.Y, side=tk.RIGHT, pady=(0, 4), padx=(0, 8))
        self._bind_treeview_copy(self._nic_tree)

        # Error rate history (text)
        rate_frame = ttk.LabelFrame(tab, text="  Error Rates  ")
        rate_frame.pack(fill=tk.X, padx=8, pady=(0, 8), side=tk.BOTTOM)
        self._nic_rates_var = tk.StringVar(value="No data yet")
        ttk.Label(rate_frame, textvariable=self._nic_rates_var,
                  style="Dim.TLabel", font=("Consolas", 10)).pack(
            anchor=tk.W, padx=8, pady=4)

    # --- Tab 6: Wireshark Capture ---

    def _build_capture_tab(self) -> None:
        """Build the Wireshark packet capture and analysis tab."""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="  🦈 Wireshark  ")

        # ----- Controls row -----
        ctrl = ttk.LabelFrame(tab, text="  Capture Controls  ")
        ctrl.pack(fill=tk.X, padx=8, pady=(8, 4))

        row1 = ttk.Frame(ctrl)
        row1.pack(fill=tk.X, padx=8, pady=4)

        ttk.Label(row1, text="Interface:").pack(side=tk.LEFT, padx=(0, 5))
        self._cap_iface_var = tk.StringVar()
        self._cap_iface_combo = ttk.Combobox(
            row1, textvariable=self._cap_iface_var,
            state="readonly", width=40
        )
        self._cap_iface_combo.pack(side=tk.LEFT, padx=(0, 10))

        ttk.Button(row1, text="↻ Refresh", command=self._refresh_interfaces).pack(
            side=tk.LEFT, padx=(0, 15))

        ttk.Label(row1, text="Duration (sec):").pack(side=tk.LEFT, padx=(0, 5))
        self._cap_duration_var = tk.StringVar(value="30")
        ttk.Entry(row1, textvariable=self._cap_duration_var, width=6,
                  font=("Consolas", 10)).pack(side=tk.LEFT, padx=(0, 15))

        self._cap_start_btn = ttk.Button(
            row1, text="▶ Start Capture", style="Start.TButton",
            command=self._on_start_capture
        )
        self._cap_start_btn.pack(side=tk.LEFT, padx=3)

        self._cap_stop_btn = ttk.Button(
            row1, text="■ Stop", style="Stop.TButton",
            command=self._on_stop_capture, state=tk.DISABLED
        )
        self._cap_stop_btn.pack(side=tk.LEFT, padx=3)

        row2 = ttk.Frame(ctrl)
        row2.pack(fill=tk.X, padx=8, pady=(0, 4))

        ttk.Button(row2, text="📂 Open pcap file...", command=self._on_open_pcap).pack(
            side=tk.LEFT, padx=3)

        self._cap_status_var = tk.StringVar(value="")
        ttk.Label(row2, textvariable=self._cap_status_var, style="Dim.TLabel").pack(
            side=tk.LEFT, padx=10)

        # ----- Tshark availability notice -----
        self._cap_notice_var = tk.StringVar(value="Checking for Wireshark...")
        self._cap_notice_label = ttk.Label(ctrl, textvariable=self._cap_notice_var,
                                            style="Warning.TLabel")
        self._cap_notice_label.pack(anchor=tk.W, padx=8, pady=(0, 4))

        # ----- Analysis results -----
        results_frame = ttk.LabelFrame(tab, text="  Analysis Results  ")
        results_frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))

        # Severity header
        self._cap_severity_var = tk.StringVar(value="No analysis yet")
        self._cap_severity_label = ttk.Label(
            results_frame, textvariable=self._cap_severity_var,
            style="Header.TLabel", font=("Segoe UI", 14, "bold")
        )
        self._cap_severity_label.pack(anchor=tk.W, padx=8, pady=(8, 4))

        # Stats summary
        self._cap_stats_var = tk.StringVar(value="")
        ttk.Label(results_frame, textvariable=self._cap_stats_var,
                  style="Stat.TLabel", font=("Consolas", 10)).pack(
            anchor=tk.W, padx=8, pady=2)

        # Problem list
        self._cap_problems_text = scrolledtext.ScrolledText(
            results_frame, wrap=tk.WORD, font=("Consolas", 10),
            bg=COLORS["bg_secondary"], fg=COLORS["fg"],
            insertbackground=COLORS["fg"], selectbackground=COLORS["bg_input"],
            state=tk.DISABLED, relief=tk.FLAT, borderwidth=0, height=12,
        )
        self._cap_problems_text.pack(fill=tk.BOTH, expand=True, padx=8, pady=(4, 8))
        self._cap_problems_text.tag_configure("critical", foreground=COLORS["red"])
        self._cap_problems_text.tag_configure("warning", foreground=COLORS["yellow"])
        self._cap_problems_text.tag_configure("info", foreground=COLORS["green"])
        self._cap_problems_text.tag_configure("ok", foreground=COLORS["green"])

        # Initialize capture monitor (auto-detects tshark)
        self.capture_monitor = CaptureMonitor()
        self._update_capture_notice()

    def _update_capture_notice(self) -> None:
        """Update the tshark availability notice in the capture tab."""
        if self.capture_monitor and self.capture_monitor.tshark_available:
            self._cap_notice_var.set(f"✓ Wireshark found: {self.capture_monitor.tshark_path}")
            self._cap_notice_label.configure(style="Stat.TLabel")
            self._cap_start_btn.configure(state=tk.NORMAL)
        else:
            self._cap_notice_var.set(
                "⚠ Wireshark/tshark not found. Install Wireshark to enable live capture. "
                "You can still open and analyse existing .pcap files if tshark is available."
            )
            self._cap_notice_label.configure(style="Warning.TLabel")
            self._cap_start_btn.configure(state=tk.DISABLED)

    def _refresh_interfaces(self) -> None:
        """Refresh the list of available capture interfaces."""
        if not self.capture_monitor or not self.capture_monitor.tshark_available:
            return
        ifaces = self.capture_monitor.get_interfaces()
        if ifaces:
            display_list = [f"{iid}: {desc}" for iid, desc in ifaces]
            self._cap_iface_combo["values"] = display_list
            if display_list:
                self._cap_iface_combo.current(0)
        else:
            self._cap_iface_combo["values"] = ["No interfaces found"]

    def _on_start_capture(self) -> None:
        """Start a live packet capture."""
        if not self.capture_monitor or self.capture_monitor.is_capturing:
            return

        # Get interface ID (first part before ':')
        iface_str = self._cap_iface_var.get()
        if not iface_str or iface_str == "No interfaces found":
            messagebox.showwarning("No Interface", "Select a capture interface first.\n"
                                   "Click 'Refresh' to list available interfaces.")
            return

        iface_id = iface_str.split(":")[0].strip()

        try:
            duration = int(self._cap_duration_var.get())
            if duration < 1:
                duration = 10
        except ValueError:
            duration = 30

        self._cap_start_btn.configure(state=tk.DISABLED)
        self._cap_stop_btn.configure(state=tk.NORMAL)
        self._cap_status_var.set("Capturing...")

        self.capture_monitor.start_capture(
            interface=iface_id,
            duration=duration,
            output_dir=self.config.output_dir,
            callback=self._on_capture_done,
        )

        # Poll capture progress
        self._poll_capture_status()

    def _poll_capture_status(self) -> None:
        """Poll capture monitor for progress updates."""
        if self.capture_monitor and self.capture_monitor.is_capturing:
            self._cap_status_var.set(
                f"{self.capture_monitor.status} — {self.capture_monitor.progress}"
            )
            self.root.after(500, self._poll_capture_status)
        else:
            self._cap_start_btn.configure(
                state=tk.NORMAL if self.capture_monitor and self.capture_monitor.tshark_available else tk.DISABLED
            )
            self._cap_stop_btn.configure(state=tk.DISABLED)

    def _on_stop_capture(self) -> None:
        """Stop an in-progress capture."""
        if self.capture_monitor:
            self.capture_monitor.stop_capture()
            self._cap_status_var.set("Capture stopped")

    def _on_capture_done(self, analysis) -> None:
        """Callback from capture thread — update UI on main thread."""
        self._capture_analyses.append(analysis)
        self.root.after(0, lambda: self._display_analysis(analysis))

    def _on_open_pcap(self) -> None:
        """Open an existing pcap file for analysis."""
        filepath = filedialog.askopenfilename(
            title="Open Packet Capture",
            initialdir=os.getcwd(),
            filetypes=[
                ("Packet captures", "*.pcap *.pcapng *.cap"),
                ("All files", "*.*"),
            ]
        )
        if not filepath:
            return

        if not self.capture_monitor:
            self.capture_monitor = CaptureMonitor()

        if not self.capture_monitor.tshark_available:
            messagebox.showerror(
                "tshark Required",
                "tshark.exe is needed to analyse pcap files.\n"
                "Please install Wireshark and try again."
            )
            return

        self._cap_status_var.set(f"Analysing {os.path.basename(filepath)}...")

        # Run analysis in a background thread to keep UI responsive
        def _analyse():
            result = self.capture_monitor.analyse_pcap(filepath)
            self._capture_analyses.append(result)
            self.root.after(0, lambda: self._display_analysis(result))

        threading.Thread(target=_analyse, daemon=True, name="PcapAnalysis").start()

    def _display_analysis(self, analysis) -> None:
        """Display capture analysis results in the UI."""
        # Severity header with color
        severity_colors = {
            "OK": COLORS["green"],
            "Info": COLORS["accent"],
            "Warning": COLORS["yellow"],
            "Critical": COLORS["red"],
            "Unknown": COLORS["fg_dim"],
        }
        color = severity_colors.get(analysis.severity, COLORS["fg"])
        self._cap_severity_var.set(f"Overall: {analysis.severity}")
        self._cap_severity_label.configure(foreground=color)

        # Stats summary
        pcap_name = os.path.basename(analysis.pcap_path) if analysis.pcap_path else "N/A"
        stats_lines = [
            f"File: {pcap_name}  |  Packets: {analysis.total_packets:,}  |  "
            f"Duration: {analysis.capture_duration_sec:.0f}s",
            f"TCP Retrans: {analysis.tcp_retransmissions}  |  "
            f"Dup ACKs: {analysis.tcp_duplicate_acks}  |  "
            f"RSTs: {analysis.tcp_resets}  |  "
            f"Zero-Win: {analysis.tcp_zero_window}  |  "
            f"OOO: {analysis.tcp_out_of_order}",
            f"DNS Queries: {analysis.dns_queries}  |  "
            f"DNS Failures: {analysis.dns_failures}  |  "
            f"ICMP Unreach: {analysis.icmp_unreachable}",
        ]
        self._cap_stats_var.set("\n".join(stats_lines))

        # Problem details
        self._cap_problems_text.configure(state=tk.NORMAL)
        self._cap_problems_text.delete("1.0", tk.END)

        for problem in analysis.problems:
            if "CRITICAL" in problem:
                tag = "critical"
            elif "WARNING" in problem:
                tag = "warning"
            elif "INFO" in problem:
                tag = "info"
            else:
                tag = "ok"
            self._cap_problems_text.insert(tk.END, f"  • {problem}\n", tag)

        # DNS details
        if analysis.dns_detail:
            self._cap_problems_text.insert(tk.END, "\nFailed DNS Lookups:\n", "warning")
            for detail in analysis.dns_detail:
                self._cap_problems_text.insert(tk.END, f"    {detail}\n", "warning")

        self._cap_problems_text.configure(state=tk.DISABLED)

        self._cap_status_var.set(f"Analysis complete — {analysis.severity}")
        self._log_event(
            "INFO" if analysis.severity == "OK" else analysis.severity.upper(),
            "Wireshark",
            f"{analysis.total_packets} packets, {len(analysis.problems)} findings, "
            f"severity={analysis.severity}"
        )

    # --- Tab 7: Web Probe ---

    def _build_web_probe_tab(self) -> None:
        """Build the URL load timing & DNS diagnostics tab."""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="  🌐 Web Probe  ")

        # ----- URL input row -----
        input_frame = ttk.LabelFrame(tab, text="  URL Probe  ")
        input_frame.pack(fill=tk.X, padx=8, pady=(8, 4))

        row = ttk.Frame(input_frame)
        row.pack(fill=tk.X, padx=8, pady=6)

        ttk.Label(row, text="URL:").pack(side=tk.LEFT, padx=(0, 5))
        self._wp_url_var = tk.StringVar(value="https://")
        self._wp_url_entry = ttk.Entry(
            row, textvariable=self._wp_url_var, width=55,
            font=("Consolas", 11)
        )
        self._wp_url_entry.pack(side=tk.LEFT, padx=(0, 10), fill=tk.X, expand=True)
        self._wp_url_entry.bind("<Return>", lambda e: self._on_web_probe_go())

        self._wp_go_btn = ttk.Button(
            row, text="▶ Go", style="Start.TButton",
            command=self._on_web_probe_go
        )
        self._wp_go_btn.pack(side=tk.LEFT, padx=3)

        # Wireshark capture + Follow redirects options
        row2 = ttk.Frame(input_frame)
        row2.pack(fill=tk.X, padx=8, pady=(0, 6))

        self._wp_capture_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(row2, text="Capture with Wireshark during probe",
                         variable=self._wp_capture_var).pack(side=tk.LEFT, padx=(0, 15))

        self._wp_redirect_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(row2, text="Follow redirects",
                         variable=self._wp_redirect_var).pack(side=tk.LEFT, padx=(0, 15))

        self._wp_status_var = tk.StringVar(value="Enter a URL and click Go")
        ttk.Label(row2, textvariable=self._wp_status_var, style="Dim.TLabel").pack(
            side=tk.RIGHT, padx=5)

        # ----- Timing breakdown -----
        timing_frame = ttk.LabelFrame(tab, text="  Timing Breakdown  ")
        timing_frame.pack(fill=tk.X, padx=8, pady=(0, 4))

        # Phase bars - canvas for visual waterfall
        self._wp_waterfall = tk.Canvas(
            timing_frame, height=160, bg=COLORS["bg_secondary"],
            highlightthickness=0
        )
        self._wp_waterfall.pack(fill=tk.X, padx=8, pady=6)

        # ----- DNS Comparison -----
        dns_frame = ttk.LabelFrame(tab, text="  DNS Resolver Comparison  ")
        dns_frame.pack(fill=tk.X, padx=8, pady=(0, 4))

        cols = ("resolver", "ip", "resolved", "time", "status")
        self._wp_dns_tree = ttk.Treeview(
            dns_frame, columns=cols, show="headings", height=4,
            style="Dark.Treeview"
        )
        self._wp_dns_tree.heading("resolver", text="Resolver")
        self._wp_dns_tree.heading("ip", text="Server")
        self._wp_dns_tree.heading("resolved", text="Resolved IP")
        self._wp_dns_tree.heading("time", text="Time (ms)")
        self._wp_dns_tree.heading("status", text="Status")
        self._wp_dns_tree.column("resolver", width=130)
        self._wp_dns_tree.column("ip", width=110)
        self._wp_dns_tree.column("resolved", width=140)
        self._wp_dns_tree.column("time", width=90, anchor=tk.E)
        self._wp_dns_tree.column("status", width=200)
        self._wp_dns_tree.pack(fill=tk.X, padx=8, pady=4)

        # ----- Diagnosis / findings -----
        diag_frame = ttk.LabelFrame(tab, text="  Diagnosis  ")
        diag_frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))

        self._wp_diag_text = scrolledtext.ScrolledText(
            diag_frame, wrap=tk.WORD, font=("Consolas", 10),
            bg=COLORS["bg_secondary"], fg=COLORS["fg"],
            insertbackground=COLORS["fg"], selectbackground=COLORS["bg_input"],
            state=tk.DISABLED, relief=tk.FLAT, borderwidth=0, height=6,
        )
        self._wp_diag_text.pack(fill=tk.BOTH, expand=True, padx=8, pady=(4, 8))
        self._wp_diag_text.tag_configure("critical", foreground=COLORS["red"])
        self._wp_diag_text.tag_configure("warning", foreground=COLORS["yellow"])
        self._wp_diag_text.tag_configure("info", foreground=COLORS["green"])
        self._wp_diag_text.tag_configure("ok", foreground=COLORS["green"])
        self._wp_diag_text.tag_configure("header", foreground=COLORS["accent"],
                                          font=("Segoe UI", 11, "bold"))

        # ----- History treeview -----
        hist_frame = ttk.LabelFrame(tab, text="  Probe History  ")
        hist_frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))

        hist_cols = ("time", "url", "dns", "tcp", "tls", "ttfb", "download", "total", "status")
        self._wp_hist_tree = ttk.Treeview(
            hist_frame, columns=hist_cols, show="headings", height=5,
            style="Dark.Treeview"
        )
        self._wp_hist_tree.heading("time", text="Time")
        self._wp_hist_tree.heading("url", text="URL")
        self._wp_hist_tree.heading("dns", text="DNS")
        self._wp_hist_tree.heading("tcp", text="TCP")
        self._wp_hist_tree.heading("tls", text="TLS")
        self._wp_hist_tree.heading("ttfb", text="TTFB")
        self._wp_hist_tree.heading("download", text="Download")
        self._wp_hist_tree.heading("total", text="Total")
        self._wp_hist_tree.heading("status", text="HTTP")
        self._wp_hist_tree.column("time", width=70)
        self._wp_hist_tree.column("url", width=200)
        self._wp_hist_tree.column("dns", width=65, anchor=tk.E)
        self._wp_hist_tree.column("tcp", width=65, anchor=tk.E)
        self._wp_hist_tree.column("tls", width=65, anchor=tk.E)
        self._wp_hist_tree.column("ttfb", width=65, anchor=tk.E)
        self._wp_hist_tree.column("download", width=75, anchor=tk.E)
        self._wp_hist_tree.column("total", width=75, anchor=tk.E)
        self._wp_hist_tree.column("status", width=55, anchor=tk.CENTER)
        self._wp_hist_tree.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)

    def _on_web_probe_go(self) -> None:
        """Launch a web probe in a background thread."""
        url = self._wp_url_var.get().strip()
        if not url or url == "https://":
            return

        self._wp_go_btn.configure(state=tk.DISABLED)
        self._wp_status_var.set(f"Probing {url}...")

        # Optionally start Wireshark capture during the probe
        capture_active = False
        if self._wp_capture_var.get() and self.capture_monitor and self.capture_monitor.tshark_available:
            iface = getattr(self, '_cap_iface_var', None)
            iface_val = iface.get() if iface else ""
            if iface_val:
                iface_id = iface_val.split(".")[0].strip() if "." in iface_val else iface_val
                try:
                    self.capture_monitor.start_capture(
                        interface=iface_id, duration=30,
                        output_dir=self.config.output_dir,
                        callback=self._on_web_probe_capture_done,
                    )
                    capture_active = True
                    self._wp_status_var.set(f"Probing {url} (with Wireshark capture)...")
                except Exception:
                    pass

        follow = self._wp_redirect_var.get()

        def _run():
            result = self.web_probe.probe(url, follow_redirects=follow)
            self.root.after(0, lambda: self._display_web_probe(result))
            # If we started a capture, let it finish on its own

        threading.Thread(target=_run, daemon=True, name="WebProbe").start()

    def _on_web_probe_capture_done(self, analysis) -> None:
        """Callback when the Wireshark capture during a web probe finishes."""
        self._capture_analyses.append(analysis)
        self.root.after(0, lambda: self._display_analysis(analysis))
        self.root.after(0, lambda: self._log_event(
            "INFO", "Web Probe Capture",
            f"Capture complete: {analysis.total_packets} packets, {analysis.severity}"
        ))

    def _display_web_probe(self, result: WebProbeResult) -> None:
        """Display web probe results in the UI."""
        self._wp_go_btn.configure(state=tk.NORMAL)

        if result.error:
            self._wp_status_var.set(f"Error: {result.error}")
        else:
            self._wp_status_var.set(
                f"Done — {result.total_ms:.0f}ms total | "
                f"HTTP {result.status_code} | Bottleneck: {result.bottleneck}"
            )

        # ----- Draw waterfall timing chart -----
        self._draw_web_waterfall(result)

        # ----- DNS comparison table -----
        for item in self._wp_dns_tree.get_children():
            self._wp_dns_tree.delete(item)
        for dns in result.dns_comparisons:
            time_str = f"{dns.time_ms:.0f}" if dns.time_ms >= 0 else "—"
            status = dns.error if dns.error else "OK"
            server = dns.resolver_ip if dns.resolver_ip else "(system)"
            self._wp_dns_tree.insert("", tk.END, values=(
                dns.resolver_name, server, dns.resolved_ip,
                time_str, status
            ))

        # ----- Diagnosis text -----
        self._wp_diag_text.configure(state=tk.NORMAL)
        self._wp_diag_text.delete("1.0", tk.END)

        self._wp_diag_text.insert(tk.END,
            f"URL: {result.url}\n"
            f"Resolved IP: {result.resolved_ip}   |   "
            f"HTTP {result.status_code} {result.status_reason}   |   "
            f"Size: {result.content_length / 1024:.1f} KB\n\n",
            "header"
        )

        for diag in result.diagnosis:
            if "CRITICAL" in diag or "FATAL" in diag:
                tag = "critical"
            elif "WARNING" in diag:
                tag = "warning"
            elif "INFO" in diag:
                tag = "info"
            else:
                tag = "ok"
            self._wp_diag_text.insert(tk.END, f"  • {diag}\n", tag)

        self._wp_diag_text.configure(state=tk.DISABLED)

        # ----- Add to history -----
        def _fmt(ms):
            return f"{ms:.0f}ms" if ms >= 0 else "—"

        self._wp_hist_tree.insert("", 0, values=(
            result.timestamp.strftime("%H:%M:%S"),
            result.url[:60],
            _fmt(result.dns_ms), _fmt(result.tcp_connect_ms),
            _fmt(result.tls_handshake_ms), _fmt(result.ttfb_ms),
            _fmt(result.download_ms), _fmt(result.total_ms),
            str(result.status_code) if result.status_code else "ERR",
        ))

        # Log to event log
        self._log_event(
            "WARNING" if result.total_ms > 1000 else "INFO",
            "Web Probe",
            f"{result.url} — {result.total_ms:.0f}ms total, "
            f"bottleneck={result.bottleneck}"
        )

    def _draw_web_waterfall(self, result: WebProbeResult) -> None:
        """Draw a horizontal waterfall bar chart of probe phase timings."""
        canvas = self._wp_waterfall
        canvas.delete("all")

        w = canvas.winfo_width() or 800
        h = canvas.winfo_height() or 160

        phases = [
            ("DNS Resolution", result.dns_ms, "#89b4fa"),
            ("TCP Connect", result.tcp_connect_ms, "#94e2d5"),
            ("TLS Handshake", result.tls_handshake_ms, "#cba6f7"),
            ("TTFB (Server)", result.ttfb_ms, "#f9e2af"),
            ("Download", result.download_ms, "#a6e3a1"),
        ]

        # Filter out skipped phases
        active = [(name, ms, color) for name, ms, color in phases if ms > 0]
        if not active:
            canvas.create_text(w / 2, h / 2, text="No timing data",
                                fill=COLORS["fg_dim"], font=("Segoe UI", 12))
            return

        total = sum(ms for _, ms, _ in active)
        if total <= 0:
            return

        label_w = 130  # pixels for labels on the left
        bar_area = w - label_w - 80  # leave room for ms label on right
        bar_h = min(22, (h - 20) / max(len(active), 1) - 4)
        y_start = 10

        for i, (name, ms, color) in enumerate(active):
            y = y_start + i * (bar_h + 6)
            bar_w = max(4, (ms / total) * bar_area)

            # Phase label
            canvas.create_text(
                label_w - 5, y + bar_h / 2,
                text=name, anchor=tk.E, fill=COLORS["fg"],
                font=("Segoe UI", 9)
            )

            # Bar
            is_bottleneck = name == result.bottleneck
            outline = COLORS["red"] if is_bottleneck else ""
            bar_width = 2 if is_bottleneck else 0
            canvas.create_rectangle(
                label_w, y, label_w + bar_w, y + bar_h,
                fill=color, outline=outline, width=bar_width
            )

            # Time label
            label_color = COLORS["red"] if is_bottleneck else COLORS["fg_dim"]
            suffix = " ◄ BOTTLENECK" if is_bottleneck else ""
            canvas.create_text(
                label_w + bar_w + 5, y + bar_h / 2,
                text=f"{ms:.0f}ms{suffix}", anchor=tk.W,
                fill=label_color, font=("Consolas", 9, "bold" if is_bottleneck else "")
            )

        # Total at the bottom
        ty = y_start + len(active) * (bar_h + 6) + 4
        canvas.create_text(
            label_w, ty, text=f"Total: {result.total_ms:.0f}ms",
            anchor=tk.W, fill=COLORS["fg"],
            font=("Segoe UI", 10, "bold")
        )

    # --- Tab 8: Event Log ---

    def _build_log_tab(self) -> None:
        """Build the scrollable spike/anomaly event log."""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="  ⚡ Event Log  ")

        # Header with event count
        hdr = ttk.Frame(tab)
        hdr.pack(fill=tk.X, padx=8, pady=(8, 4))
        ttk.Label(hdr, text="Spike & Anomaly Events", style="Header.TLabel").pack(side=tk.LEFT)
        self._event_count_var = tk.StringVar(value="0 events")
        ttk.Label(hdr, textvariable=self._event_count_var, style="Dim.TLabel").pack(side=tk.RIGHT)

        # Clear button
        ttk.Button(hdr, text="Clear", command=self._clear_log).pack(side=tk.RIGHT, padx=8)

        # Scrolled text widget for events
        self.event_log = scrolledtext.ScrolledText(
            tab, wrap=tk.WORD, font=("Consolas", 10),
            bg=COLORS["bg_secondary"], fg=COLORS["fg"],
            insertbackground=COLORS["fg"], selectbackground=COLORS["bg_input"],
            state=tk.DISABLED, relief=tk.FLAT, borderwidth=0,
        )
        self.event_log.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))

        # Configure text tags for colored log entries
        self.event_log.tag_configure("spike", foreground=COLORS["orange"])
        self.event_log.tag_configure("warning", foreground=COLORS["yellow"])
        self.event_log.tag_configure("critical", foreground=COLORS["red"])
        self.event_log.tag_configure("info", foreground=COLORS["green"])
        self.event_log.tag_configure("timestamp", foreground=COLORS["fg_dim"])

    # --- Tab 8: Settings ---

    def _build_settings_tab(self) -> None:
        """Build the settings panel with all configurable options."""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="  ⚙ Settings  ")

        # Scrollable settings area
        canvas = tk.Canvas(tab, bg=COLORS["bg"], highlightthickness=0)
        scrollbar = ttk.Scrollbar(tab, orient=tk.VERTICAL, command=canvas.yview)
        settings_inner = ttk.Frame(canvas)
        settings_inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=settings_inner, anchor=tk.NW)
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=8, pady=8)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=8)

        # --- Setting groups ---
        self._setting_vars = {}

        # Ping Settings
        ping_frame = ttk.LabelFrame(settings_inner, text="  Ping Settings  ")
        ping_frame.pack(fill=tk.X, padx=4, pady=6)
        self._add_setting(ping_frame, "Ping Interval (sec):", "ping_interval", self.config.ping_interval)
        self._add_setting(ping_frame, "Ping Timeout (sec):", "ping_timeout", self.config.ping_timeout)
        self._add_setting(ping_frame, "Pings per Cycle:", "ping_count", self.config.ping_count)

        # Spike Detection
        spike_frame = ttk.LabelFrame(settings_inner, text="  Spike Detection  ")
        spike_frame.pack(fill=tk.X, padx=4, pady=6)
        self._add_setting(spike_frame, "Spike Threshold (ms):", "spike_threshold_ms", self.config.spike_threshold_ms)
        self._add_setting(spike_frame, "Loss Threshold (%):", "spike_loss_pct", self.config.spike_loss_pct)

        # Traceroute
        trace_frame = ttk.LabelFrame(settings_inner, text="  Traceroute  ")
        trace_frame.pack(fill=tk.X, padx=4, pady=6)
        self._setting_vars["monitor_traceroute"] = tk.BooleanVar(value=self.config.monitor_traceroute)
        ttk.Checkbutton(trace_frame, text="Enable Traceroute",
                         variable=self._setting_vars["monitor_traceroute"]).pack(anchor=tk.W, padx=8, pady=2)
        self._add_setting(trace_frame, "Trace Interval (sec):", "traceroute_interval", self.config.traceroute_interval)
        self._add_setting(trace_frame, "Max Hops:", "traceroute_max_hops", self.config.traceroute_max_hops)

        # Netstat
        ns_frame = ttk.LabelFrame(settings_inner, text="  Netstat Monitor  ")
        ns_frame.pack(fill=tk.X, padx=4, pady=6)
        self._setting_vars["monitor_netstat"] = tk.BooleanVar(value=self.config.monitor_netstat)
        ttk.Checkbutton(ns_frame, text="Enable Netstat Monitoring",
                         variable=self._setting_vars["monitor_netstat"]).pack(anchor=tk.W, padx=8, pady=2)
        self._add_setting(ns_frame, "Netstat Interval (sec):", "netstat_interval", self.config.netstat_interval)

        # Process Monitor
        proc_frame = ttk.LabelFrame(settings_inner, text="  Process Monitor  ")
        proc_frame.pack(fill=tk.X, padx=4, pady=6)
        self._setting_vars["monitor_processes"] = tk.BooleanVar(value=self.config.monitor_processes)
        ttk.Checkbutton(proc_frame, text="Enable Process Monitoring",
                         variable=self._setting_vars["monitor_processes"]).pack(anchor=tk.W, padx=8, pady=2)
        self._add_setting(proc_frame, "Process Interval (sec):", "process_interval", self.config.process_interval)

        # Reporting
        report_frame = ttk.LabelFrame(settings_inner, text="  Reporting  ")
        report_frame.pack(fill=tk.X, padx=4, pady=6)
        self._add_setting(report_frame, "Report Interval (sec):", "report_interval", self.config.report_interval)
        self._add_setting(report_frame, "Output Directory:", "output_dir", self.config.output_dir, width=30)

        self._setting_vars["report_format"] = tk.StringVar(value=self.config.report_format)
        fmt_row = ttk.Frame(report_frame)
        fmt_row.pack(fill=tk.X, padx=8, pady=3)
        ttk.Label(fmt_row, text="Report Format:").pack(side=tk.LEFT, padx=(0, 8))
        ttk.Combobox(fmt_row, textvariable=self._setting_vars["report_format"],
                      values=["csv", "html", "both"], state="readonly", width=10).pack(side=tk.LEFT)

        # Config file buttons
        btn_frame = ttk.Frame(settings_inner)
        btn_frame.pack(fill=tk.X, padx=4, pady=10)
        ttk.Button(btn_frame, text="Load Config...", command=self._load_config).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_frame, text="Save Config...", command=self._save_config).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_frame, text="Reset Defaults", command=self._reset_defaults).pack(side=tk.LEFT, padx=4)

    def _add_setting(self, parent: ttk.Frame, label: str, key: str,
                      default, width: int = 12) -> None:
        """Helper to create a labeled entry row in the settings panel."""
        row = ttk.Frame(parent)
        row.pack(fill=tk.X, padx=8, pady=3)
        ttk.Label(row, text=label).pack(side=tk.LEFT, padx=(0, 8))
        sv = tk.StringVar(value=str(default))
        entry = ttk.Entry(row, textvariable=sv, width=width, font=("Consolas", 10))
        entry.pack(side=tk.LEFT)
        self._setting_vars[key] = sv

    # -----------------------------------------------------------------------
    #  Status Bar
    # -----------------------------------------------------------------------

    def _build_status_bar(self) -> None:
        """Build the bottom status bar showing running state and version."""
        bar = ttk.Frame(self.root, style="Card.TFrame")
        bar.pack(fill=tk.X, side=tk.BOTTOM, padx=0, pady=0)

        self._status_var = tk.StringVar(value="Ready — configure targets and press Start")
        ttk.Label(bar, textvariable=self._status_var, style="Dim.TLabel").pack(
            side=tk.LEFT, padx=10, pady=4)
        ttk.Label(bar, text=f"{__app_name__} v{__version__}", style="Dim.TLabel").pack(
            side=tk.RIGHT, padx=10, pady=4)

    # -----------------------------------------------------------------------
    #  Start / Stop / Report Actions
    # -----------------------------------------------------------------------

    def _apply_settings(self) -> None:
        """Read all setting widgets back into self.config before starting."""
        # Targets from toolbar entry
        raw_targets = self._target_var.get()
        targets = [t.strip() for t in raw_targets.replace(";", ",").split(",") if t.strip()]
        if not targets:
            targets = ["8.8.8.8"]
        self.config.targets = targets

        # Numeric / string settings from the settings tab
        float_keys = [
            "ping_interval", "ping_timeout", "spike_threshold_ms", "spike_loss_pct",
            "traceroute_interval", "netstat_interval", "process_interval", "report_interval",
        ]
        int_keys = ["ping_count", "traceroute_max_hops"]
        str_keys = ["output_dir"]
        bool_keys = ["monitor_traceroute", "monitor_netstat", "monitor_processes"]

        for key in float_keys:
            try:
                setattr(self.config, key, float(self._setting_vars[key].get()))
            except (ValueError, KeyError):
                pass

        for key in int_keys:
            try:
                setattr(self.config, key, int(self._setting_vars[key].get()))
            except (ValueError, KeyError):
                pass

        for key in str_keys:
            try:
                setattr(self.config, key, self._setting_vars[key].get())
            except KeyError:
                pass

        for key in bool_keys:
            try:
                setattr(self.config, key, self._setting_vars[key].get())
            except KeyError:
                pass

        # Report format from combobox
        try:
            self.config.report_format = self._setting_vars["report_format"].get()
        except KeyError:
            pass

    def _on_start(self) -> None:
        """Start all monitoring subsystems and begin UI refresh loops."""
        if self.is_running:
            return

        # Apply current settings
        self._apply_settings()

        # Set up logging (first time or re-init)
        setup_logger(
            name="netprobe",
            log_dir=os.path.join(self.config.output_dir, "logs"),
            console_level=logging.DEBUG if self.config.verbose else logging.INFO,
        )

        logger.info("GUI: Starting monitoring — targets=%s", self.config.targets)

        # ----- Initialize chart data -----
        self._chart_data = {t: deque(maxlen=CHART_MAX_POINTS) for t in self.config.targets}
        self._chart_timestamps = deque(maxlen=CHART_MAX_POINTS)

        # Update target combo boxes
        self._chart_target_combo["values"] = self.config.targets
        self._chart_target_var.set(self.config.targets[0] if self.config.targets else "")
        self._trace_target_combo["values"] = self.config.targets
        self._trace_target_var.set(self.config.targets[0] if self.config.targets else "")

        # Rebuild stat cards for current targets
        self._rebuild_stat_cards()

        # ----- Create monitors -----
        self.ping_monitor = PingMonitor(
            targets=self.config.targets,
            interval=self.config.ping_interval,
            timeout=self.config.ping_timeout,
            count=self.config.ping_count,
            spike_threshold_ms=self.config.spike_threshold_ms,
        )

        self.traceroute_monitor = None
        if self.config.monitor_traceroute:
            self.traceroute_monitor = TracerouteMonitor(
                targets=self.config.targets,
                interval=self.config.traceroute_interval,
                max_hops=self.config.traceroute_max_hops,
                timeout=self.config.ping_timeout,
            )

        self.netstat_monitor = None
        if self.config.monitor_netstat:
            self.netstat_monitor = NetstatMonitor(interval=self.config.netstat_interval)

        self.process_monitor = None
        if self.config.monitor_processes and PSUTIL_AVAILABLE:
            self.process_monitor = ProcessMonitor(interval=self.config.process_interval)

        # v1.2.0: NIC Health monitor (always enabled — low overhead)
        self.nic_monitor = NicMonitor(interval=10.0)

        self.reporter = Reporter(
            config=self.config,
            ping_monitor=self.ping_monitor,
            traceroute_monitor=self.traceroute_monitor,
            netstat_monitor=self.netstat_monitor,
            process_monitor=self.process_monitor,
            capture_analyses=self._capture_analyses,
        )

        # Start monitors
        self.ping_monitor.start()
        if self.traceroute_monitor:
            self.traceroute_monitor.start()
        if self.netstat_monitor:
            self.netstat_monitor.start()
        if self.process_monitor:
            self.process_monitor.start()
        if self.nic_monitor:
            self.nic_monitor.start()
        self.reporter.start()

        # Update UI state
        self.is_running = True
        self._start_ts = time.monotonic()
        self._start_btn.configure(state=tk.DISABLED)
        self._stop_btn.configure(state=tk.NORMAL)
        self._report_btn.configure(state=tk.NORMAL)
        self._open_report_btn.configure(state=tk.NORMAL)
        self._target_entry.configure(state=tk.DISABLED)
        self._status_var.set("Monitoring active — collecting data...")

        # Begin UI refresh callbacks
        self._schedule_refresh()
        self._schedule_chart_refresh()

        self._log_event("INFO", "Monitoring started", f"Targets: {', '.join(self.config.targets)}")

    def _on_stop(self) -> None:
        """Stop all monitoring subsystems."""
        if not self.is_running:
            return

        logger.info("GUI: Stopping monitoring")
        self.is_running = False

        # Stop monitors
        if self.ping_monitor:
            self.ping_monitor.stop()
        if self.traceroute_monitor:
            self.traceroute_monitor.stop()
        if self.netstat_monitor:
            self.netstat_monitor.stop()
        if self.process_monitor:
            self.process_monitor.stop()
        if self.nic_monitor:
            self.nic_monitor.stop()
        if self.reporter:
            self.reporter.stop()

        # Update UI state
        self._start_btn.configure(state=tk.NORMAL)
        self._stop_btn.configure(state=tk.DISABLED)
        self._target_entry.configure(state=tk.NORMAL)

        elapsed = time.monotonic() - self._start_ts if self._start_ts else 0
        self._time_var.set(f"Stopped after {self._fmt_duration(elapsed)}")
        self._status_var.set("Monitoring stopped")

        self._log_event("INFO", "Monitoring stopped", f"Duration: {self._fmt_duration(elapsed)}")

    def _on_save_report(self) -> None:
        """Generate and save the final report."""
        if not self.reporter:
            return
        self.reporter.write_final_report()
        output_path = os.path.abspath(self.config.output_dir)
        self._status_var.set(f"Reports saved to {output_path}")
        self._log_event("INFO", "Report saved", f"Output: {output_path}")
        self._open_report_btn.configure(state=tk.NORMAL)
        messagebox.showinfo("Report Saved", f"Reports written to:\n{output_path}")

    def _on_open_report(self) -> None:
        """Open the latest HTML report in the default browser."""
        output_dir = os.path.abspath(self.config.output_dir)
        if not os.path.isdir(output_dir):
            messagebox.showwarning("No Reports", "Output directory does not exist yet.")
            return
        # Find the newest report_*.html file
        html_files = [
            f for f in os.listdir(output_dir)
            if f.startswith("report_") and f.endswith(".html")
        ]
        if not html_files:
            messagebox.showwarning("No Reports", "No HTML reports found in the output directory.")
            return
        html_files.sort(reverse=True)  # Newest first (timestamp in filename)
        latest = os.path.join(output_dir, html_files[0])
        import webbrowser
        webbrowser.open(latest)
        self._status_var.set(f"Opened: {latest}")

    def _on_close(self) -> None:
        """Handle window close — stop monitors first."""
        if self.is_running:
            self._on_stop()
            # Give monitors a moment to shut down
            self.root.after(500, self.root.destroy)
        else:
            self.root.destroy()

    # -----------------------------------------------------------------------
    #  Settings Actions
    # -----------------------------------------------------------------------

    def _load_config(self) -> None:
        """Load configuration from a JSON file."""
        filepath = filedialog.askopenfilename(
            title="Load Configuration",
            initialdir=os.getcwd(),
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if filepath:
            try:
                self.config = ProbeConfig.load(filepath)
                self._populate_settings_from_config()
                self._status_var.set(f"Config loaded: {filepath}")
            except Exception as exc:
                messagebox.showerror("Load Error", f"Failed to load config:\n{exc}")

    def _save_config(self) -> None:
        """Save current configuration to a JSON file."""
        self._apply_settings()
        filepath = filedialog.asksaveasfilename(
            title="Save Configuration",
            initialdir=os.getcwd(),
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if filepath:
            try:
                self.config.save(filepath)
                self._status_var.set(f"Config saved: {filepath}")
            except Exception as exc:
                messagebox.showerror("Save Error", f"Failed to save config:\n{exc}")

    def _reset_defaults(self) -> None:
        """Reset all settings to defaults."""
        self.config = ProbeConfig()
        self._populate_settings_from_config()
        self._status_var.set("Settings reset to defaults")

    def _populate_settings_from_config(self) -> None:
        """Push config values into the settings widgets."""
        self._target_var.set(", ".join(self.config.targets))

        mapping = {
            "ping_interval": self.config.ping_interval,
            "ping_timeout": self.config.ping_timeout,
            "ping_count": self.config.ping_count,
            "spike_threshold_ms": self.config.spike_threshold_ms,
            "spike_loss_pct": self.config.spike_loss_pct,
            "traceroute_interval": self.config.traceroute_interval,
            "traceroute_max_hops": self.config.traceroute_max_hops,
            "netstat_interval": self.config.netstat_interval,
            "process_interval": self.config.process_interval,
            "report_interval": self.config.report_interval,
            "output_dir": self.config.output_dir,
            "report_format": self.config.report_format,
            "monitor_traceroute": self.config.monitor_traceroute,
            "monitor_netstat": self.config.monitor_netstat,
            "monitor_processes": self.config.monitor_processes,
        }
        for key, val in mapping.items():
            if key in self._setting_vars:
                self._setting_vars[key].set(str(val) if not isinstance(val, bool) else val)

    # -----------------------------------------------------------------------
    #  UI Refresh Callbacks
    # -----------------------------------------------------------------------

    def _schedule_refresh(self) -> None:
        """Schedule the next data refresh cycle if still running."""
        if not self.is_running:
            return
        try:
            self._refresh_data()
        except Exception as exc:
            logger.error("Error in _refresh_data: %s", exc, exc_info=True)
        self.root.after(UI_REFRESH_MS, self._schedule_refresh)

    def _schedule_chart_refresh(self) -> None:
        """Schedule the next chart redraw cycle if still running."""
        if not self.is_running:
            return
        try:
            self._update_chart_data()
            self._draw_chart()
        except Exception as exc:
            logger.error("Error in chart refresh: %s", exc, exc_info=True)
        self.root.after(CHART_REFRESH_MS, self._schedule_chart_refresh)

    def _refresh_data(self) -> None:
        """
        Poll all monitors for latest data and update the UI widgets.
        This runs on the tkinter main thread via after(), so it's safe
        to modify widgets directly.
        """
        if not self.is_running:
            return

        # Update running time
        if self._start_ts:
            elapsed = time.monotonic() - self._start_ts
            self._time_var.set(f"Running: {self._fmt_duration(elapsed)}")

        # ----- Ping stats -----
        if self.ping_monitor:
            for target, vars_dict in self._stat_frames.items():
                stats = self.ping_monitor.get_stats(target)
                latest = self.ping_monitor.get_latest(target)

                if latest and latest.latency_ms is not None:
                    vars_dict["last"].set(f"{latest.latency_ms:.1f} ms")
                elif latest and latest.is_timeout:
                    vars_dict["last"].set("TIMEOUT")

                vars_dict["avg"].set(f"{stats['avg']:.1f} ms")
                vars_dict["min"].set(f"{stats['min']:.1f} ms")
                vars_dict["max"].set(f"{stats['max']:.1f} ms")
                vars_dict["loss"].set(f"{stats['loss_pct']:.1f} %")
                vars_dict["jitter"].set(f"{stats['jitter']:.1f} ms")
                vars_dict["sent"].set(str(stats['sent']))

                # Log spikes to event log
                if latest and latest.latency_ms and latest.latency_ms > self.config.spike_threshold_ms:
                    self._log_event(
                        "SPIKE", target,
                        f"{latest.latency_ms:.1f}ms (threshold: {self.config.spike_threshold_ms:.0f}ms)"
                    )
                elif latest and latest.is_timeout:
                    self._log_event("CRITICAL", target, "Request timed out")

        # ----- Traceroute -----
        if self.traceroute_monitor:
            target = self._trace_target_var.get()
            if target:
                hops = self.traceroute_monitor.get_hops(target)
                # Clear and repopulate the treeview
                self._trace_tree.delete(*self._trace_tree.get_children())
                for hop in hops:
                    host = hop.hostname if hop.hostname != "*" else hop.ip_address
                    tags = ()
                    if hop.loss_pct > self.config.spike_loss_pct and hop.sent >= 6:
                        tags = ("loss",)
                    self._trace_tree.insert("", tk.END, values=(
                        hop.hop_number, host,
                        f"{hop.loss_pct:.1f}%", hop.sent, hop.received,
                        f"{hop.avg_ms:.1f}", f"{hop.min_ms:.1f}",
                        f"{hop.max_ms:.1f}", f"{hop.jitter_ms:.1f}",
                    ), tags=tags)
                self._trace_tree.tag_configure("loss", foreground=COLORS["red"])

        # ----- Netstat -----
        if self.netstat_monitor:
            snap = self.netstat_monitor.get_latest()
            if snap:
                self._ns_total_var.set(f"Total connections: {snap.total_count}")
                tcp = snap.protocol_counts.get("TCP", 0)
                udp = snap.protocol_counts.get("UDP", 0)
                self._ns_proto_var.set(f"TCP: {tcp}  |  UDP: {udp}")

                # Remember which state nodes are expanded so we can restore them
                expanded_states = set()
                for item in self._ns_tree.get_children():
                    if self._ns_tree.item(item, "open"):
                        vals = self._ns_tree.item(item, "values")
                        if vals:
                            expanded_states.add(vals[0])

                self._ns_tree.delete(*self._ns_tree.get_children())

                # Group connections by state
                conns_by_state: Dict[str, list] = {}
                for conn in snap.connections:
                    st = conn.state or "(stateless)"
                    conns_by_state.setdefault(st, []).append(conn)

                for state, count in sorted(snap.state_counts.items(), key=lambda x: -x[1]):
                    indicator = ""
                    tags = ()
                    if state == "TIME_WAIT" and count > 500:
                        indicator = "HIGH — possible churn"
                        tags = ("warn",)
                    elif state == "CLOSE_WAIT" and count > 50:
                        indicator = "HIGH — possible leak"
                        tags = ("warn",)
                    elif state == "SYN_SENT" and count > 20:
                        indicator = "HIGH — stalled connections"
                        tags = ("warn",)
                    elif state == "ESTABLISHED":
                        indicator = "OK"
                        tags = ("ok",)
                    elif state == "LISTENING":
                        indicator = "OK"
                        tags = ("ok",)
                    else:
                        indicator = "Normal"

                    # Insert state as expandable parent row
                    parent_id = self._ns_tree.insert(
                        "", tk.END, values=(state, count, indicator),
                        tags=tags, open=(state in expanded_states),
                    )

                    # Insert individual connections as children
                    for conn in conns_by_state.get(state, [])[:200]:  # cap at 200
                        # Resolve PID to process name
                        pid_int = int(conn.pid) if conn.pid else 0
                        if pid_int:
                            proc_name = self._resolve_pid_name(pid_int)
                            pid_str = f"{proc_name} (PID {pid_int})"
                        else:
                            pid_str = ""

                        # Resolve remote IP to hostname if nslookup is enabled
                        remote = conn.remote_address
                        if self._ns_nslookup_var.get() and remote and remote != "*:*":
                            remote_ip = remote.rsplit(":", 1)[0]  # strip port
                            hostname = self._dns_cache.get(remote_ip)
                            if hostname and hostname != remote_ip:
                                port = remote.rsplit(":", 1)[-1] if ":" in remote else ""
                                remote = f"{hostname}:{port}" if port else hostname
                            elif remote_ip not in self._dns_cache and remote_ip not in self._dns_pending:
                                self._start_dns_lookup(remote_ip)

                        detail = f"{conn.protocol}  {conn.local_address}  →  {remote}"
                        self._ns_tree.insert(
                            parent_id, tk.END,
                            values=("", pid_str, detail),
                            tags=("child",),
                        )

                self._ns_tree.tag_configure("warn", foreground=COLORS["yellow"])
                self._ns_tree.tag_configure("ok", foreground=COLORS["green"])
                self._ns_tree.tag_configure("child", foreground=COLORS["fg_dim"])

                if self._ns_nslookup_var.get():
                    pending = len(self._dns_pending)
                    cached = len(self._dns_cache)
                    self._ns_lookup_status.set(
                        f"DNS cache: {cached} resolved, {pending} pending"
                    )
                else:
                    self._ns_lookup_status.set("")

        # ----- Process Monitor -----
        if self.process_monitor:
            snap = self.process_monitor.get_latest()
            if snap:
                sio = snap.system_io
                self._sys_send_var.set(f"↑ Send: {_format_rate(sio.bytes_sent_per_sec)}")
                self._sys_recv_var.set(f"↓ Recv: {_format_rate(sio.bytes_recv_per_sec)}")
                self._sys_errors_var.set(
                    f"Errors: in={sio.errin} out={sio.errout} | "
                    f"Drops: in={sio.dropin} out={sio.dropout}"
                )

                self._proc_tree.delete(*self._proc_tree.get_children())
                if snap.top_talkers:
                    self._proc_status_var.set(
                        f"{len(snap.top_talkers)} processes with network activity "
                        f"(of {snap.total_processes_with_net} total)"
                    )
                    for proc in snap.top_talkers[:15]:
                        self._proc_tree.insert("", tk.END, values=(
                            proc.pid, proc.name,
                            _format_rate(proc.bytes_sent_per_sec),
                            _format_rate(proc.bytes_recv_per_sec),
                            _format_rate(proc.bytes_sent_per_sec + proc.bytes_recv_per_sec),
                            proc.connections,
                        ))
                else:
                    self._proc_status_var.set("Collecting data — waiting for rate calculations...")
            else:
                self._proc_status_var.set("Waiting for first process snapshot (~5s)...")

        # ----- NIC Health -----
        if self.nic_monitor:
            snap = self.nic_monitor.get_latest()
            if snap:
                # Update warnings
                if snap.health_warnings:
                    # Separate actionable warnings from routine disconnects
                    active_warnings = []
                    for w in snap.health_warnings:
                        # Disconnected adapters are normal if they were already known
                        if "DISCONNECTED" in w:
                            # Extract adapter name (format: "AdapterName: DISCONNECTED ...")
                            adapter_name = w.split(":")[0].strip()
                            if adapter_name not in self._logged_nic_disconnects:
                                self._logged_nic_disconnects.add(adapter_name)
                                self._log_event("INFO", "NIC", w)
                        else:
                            self._log_event("WARNING", "NIC", w)
                        active_warnings.append(w)

                    self._nic_warn_var.set("\n".join(active_warnings))
                    # Use Error style only for non-disconnect warnings
                    has_real_errors = any("DISCONNECTED" not in w for w in active_warnings)
                    self._nic_warn_label.configure(
                        style="Error.TLabel" if has_real_errors else "Warning.TLabel"
                    )
                else:
                    self._nic_warn_var.set("✓ All adapters healthy — no errors detected")
                    self._nic_warn_label.configure(style="Stat.TLabel")
                    # Clear tracked disconnects when all is healthy
                    self._logged_nic_disconnects.clear()

                # Update adapter table
                self._nic_tree.delete(*self._nic_tree.get_children())
                for nic in snap.adapters:
                    speed_str = (f"{nic.link_speed_mbps:.0f} Mbps"
                                 if nic.link_speed_mbps > 0 else "—")
                    duplex_str = "Full" if nic.full_duplex else "HALF"
                    tags = ()
                    if nic.status == "Disconnected":
                        tags = ("disconn",)
                    elif (nic.recv_errors > 0 or nic.send_errors > 0
                          or nic.recv_crc_errors > 0):
                        tags = ("errors",)

                    # Subtract baseline if set
                    bl = self._nic_baseline.get(nic.name, {})
                    rx_err = max(0, nic.recv_errors - bl.get("rx_err", 0))
                    tx_err = max(0, nic.send_errors - bl.get("tx_err", 0))
                    crc = max(0, nic.recv_crc_errors - bl.get("crc", 0))
                    rx_disc = max(0, nic.recv_discards - bl.get("rx_disc", 0))
                    tx_disc = max(0, nic.send_discards - bl.get("tx_disc", 0))

                    # Autoscaling throughput rates
                    rx_rate = self._format_bitrate(nic.recv_bytes_per_sec)
                    tx_rate = self._format_bitrate(nic.send_bytes_per_sec)
                    total_rate = self._format_bitrate(
                        nic.recv_bytes_per_sec + nic.send_bytes_per_sec)

                    self._nic_tree.insert("", tk.END, values=(
                        nic.name, nic.status, speed_str, duplex_str,
                        rx_rate, tx_rate, total_rate,
                        rx_err, tx_err, crc, rx_disc, tx_disc,
                    ), tags=tags)

                self._nic_tree.tag_configure("disconn", foreground=COLORS["red"])
                self._nic_tree.tag_configure("errors", foreground=COLORS["yellow"])

                # Error rates
                rate_parts = []
                for nic in snap.adapters:
                    if nic.status == "Up":
                        rate_parts.append(
                            f"{nic.name}: Rx err={nic.recv_errors_per_sec:.1f}/s  "
                            f"Tx err={nic.send_errors_per_sec:.1f}/s  "
                            f"CRC={nic.crc_errors_per_sec:.1f}/s"
                        )
                self._nic_rates_var.set(
                    "  |  ".join(rate_parts) if rate_parts else "No active adapters"
                )

        # ----- Spike events from reporter -----
        if self.reporter:
            with self.reporter._lock:
                count = len(self.reporter.spike_events)
            self._event_count_var.set(f"{count} events")

    # -----------------------------------------------------------------------
    #  Chart Drawing (Canvas-based latency graph)
    # -----------------------------------------------------------------------

    def _update_chart_data(self) -> None:
        """Pull latest ping data into the chart deques."""
        if not self.ping_monitor:
            return

        now_str = datetime.now().strftime("%H:%M:%S")

        for target in self.config.targets:
            latest = self.ping_monitor.get_latest(target)
            if target not in self._chart_data:
                self._chart_data[target] = deque(maxlen=CHART_MAX_POINTS)

            if latest:
                self._chart_data[target].append(latest.latency_ms)  # None if timeout
            else:
                self._chart_data[target].append(None)

        self._chart_timestamps.append(now_str)

    def _draw_chart(self) -> None:
        """
        Render the latency time-series chart on the canvas.
        Draws grid lines, Y-axis labels, latency polyline, and spike markers.
        """
        canvas = self.chart_canvas
        canvas.delete("all")

        w = canvas.winfo_width()
        h = canvas.winfo_height()
        if w < 100 or h < 50:
            return  # Too small to draw

        target = self._chart_target_var.get()
        data = list(self._chart_data.get(target, []))
        timestamps = list(self._chart_timestamps)

        # Compute the plotting area boundaries
        left = CHART_MARGIN_L
        right = w - CHART_MARGIN_R
        top = CHART_MARGIN_T
        bottom = h - CHART_MARGIN_B
        plot_w = right - left
        plot_h = bottom - top

        if plot_w < 20 or plot_h < 20:
            return

        # Determine Y-axis range from data
        valid = [v for v in data if v is not None]
        if valid:
            y_min = 0
            y_max = max(valid) * 1.2  # 20% headroom
            y_max = max(y_max, 10)    # Minimum 10ms range
        else:
            y_min, y_max = 0, 100

        # Draw background
        canvas.create_rectangle(left, top, right, bottom,
                                 fill=COLORS["bg_secondary"], outline=COLORS["surface0"])

        # Draw horizontal grid lines and Y-axis labels
        num_grid_lines = 5
        for i in range(num_grid_lines + 1):
            y_val = y_min + (y_max - y_min) * (i / num_grid_lines)
            y_px = bottom - (i / num_grid_lines) * plot_h

            # Grid line
            canvas.create_line(left, y_px, right, y_px, fill=COLORS["grid"], dash=(2, 4))
            # Y-axis label
            canvas.create_text(left - 5, y_px, text=f"{y_val:.0f}",
                                anchor=tk.E, fill=COLORS["fg_dim"],
                                font=("Consolas", 8))

        # Y-axis title
        canvas.create_text(12, (top + bottom) / 2, text="ms", angle=90,
                            fill=COLORS["fg_dim"], font=("Consolas", 9))

        # Draw spike threshold line
        threshold = self.config.spike_threshold_ms
        if y_min <= threshold <= y_max:
            th_px = bottom - ((threshold - y_min) / (y_max - y_min)) * plot_h
            canvas.create_line(left, th_px, right, th_px,
                                fill=COLORS["red"], dash=(6, 3), width=1)
            canvas.create_text(right - 2, th_px - 8, text=f"spike: {threshold:.0f}ms",
                                anchor=tk.E, fill=COLORS["red"], font=("Consolas", 8))

        # Draw average latency dotted line
        if valid:
            avg = sum(valid) / len(valid)
            if y_min <= avg <= y_max:
                avg_px = bottom - ((avg - y_min) / (y_max - y_min)) * plot_h
                canvas.create_line(left, avg_px, right, avg_px,
                                    fill=COLORS["green"], dash=(4, 6), width=1)
                canvas.create_text(left + 4, avg_px - 8, text=f"avg: {avg:.1f}ms",
                                    anchor=tk.W, fill=COLORS["green"], font=("Consolas", 8))

        # Plot the latency data points
        if len(data) < 2:
            canvas.create_text((left + right) / 2, (top + bottom) / 2,
                                text="Collecting data...", fill=COLORS["fg_dim"],
                                font=("Segoe UI", 12))
            return

        n = len(data)
        x_step = plot_w / max(n - 1, 1)

        # Build the polyline coordinates and mark spikes
        line_coords = []
        spike_points = []
        timeout_xs = []

        for i, val in enumerate(data):
            x = left + i * x_step
            if val is not None:
                y_frac = (val - y_min) / (y_max - y_min) if (y_max - y_min) > 0 else 0
                y = bottom - y_frac * plot_h
                line_coords.extend([x, y])
                if val > threshold:
                    spike_points.append((x, y, val))
            else:
                # Timeout — break the line and mark with an X
                if line_coords:
                    # Draw what we have so far
                    if len(line_coords) >= 4:
                        canvas.create_line(line_coords, fill=COLORS["chart_line"],
                                            width=2, smooth=True)
                    line_coords = []
                timeout_xs.append(x)

        # Draw remaining polyline
        if len(line_coords) >= 4:
            canvas.create_line(line_coords, fill=COLORS["chart_line"],
                                width=2, smooth=True)
        elif len(line_coords) == 2:
            # Single point — draw a dot
            canvas.create_oval(line_coords[0] - 3, line_coords[1] - 3,
                                line_coords[0] + 3, line_coords[1] + 3,
                                fill=COLORS["chart_line"], outline="")

        # Draw spike markers (red dots)
        for sx, sy, sval in spike_points:
            canvas.create_oval(sx - 4, sy - 4, sx + 4, sy + 4,
                                fill=COLORS["chart_spike"], outline=COLORS["red"])

        # Draw timeout markers (red X)
        for tx in timeout_xs:
            size = 5
            canvas.create_line(tx - size, top + 5, tx + size, top + 15,
                                fill=COLORS["red"], width=2)
            canvas.create_line(tx - size, top + 15, tx + size, top + 5,
                                fill=COLORS["red"], width=2)

        # X-axis time labels (show every ~10th label to avoid overlap)
        if timestamps:
            label_step = max(1, len(timestamps) // 8)
            for i in range(0, len(timestamps), label_step):
                if i < n:
                    x = left + i * x_step
                    canvas.create_text(x, bottom + 12, text=timestamps[i],
                                        fill=COLORS["fg_dim"], font=("Consolas", 7),
                                        angle=0)

        # Stats text in top-right corner
        if valid:
            avg = sum(valid) / len(valid)
            stats_text = f"avg={avg:.1f}ms  min={min(valid):.1f}ms  max={max(valid):.1f}ms"
            canvas.create_text(right - 5, top + 10, text=stats_text,
                                anchor=tk.NE, fill=COLORS["fg_dim"],
                                font=("Consolas", 9))

    # -----------------------------------------------------------------------
    #  Event Log
    # -----------------------------------------------------------------------

    def _log_event(self, severity: str, category: str, message: str) -> None:
        """
        Append a timestamped event to the GUI event log.
        Deduplicates events that repeat within 2 seconds.
        """
        now = datetime.now().strftime("%H:%M:%S")
        line = f"[{now}] {severity} [{category}] {message}\n"

        # Simple dedup: check if the last line is identical (minus timestamp)
        self.event_log.configure(state=tk.NORMAL)
        existing = self.event_log.get("end-2l", "end-1l").strip()
        # Compare the content after the timestamp
        if existing and len(existing) > 11:
            existing_content = existing[11:]  # Skip "[HH:MM:SS] "
            new_content = f"{severity} [{category}] {message}"
            if existing_content == new_content:
                self.event_log.configure(state=tk.DISABLED)
                return

        # Choose color tag based on severity
        tag = "info"
        if severity in ("SPIKE", "WARNING"):
            tag = "spike"
        elif severity == "CRITICAL":
            tag = "critical"

        self.event_log.insert(tk.END, line, tag)
        self.event_log.see(tk.END)
        self.event_log.configure(state=tk.DISABLED)

    def _clear_log(self) -> None:
        """Clear the event log text widget."""
        self.event_log.configure(state=tk.NORMAL)
        self.event_log.delete("1.0", tk.END)
        self.event_log.configure(state=tk.DISABLED)
        self._event_count_var.set("0 events")

    # -----------------------------------------------------------------------
    #  Utility
    # -----------------------------------------------------------------------

    def _reset_traceroute(self) -> None:
        """Clear traceroute hop counters and tree display."""
        if self.traceroute_monitor:
            with self.traceroute_monitor._lock:
                self.traceroute_monitor._hops.clear()
        self._trace_tree.delete(*self._trace_tree.get_children())
        self._log_event("INFO", "TRACE", "Traceroute counters reset")

    def _clear_nic_counters(self) -> None:
        """Snapshot current NIC error counters as baseline so display shows delta."""
        if not self.nic_monitor:
            return
        snap = self.nic_monitor.get_latest()
        if not snap:
            return
        for nic in snap.adapters:
            self._nic_baseline[nic.name] = {
                "rx_err": nic.recv_errors,
                "tx_err": nic.send_errors,
                "crc": nic.recv_crc_errors,
                "rx_disc": nic.recv_discards,
                "tx_disc": nic.send_discards,
            }
        now = datetime.now().strftime("%H:%M:%S")
        self._nic_baseline_note.set(f"Counters zeroed at {now}")
        self._log_event("INFO", "NIC", "Error counters reset (baseline captured)")

    def _sort_proc_tree(self, col: str) -> None:
        """Sort the process treeview by the given column."""
        if col == self._proc_sort_col:
            self._proc_sort_asc = not self._proc_sort_asc
        else:
            self._proc_sort_col = col
            self._proc_sort_asc = True if col in ("pid", "name") else False

        items = []
        for item in self._proc_tree.get_children():
            values = self._proc_tree.item(item, "values")
            items.append(values)

        def sort_key(vals):
            idx = {"pid": 0, "name": 1, "send_rate": 2, "recv_rate": 3, "total_rate": 4, "conns": 5}[col]
            v = vals[idx]
            if col == "name":
                return str(v).lower()
            if col in ("send_rate", "recv_rate", "total_rate"):
                # Parse rate strings like "1.2 MB/s" → float bytes
                return self._parse_rate_for_sort(str(v))
            try:
                return float(v)
            except (ValueError, TypeError):
                return 0

        items.sort(key=sort_key, reverse=not self._proc_sort_asc)

        self._proc_tree.delete(*self._proc_tree.get_children())
        for vals in items:
            self._proc_tree.insert("", tk.END, values=vals)

        # Update heading to show sort indicator
        proc_headings = {
            "pid": "PID", "name": "Process",
            "send_rate": "↑ Send/s", "recv_rate": "↓ Recv/s",
            "total_rate": "⇅ Total/s",
            "conns": "Connections",
        }
        for c, text in proc_headings.items():
            if c == col:
                arrow = " ▲" if self._proc_sort_asc else " ▼"
                self._proc_tree.heading(c, text=text + arrow)
            else:
                self._proc_tree.heading(c, text=text)

    @staticmethod
    def _parse_rate_for_sort(rate_str: str) -> float:
        """Parse a formatted rate string like '1.2 MB/s' to bytes for sorting."""
        rate_str = rate_str.strip()
        if not rate_str or rate_str == "—":
            return 0.0
        multipliers = {"B/s": 1, "KB/s": 1024, "MB/s": 1024**2, "GB/s": 1024**3}
        for suffix, mult in multipliers.items():
            if rate_str.endswith(suffix):
                try:
                    return float(rate_str[:-len(suffix)].strip()) * mult
                except ValueError:
                    return 0.0
        try:
            return float(rate_str)
        except ValueError:
            return 0.0

    @staticmethod
    def _format_bitrate(bytes_per_sec: float) -> str:
        """Format bytes/sec as autoscaling bits/sec (Kbps, Mbps, Gbps)."""
        bits = bytes_per_sec * 8
        if bits < 1000:
            return f"{bits:.0f} bps"
        elif bits < 1_000_000:
            return f"{bits / 1000:.1f} Kbps"
        elif bits < 1_000_000_000:
            return f"{bits / 1_000_000:.2f} Mbps"
        else:
            return f"{bits / 1_000_000_000:.2f} Gbps"

    def _bind_treeview_copy(self, tree: ttk.Treeview) -> None:
        """Bind right-click context menu and Ctrl+C to copy cell/row values."""
        menu = tk.Menu(tree, tearoff=0,
                       bg=COLORS["bg_card"], fg=COLORS["fg"],
                       activebackground=COLORS["bg_input"],
                       activeforeground=COLORS["accent"])

        def _get_cell_value(event):
            """Return (row_values_tuple, column_index) at click position."""
            row_id = tree.identify_row(event.y)
            col_id = tree.identify_column(event.x)
            if not row_id:
                return None, None, None
            values = tree.item(row_id, "values")
            col_idx = int(col_id.replace("#", "")) - 1 if col_id else -1
            return values, col_idx, row_id

        def _copy_cell(event=None):
            sel = tree.selection()
            if not sel:
                return
            values = tree.item(sel[0], "values")
            if values and hasattr(tree, "_last_col_idx") and 0 <= tree._last_col_idx < len(values):
                self.root.clipboard_clear()
                self.root.clipboard_append(str(values[tree._last_col_idx]))

        def _copy_row(event=None):
            sel = tree.selection()
            if not sel:
                return
            values = tree.item(sel[0], "values")
            if values:
                self.root.clipboard_clear()
                self.root.clipboard_append("\t".join(str(v) for v in values))

        def _copy_all_rows():
            lines = []
            for item in tree.get_children():
                values = tree.item(item, "values")
                if values:
                    lines.append("\t".join(str(v) for v in values))
                for child in tree.get_children(item):
                    cv = tree.item(child, "values")
                    if cv:
                        lines.append("  \t".join(str(v) for v in cv))
            if lines:
                self.root.clipboard_clear()
                self.root.clipboard_append("\n".join(lines))

        def _on_right_click(event):
            values, col_idx, row_id = _get_cell_value(event)
            if not values:
                return
            tree._last_col_idx = col_idx
            if row_id:
                tree.selection_set(row_id)
            menu.delete(0, tk.END)
            if 0 <= col_idx < len(values):
                cell_val = str(values[col_idx])
                display = cell_val[:40] + "..." if len(cell_val) > 40 else cell_val
                menu.add_command(label=f'Copy "{display}"', command=_copy_cell)
            menu.add_command(label="Copy Row", command=_copy_row)
            menu.add_separator()
            menu.add_command(label="Copy All Rows", command=_copy_all_rows)
            menu.tk_popup(event.x_root, event.y_root)

        tree.bind("<Button-3>", _on_right_click)
        tree.bind("<Control-c>", _copy_row)

    def _resolve_pid_name(self, pid: int) -> str:
        """Resolve a PID to its process name, with caching."""
        pid = int(pid)  # ensure int
        if pid <= 0:
            return ""
        if pid in self._pid_name_cache:
            return self._pid_name_cache[pid]
        try:
            if PSUTIL_AVAILABLE:
                import psutil
                proc = psutil.Process(pid)
                name = proc.name()
            else:
                name = str(pid)
        except Exception:
            name = "(exited)"
        self._pid_name_cache[pid] = name
        return name

    def _start_dns_lookup(self, ip: str) -> None:
        """Start a background reverse DNS lookup for an IP address."""
        if ip in self._dns_cache or ip in self._dns_pending:
            return
        # Skip local/private addresses and wildcards
        if ip in ("0.0.0.0", "*", "[::]", "[::1]", "127.0.0.1", ""):
            self._dns_cache[ip] = ip
            return
        self._dns_pending.add(ip)
        threading.Thread(
            target=self._do_dns_lookup, args=(ip,),
            daemon=True, name=f"DNS-{ip}",
        ).start()

    def _do_dns_lookup(self, ip: str) -> None:
        """Background thread: resolve IP to hostname."""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            self._dns_cache[ip] = hostname
        except (socket.herror, socket.gaierror, OSError):
            self._dns_cache[ip] = ip  # Cache the failure so we don't retry
        finally:
            self._dns_pending.discard(ip)

    @staticmethod
    def _fmt_duration(seconds: float) -> str:
        """Format seconds into HH:MM:SS."""
        h = int(seconds // 3600)
        m = int((seconds % 3600) // 60)
        s = int(seconds % 60)
        if h > 0:
            return f"{h}h {m:02d}m {s:02d}s"
        elif m > 0:
            return f"{m}m {s:02d}s"
        else:
            return f"{s}s"

    # -----------------------------------------------------------------------
    #  Main Loop
    # -----------------------------------------------------------------------

    def run(self) -> None:
        """Start the tkinter main loop (blocking)."""
        logger.info("Entering GUI main loop")
        self.root.mainloop()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _format_rate(bps: float) -> str:
    """Convert bytes/sec to human-readable string."""
    if bps >= 1_073_741_824:
        return f"{bps / 1_073_741_824:.1f} GB/s"
    elif bps >= 1_048_576:
        return f"{bps / 1_048_576:.1f} MB/s"
    elif bps >= 1024:
        return f"{bps / 1024:.1f} KB/s"
    else:
        return f"{bps:.0f} B/s"


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

def run_gui() -> None:
    """Launch the NetProbe GUI application."""
    # Initialize basic logging before the GUI creates its own logger
    setup_logger(name="netprobe", log_dir="output/logs")
    app = NetProbeGUI()
    app.run()


if __name__ == "__main__":
    run_gui()
