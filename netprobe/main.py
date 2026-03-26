"""
netprobe/main.py - Main Entry Point & CLI Interface
=====================================================
Orchestrates all monitoring subsystems, handles CLI argument parsing,
and manages the main display loop. This is the file you run to start
the tool.

Usage:
    python -m netprobe                              # Monitor defaults (8.8.8.8, 1.1.1.1)
    python -m netprobe 8.8.8.8 google.com           # Custom targets
    python -m netprobe --interval 2 --verbose       # 2s interval, debug output
    python -m netprobe --no-traceroute --no-process  # Disable subsystems
    python -m netprobe --config myconfig.json        # Load from config file
    python -m netprobe --save-config defaults.json   # Save current config

Version: 1.0.0
"""

import argparse
import os
import signal
import sys
import time
from datetime import datetime

from netprobe import __version__, __app_name__
from netprobe.config import ProbeConfig
from netprobe.logger import setup_logger
from netprobe.ping_monitor import PingMonitor, TracerouteMonitor
from netprobe.netstat_monitor import NetstatMonitor
from netprobe.process_monitor import ProcessMonitor, PSUTIL_AVAILABLE
from netprobe.reporter import Reporter


def build_arg_parser() -> argparse.ArgumentParser:
    """
    Construct the CLI argument parser with all user-facing options.
    Arguments mirror the ProbeConfig fields for easy mapping.
    """
    parser = argparse.ArgumentParser(
        prog="netprobe",
        description=(
            f"{__app_name__} v{__version__} — Windows Network Latency Monitor\n"
            "Continuously monitors network latency, hop-by-hop paths, connection\n"
            "states, and per-process network I/O to help troubleshoot intermittent\n"
            "network issues and latency spikes."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python -m netprobe 8.8.8.8 1.1.1.1\n"
            "  python -m netprobe google.com --interval 0.5 --verbose\n"
            "  python -m netprobe --spike-threshold 50 --duration 3600\n"
            "  python -m netprobe --no-traceroute --no-process\n"
        ),
    )

    # Positional: targets
    parser.add_argument(
        "targets",
        nargs="*",
        default=None,
        help="Hostnames or IP addresses to monitor (default: 8.8.8.8, 1.1.1.1)",
    )

    # Ping settings
    ping_group = parser.add_argument_group("Ping Settings")
    ping_group.add_argument(
        "-i", "--interval",
        type=float, default=None,
        help="Seconds between ping cycles (default: 1.0)",
    )
    ping_group.add_argument(
        "-t", "--timeout",
        type=float, default=None,
        help="Ping timeout in seconds (default: 2.0)",
    )
    ping_group.add_argument(
        "-c", "--count",
        type=int, default=None,
        help="Pings per cycle (default: 1)",
    )

    # Traceroute settings
    trace_group = parser.add_argument_group("Traceroute Settings")
    trace_group.add_argument(
        "--trace-interval",
        type=float, default=None,
        help="Seconds between traceroute sweeps (default: 30)",
    )
    trace_group.add_argument(
        "--max-hops",
        type=int, default=None,
        help="Maximum hops for traceroute (default: 30)",
    )
    trace_group.add_argument(
        "--no-traceroute",
        action="store_true",
        help="Disable traceroute monitoring",
    )

    # Netstat settings
    net_group = parser.add_argument_group("Netstat Settings")
    net_group.add_argument(
        "--netstat-interval",
        type=float, default=None,
        help="Seconds between netstat snapshots (default: 10)",
    )
    net_group.add_argument(
        "--no-netstat",
        action="store_true",
        help="Disable netstat connection monitoring",
    )

    # Process settings
    proc_group = parser.add_argument_group("Process Monitor Settings")
    proc_group.add_argument(
        "--process-interval",
        type=float, default=None,
        help="Seconds between process I/O snapshots (default: 5)",
    )
    proc_group.add_argument(
        "--no-process",
        action="store_true",
        help="Disable per-process network monitoring",
    )

    # Spike detection
    spike_group = parser.add_argument_group("Spike Detection")
    spike_group.add_argument(
        "-s", "--spike-threshold",
        type=float, default=None,
        help="Latency threshold in ms to flag as spike (default: 100)",
    )
    spike_group.add_argument(
        "--spike-loss",
        type=float, default=None,
        help="Packet loss %% threshold for traceroute hops (default: 5)",
    )

    # Reporting
    report_group = parser.add_argument_group("Reporting")
    report_group.add_argument(
        "--report-interval",
        type=float, default=None,
        help="Seconds between report updates (default: 60)",
    )
    report_group.add_argument(
        "--report-format",
        choices=["csv", "html", "both"],
        default=None,
        help="Report output format (default: both)",
    )
    report_group.add_argument(
        "-o", "--output-dir",
        type=str, default=None,
        help="Directory for reports and logs (default: output/)",
    )

    # Session
    session_group = parser.add_argument_group("Session")
    session_group.add_argument(
        "-d", "--duration",
        type=float, default=None,
        help="Total monitoring duration in seconds (default: 0 = forever)",
    )
    session_group.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose (DEBUG-level) console output",
    )

    # Config file
    config_group = parser.add_argument_group("Configuration")
    config_group.add_argument(
        "--config",
        type=str, default=None,
        help="Load settings from a JSON config file",
    )
    config_group.add_argument(
        "--save-config",
        type=str, default=None,
        help="Save current settings to a JSON config file and exit",
    )

    return parser


def apply_cli_overrides(config: ProbeConfig, args: argparse.Namespace) -> ProbeConfig:
    """
    Apply CLI argument overrides on top of a base config (from file or defaults).
    Only overrides values that were explicitly provided on the command line.
    """
    if args.targets:
        config.targets = args.targets
    if args.interval is not None:
        config.ping_interval = args.interval
    if args.timeout is not None:
        config.ping_timeout = args.timeout
    if args.count is not None:
        config.ping_count = args.count
    if args.trace_interval is not None:
        config.traceroute_interval = args.trace_interval
    if args.max_hops is not None:
        config.traceroute_max_hops = args.max_hops
    if args.no_traceroute:
        config.monitor_traceroute = False
    if args.netstat_interval is not None:
        config.netstat_interval = args.netstat_interval
    if args.no_netstat:
        config.monitor_netstat = False
    if args.process_interval is not None:
        config.process_interval = args.process_interval
    if args.no_process:
        config.monitor_processes = False
    if args.spike_threshold is not None:
        config.spike_threshold_ms = args.spike_threshold
    if args.spike_loss is not None:
        config.spike_loss_pct = args.spike_loss
    if args.report_interval is not None:
        config.report_interval = args.report_interval
    if args.report_format is not None:
        config.report_format = args.report_format
    if args.output_dir is not None:
        config.output_dir = args.output_dir
    if args.duration is not None:
        config.duration = args.duration
    if args.verbose:
        config.verbose = True

    return config


def print_banner(config: ProbeConfig) -> None:
    """Print the startup banner with active configuration summary."""
    banner = f"""
╔══════════════════════════════════════════════════════════════════╗
║  {__app_name__} v{__version__} — Windows Network Latency Monitor            ║
╠══════════════════════════════════════════════════════════════════╣
║  Targets:    {', '.join(config.targets):<50}║
║  Ping:       every {config.ping_interval:.1f}s, timeout {config.ping_timeout:.1f}s{' ' * 33}║
║  Traceroute: {'enabled, every ' + str(int(config.traceroute_interval)) + 's' if config.monitor_traceroute else 'disabled':<50}║
║  Netstat:    {'enabled, every ' + str(int(config.netstat_interval)) + 's' if config.monitor_netstat else 'disabled':<50}║
║  Processes:  {'enabled, every ' + str(int(config.process_interval)) + 's' if config.monitor_processes and PSUTIL_AVAILABLE else 'disabled':<50}║
║  Spike at:   >{config.spike_threshold_ms:.0f}ms latency, >{config.spike_loss_pct:.0f}% loss{' ' * 28}║
║  Output:     {config.output_dir + '/':<50}║
║  Duration:   {'unlimited (Ctrl+C to stop)' if config.duration == 0 else str(int(config.duration)) + ' seconds':<50}║
╚══════════════════════════════════════════════════════════════════╝
"""
    print(banner)


def main() -> None:
    """
    Main entry point. Parses CLI args, initializes all monitoring subsystems,
    runs the display loop, and generates final reports on exit.
    """
    import logging as _logging

    # ----- Parse CLI arguments -----
    parser = build_arg_parser()
    args = parser.parse_args()

    # ----- Load or create configuration -----
    if args.config and os.path.isfile(args.config):
        config = ProbeConfig.load(args.config)
    else:
        config = ProbeConfig()

    # Apply any CLI overrides on top of the loaded/default config
    config = apply_cli_overrides(config, args)

    # ----- Handle --save-config -----
    if args.save_config:
        config.save(args.save_config)
        print(f"Configuration saved to {args.save_config}")
        sys.exit(0)

    # ----- Initialize logging -----
    console_level = _logging.DEBUG if config.verbose else _logging.INFO
    log = setup_logger(
        name="netprobe",
        log_dir=os.path.join(config.output_dir, "logs"),
        console_level=console_level,
    )

    log.info("=" * 60)
    log.info("%s v%s starting", __app_name__, __version__)
    log.info("=" * 60)

    # Print the startup banner
    print_banner(config)

    # ----- Initialize monitoring subsystems -----

    # 1) Ping Monitor (always active — core feature)
    ping_monitor = PingMonitor(
        targets=config.targets,
        interval=config.ping_interval,
        timeout=config.ping_timeout,
        count=config.ping_count,
        spike_threshold_ms=config.spike_threshold_ms,
    )

    # 2) Traceroute Monitor (optional)
    traceroute_monitor = None
    if config.monitor_traceroute:
        traceroute_monitor = TracerouteMonitor(
            targets=config.targets,
            interval=config.traceroute_interval,
            max_hops=config.traceroute_max_hops,
            timeout=config.ping_timeout,
        )

    # 3) Netstat Monitor (optional)
    netstat_monitor = None
    if config.monitor_netstat:
        netstat_monitor = NetstatMonitor(interval=config.netstat_interval)

    # 4) Process Monitor (optional, requires psutil)
    process_monitor = None
    if config.monitor_processes and PSUTIL_AVAILABLE:
        process_monitor = ProcessMonitor(interval=config.process_interval)
    elif config.monitor_processes and not PSUTIL_AVAILABLE:
        log.warning(
            "Process monitoring requested but psutil is not installed. "
            "Install with: pip install psutil"
        )

    # 5) Reporter (aggregates all subsystem data)
    reporter = Reporter(
        config=config,
        ping_monitor=ping_monitor,
        traceroute_monitor=traceroute_monitor,
        netstat_monitor=netstat_monitor,
        process_monitor=process_monitor,
    )

    # ----- Register signal handlers for graceful shutdown -----
    shutdown_requested = False

    def signal_handler(signum, frame):
        nonlocal shutdown_requested
        if shutdown_requested:
            # Second Ctrl+C — force exit
            log.warning("Force exit requested")
            sys.exit(1)
        shutdown_requested = True
        log.info("Shutdown signal received — stopping monitors...")
        print("\n\n  Shutting down... generating final report...\n")

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # ----- Start all subsystems -----
    log.info("Starting monitoring subsystems...")
    ping_monitor.start()
    if traceroute_monitor:
        traceroute_monitor.start()
    if netstat_monitor:
        netstat_monitor.start()
    if process_monitor:
        process_monitor.start()
    reporter.start()

    log.info("All subsystems running — entering main display loop")
    print("  Monitoring started. Collecting data...\n")

    # ----- Main display loop -----
    start_time = time.monotonic()
    display_interval = 5.0  # Refresh console summary every 5 seconds

    try:
        # Wait a few seconds for initial data collection before first display
        time.sleep(min(3.0, config.ping_interval * 3))

        while not shutdown_requested:
            # Check duration limit
            if config.duration > 0:
                elapsed = time.monotonic() - start_time
                if elapsed >= config.duration:
                    log.info("Duration limit reached (%.0fs) — shutting down", config.duration)
                    break

            # Print the consolidated console summary
            try:
                summary = reporter.get_console_summary()
                # Clear screen on Windows for clean re-render
                os.system("cls")
                print(summary)
            except Exception as exc:
                log.error("Display error: %s", exc)

            # Sleep until next display refresh (interruptible)
            sleep_end = time.monotonic() + display_interval
            while time.monotonic() < sleep_end and not shutdown_requested:
                time.sleep(0.25)

    except KeyboardInterrupt:
        log.info("KeyboardInterrupt caught in main loop")

    # ----- Shutdown sequence -----
    log.info("Stopping all subsystems...")
    ping_monitor.stop()
    if traceroute_monitor:
        traceroute_monitor.stop()
    if netstat_monitor:
        netstat_monitor.stop()
    if process_monitor:
        process_monitor.stop()
    reporter.stop()

    # Generate final reports
    reporter.write_final_report()

    # Print final summary to console
    print("\n")
    print("=" * 60)
    print(f"  {__app_name__} session complete")
    print(f"  Duration: {time.monotonic() - start_time:.0f} seconds")
    print(f"  Reports saved to: {os.path.abspath(config.output_dir)}/")
    print("=" * 60)

    # Print per-target final stats
    for target in config.targets:
        stats = ping_monitor.get_stats(target)
        print(f"\n  {target}:")
        print(f"    Sent: {stats['sent']}  |  Received: {stats['received']}  |  "
              f"Loss: {stats['loss_pct']:.1f}%")
        print(f"    Min: {stats['min']:.1f}ms  |  Avg: {stats['avg']:.1f}ms  |  "
              f"Max: {stats['max']:.1f}ms  |  Jitter: {stats['jitter']:.1f}ms")

    print()
    log.info("Session ended successfully")


if __name__ == "__main__":
    main()
