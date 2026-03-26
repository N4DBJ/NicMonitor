# NetProbe v1.4.0

**Windows Network Latency Monitor** — A comprehensive diagnostic tool with a full GUI dashboard that measures network latency over time, similar to WinMTR, to help troubleshoot random network errors and latency spikes.

## Features

### GUI Dashboard
- **Dark-themed graphical interface** — Professional dark UI built with tkinter (no extra dependencies)
- **Live scrolling latency chart** — Canvas-based time-series graph with spike markers, threshold line, and timeout indicators
- **8 tabbed panels** — Latency, Traceroute, Connections, Processes, NIC Health, Wireshark, Event Log, and Settings
- **Real-time stat cards** — Per-target latency stats updated live
- **Point-and-click configuration** — All settings adjustable in the Settings tab, with save/load config

### NIC & Cable Health Monitoring (v1.2.0)
- **Physical adapter statistics** — Queries Windows `Get-NetAdapterStatistics` for hardware-level error counters
- **CRC error detection** — Identifies damaged packets from bad cables, connectors, or EMI interference
- **Link speed monitoring** — Detects speed degradation that indicates cable issues
- **Duplex mismatch detection** — Flags half-duplex mode on wired connections
- **Disconnect alerts** — Immediate notification when adapters lose link
- **Error rate tracking** — Shows errors/sec trends to identify developing problems

### Wireshark Integration (v1.2.0)
- **Live packet capture** — Start/stop captures from the GUI using tshark/dumpcap
- **Automated analysis** — Scans captures for TCP retransmissions, duplicate ACKs, RST floods, zero-window events, out-of-order packets, DNS failures, and ICMP errors
- **Problem severity assessment** — Categorizes findings as OK/Info/Warning/Critical
- **Open pcap files** — Analyse existing .pcap/.pcapng captures without Wireshark GUI
- **Interface selector** — Pick capture interface from auto-detected list
- **Auto-detection** — Finds Wireshark/tshark in standard install locations or PATH

### Report Charts & Event Log Correlation (v1.4.0)
- **SVG latency charts in reports** — Inline SVG graphs embedded directly in the HTML report, mirroring the live GUI chart with spike markers, threshold line, and average overlay
- **Windows Event Log cross-referencing** — Queries System and Application event logs for errors and warnings during the monitoring session
- **Spike-to-event correlation** — Automatically matches latency spikes with Windows events within a ±30 second window to identify system-level causes
- **Correlated events table** — Highlights which system errors coincide with network anomalies
- **Full session event listing** — Complete log of all errors/warnings from Windows Event Logs

### Copyable Fields & Stability (v1.3.0)
- **Right-click context menu** — Copy Cell, Copy Row, or Copy All on any table
- **Keyboard copy** — Ctrl+C copies the selected row
- **Sortable process columns** — Click column headers with ▲/▼ indicators
- **NIC throughput rates** — Rx/Tx/Total rates with autoscaling bps/Kbps/Mbps/Gbps
- **NIC clear counters** — Reset baseline without adapter restart
- **Traceroute reset** — Clear accumulated hop statistics on demand
- **Process total column** — Combined send+recv rate with default descending sort

### Monitoring Engine
- **Continuous ICMP Ping Monitoring** — Tracks latency, TTL, and packet loss to multiple targets simultaneously with configurable intervals
- **Hop-by-Hop Traceroute (WinMTR-style)** — Periodically traces the network path and accumulates per-hop statistics including loss%, avg/min/max latency, and jitter
- **Netstat Connection Monitoring** — Snapshots TCP/UDP connection states, detects anomalies like TIME_WAIT floods, CLOSE_WAIT leaks, and SYN_SENT buildup
- **Per-Process Network I/O Tracking** — Identifies top bandwidth-consuming processes and detects abnormal network activity (via psutil)
- **Spike Detection** — Configurable thresholds for latency spikes and packet loss, with a timeline of all detected anomalies
- **Reports** — Generates CSV and HTML reports with styled tables, color-coded severity, SVG latency charts, Windows Event Log correlation, and latency time-series data
- **Verbose Logging** — Dual-output logging (rotating files + colored console) with full timestamps and module tracing

## Requirements

- **Python 3.8+** (tested on 3.10, 3.11, 3.12)
- **Windows 10/11** (uses `ping.exe`, `tracert.exe`, `netstat.exe`)
- **psutil** (optional, for per-process monitoring): `pip install psutil`
- **Wireshark** (optional, for packet capture): Install from [wireshark.org](https://www.wireshark.org/) to enable the Wireshark tab

## Installation

```bash
cd TFE_Creator
pip install -r requirements.txt
```

## Usage

### GUI Mode (recommended)
```bash
python -m netprobe --gui
# or
python run_gui.py
```

### CLI Mode — Basic (monitor Google DNS and Cloudflare DNS)
```bash
python -m netprobe
```

### Custom targets
```bash
python -m netprobe 8.8.8.8 google.com 192.168.1.1
```

### Full options
```bash
python -m netprobe 8.8.8.8 \
    --interval 0.5 \
    --spike-threshold 50 \
    --verbose \
    --duration 3600 \
    --output-dir results/
```

### Disable optional subsystems
```bash
python -m netprobe --no-traceroute --no-process --no-netstat
```

### Save/load configuration
```bash
python -m netprobe --save-config myconfig.json
python -m netprobe --config myconfig.json
```

## CLI Options

| Option | Default | Description |
|---|---|---|
| `targets` (positional) | `8.8.8.8 1.1.1.1` | Hosts to monitor |
| `-i, --interval` | `1.0` | Seconds between pings |
| `-t, --timeout` | `2.0` | Ping timeout (seconds) |
| `-c, --count` | `1` | Pings per cycle |
| `-s, --spike-threshold` | `100` | Latency spike threshold (ms) |
| `--trace-interval` | `30` | Seconds between traceroutes |
| `--max-hops` | `30` | Max traceroute hops |
| `--netstat-interval` | `10` | Seconds between netstat snapshots |
| `--process-interval` | `5` | Seconds between process I/O snapshots |
| `--report-interval` | `60` | Seconds between report updates |
| `--report-format` | `both` | `csv`, `html`, or `both` |
| `-o, --output-dir` | `output/` | Report output directory |
| `-d, --duration` | `0` | Run duration (0 = forever) |
| `-v, --verbose` | off | Enable DEBUG console output |
| `--no-traceroute` | | Disable traceroute |
| `--no-netstat` | | Disable netstat monitoring |
| `--no-process` | | Disable process monitoring |

## Output

Reports are written to the `output/` directory (configurable):

```
output/
├── logs/
│   └── netprobe_20260324_143022.log     # Verbose rotating log file
├── latency_20260324_143022.csv          # Running latency time-series
├── summary_20260324_143022.csv          # Session summary statistics
└── report_20260324_143022.html          # Styled HTML report
```

## Architecture

```
netprobe/
├── __init__.py          # Version info & changelog
├── __main__.py          # Package runner (--gui / CLI routing)
├── main.py              # CLI interface & orchestration
├── gui.py               # Tkinter dark-themed GUI dashboard
├── config.py            # Configuration management
├── logger.py            # Dual-output colored logging
├── ping_monitor.py      # ICMP ping & WinMTR-style traceroute
├── netstat_monitor.py   # Connection state tracking
├── process_monitor.py   # Per-process network I/O (psutil)
├── nic_monitor.py       # Physical NIC/cable health (PowerShell)
├── capture_monitor.py   # Wireshark packet capture & analysis
└── reporter.py          # Spike detection, CSV/HTML reports
run_gui.py               # Convenience GUI launcher (double-click)
```

## What It Detects

| Category | Anomaly | How |
|---|---|---|
| Latency | Spikes above threshold | Ping monitor continuous comparison |
| Latency | Packet loss | Ping timeout tracking |
| Routing | Per-hop packet loss | Traceroute with cumulative stats |
| Routing | Jitter at specific hops | Traceroute min/max delta |
| Connections | TIME_WAIT flood | Netstat state counting |
| Connections | CLOSE_WAIT leak | Netstat state counting |
| Connections | SYN_SENT buildup | Netstat state counting |
| Connections | Sudden connection spike | Netstat delta comparison |
| Processes | Bandwidth-hungry process | psutil per-process I/O rates |
| System | NIC errors/drops | psutil system net_io_counters |
| NIC/Cable | CRC errors | Get-NetAdapterStatistics via PowerShell |
| NIC/Cable | Link speed degradation | Get-NetAdapter link speed monitoring |
| NIC/Cable | Duplex mismatch | Get-NetAdapter full-duplex check |
| NIC/Cable | Cable disconnect | Adapter status change detection |
| System | Event log errors near spikes | PowerShell Get-WinEvent correlation |
| Packets | TCP retransmissions | tshark pcap analysis |
| Packets | Duplicate ACKs | tshark display filter counting |
| Packets | TCP RST floods | tshark RST flag counting |
| Packets | Zero-window (slow app) | tshark TCP analysis |
| Packets | DNS failures | tshark DNS rcode analysis |
| Packets | ICMP unreachable | tshark ICMP type filtering |

## License

MIT
