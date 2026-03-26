"""
netprobe/logger.py - Centralized Logging Module
=================================================
Provides a dual-output logging system that writes verbose diagnostic
information to both a rotating log file and the console. The console
output uses color coding for severity levels on Windows terminals.

Version: 1.0.0
"""

import logging
import os
import sys
from datetime import datetime
from logging.handlers import RotatingFileHandler


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Maximum log file size before rotation (5 MB)
MAX_LOG_FILE_BYTES = 5 * 1024 * 1024

# Number of backup log files to keep
BACKUP_COUNT = 3

# Default log directory relative to the script
DEFAULT_LOG_DIR = "logs"

# Console color codes for Windows terminal (ANSI escape sequences)
COLORS = {
    "DEBUG": "\033[36m",     # Cyan
    "INFO": "\033[32m",      # Green
    "WARNING": "\033[33m",   # Yellow
    "ERROR": "\033[31m",     # Red
    "CRITICAL": "\033[41m",  # Red background
    "RESET": "\033[0m",      # Reset
}


class ColoredConsoleHandler(logging.StreamHandler):
    """
    A custom StreamHandler that applies ANSI color codes to log messages
    based on their severity level. This makes it easy to visually distinguish
    warnings and errors from informational messages in the console output.
    """

    def emit(self, record: logging.LogRecord) -> None:
        """Override emit to inject ANSI color codes around the log level name."""
        color = COLORS.get(record.levelname, COLORS["RESET"])
        reset = COLORS["RESET"]
        # Temporarily modify the levelname for colored output
        original_levelname = record.levelname
        record.levelname = f"{color}{record.levelname}{reset}"
        super().emit(record)
        # Restore the original levelname so file handlers aren't affected
        record.levelname = original_levelname


def setup_logger(
    name: str = "netprobe",
    log_dir: str = DEFAULT_LOG_DIR,
    console_level: int = logging.INFO,
    file_level: int = logging.DEBUG,
) -> logging.Logger:
    """
    Configure and return a logger with both file and console handlers.

    The file handler captures ALL messages (DEBUG and above) with full
    timestamps and module info for post-mortem analysis. The console
    handler shows INFO and above with colored output for real-time monitoring.

    Args:
        name:          Logger name (used as the logger namespace).
        log_dir:       Directory where log files are stored.
        console_level: Minimum severity for console output.
        file_level:    Minimum severity for file output.

    Returns:
        A configured logging.Logger instance.
    """
    # Enable ANSI escape codes on Windows 10+ terminals
    if sys.platform == "win32":
        os.system("")  # Triggers VT100 mode in Windows console

    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)  # Capture everything; handlers filter

    # Avoid adding duplicate handlers if called multiple times
    if logger.handlers:
        return logger

    # Ensure the log directory exists
    os.makedirs(log_dir, exist_ok=True)

    # Generate a timestamped log filename for this session
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(log_dir, f"netprobe_{timestamp}.log")

    # ----- File Handler (verbose, rotating) -----
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=MAX_LOG_FILE_BYTES,
        backupCount=BACKUP_COUNT,
        encoding="utf-8",
    )
    file_handler.setLevel(file_level)
    file_formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)-20s | %(funcName)-25s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    file_handler.setFormatter(file_formatter)

    # ----- Console Handler (colored, concise) -----
    console_handler = ColoredConsoleHandler(sys.stdout)
    console_handler.setLevel(console_level)
    console_formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%H:%M:%S",
    )
    console_handler.setFormatter(console_formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    logger.info("Logger initialized — log file: %s", log_file)
    return logger
