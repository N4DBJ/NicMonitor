"""
run_gui.py - Convenience Launcher for NetProbe GUI
====================================================
Double-click this file or run `python run_gui.py` to launch
the NetProbe graphical dashboard.

Version: 1.1.0
"""

import sys
import os

# Ensure the package directory is on the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from netprobe.gui import run_gui

if __name__ == "__main__":
    run_gui()
