"""
NetProbe - Package runner
==========================
Allows the package to be run with:
    python -m netprobe           # CLI mode
    python -m netprobe --gui     # GUI mode

Version: 1.1.0
"""

import sys


def entry() -> None:
    """Route to GUI or CLI mode based on the --gui flag."""
    if "--gui" in sys.argv:
        # Remove the --gui flag so it doesn't confuse argparse
        sys.argv.remove("--gui")
        from netprobe.gui import run_gui
        run_gui()
    else:
        from netprobe.main import main
        main()


if __name__ == "__main__":
    entry()
