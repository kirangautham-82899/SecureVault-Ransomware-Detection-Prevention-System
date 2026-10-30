# packaging/launcher.py
"""Entry point of the packaged Windows app: opens the SecureVault dashboard."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gui.main_gui import run_gui  # noqa: E402

if __name__ == "__main__":
    run_gui()
