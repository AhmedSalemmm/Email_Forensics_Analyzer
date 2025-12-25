#!/usr/bin/env bash
set -euo pipefail
# Convenience wrapper without installing the package:
# Usage: ./run_gui.sh
PYTHONPATH="$(pwd)/src" python3 -m email_forensics_analyzer.gui
