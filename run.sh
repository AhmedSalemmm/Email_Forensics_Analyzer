#!/usr/bin/env bash
set -euo pipefail
# Convenience wrapper without installing the package:
# Usage: ./run.sh analyze --input sample.mbox --out out_dir
PYTHONPATH="$(pwd)/src" python3 -m email_forensics_analyzer "$@"
