#!/usr/bin/env bash
# Portable entrypoint; real command execution and failure checks live in demo.py.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec "${PYTHON:-python3}" "$SCRIPT_DIR/demo.py" "$@"