#!/bin/bash
# SentryLog Quick Scan
# Activates venv, copies auth.log, ingests, scans, and generates a PDF report.
#
# Usage:
#   ./scripts/sentrylog-scan.sh          # normal run
#   ./scripts/sentrylog-scan.sh -v       # verbose
#   ./scripts/sentrylog-scan.sh -vv      # debug

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="/tmp/sentrylog-venv"
VERBOSE="${1:-}"

# --- Create venv if missing ---
if [ ! -f "$VENV_DIR/bin/activate" ]; then
    echo "[*] Creating virtual environment in $VENV_DIR ..."
    python3 -m venv "$VENV_DIR"
    source "$VENV_DIR/bin/activate"
    echo "[*] Installing SentryLog ..."
    pip install -e "$PROJECT_DIR" --quiet
else
    source "$VENV_DIR/bin/activate"
fi

# --- Ensure sentrylog is installed ---
if ! command -v sentrylog &>/dev/null; then
    echo "[*] Installing SentryLog ..."
    pip install -e "$PROJECT_DIR" --quiet
fi

cd "$PROJECT_DIR"

# --- Copy auth.log ---
echo "[*] Copying /var/log/auth.log (requires sudo) ..."
sudo cp /var/log/auth.log /tmp/auth.log
sudo chown "$USER:$USER" /tmp/auth.log

# --- Ingest ---
echo "[*] Ingesting auth.log ..."
sentrylog $VERBOSE ingest /tmp/auth.log --parser authlog

# --- Scan + Report ---
echo "[*] Running detection scan ..."
sentrylog $VERBOSE scan --report

echo ""
echo "[+] Done. Report saved to: $PROJECT_DIR/sentrylog_report_$(date +'%m-%d-%Y').pdf"
