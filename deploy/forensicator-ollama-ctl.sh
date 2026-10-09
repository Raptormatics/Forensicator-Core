#!/usr/bin/env bash
#
# Forensicator Enterprise — privileged Ollama service control.
#
# This is a second, narrowly-scoped entry in the sudoers drop-in alongside
# forensicator-update.sh (see provision.sh) — the app's own service account
# is deliberately locked down (nologin, no shell) and can't install system
# packages, create a systemd unit, or start/stop services itself, so the
# Settings > AI Analysis page's "Install Ollama" / start / stop actions
# invoke this via `sudo`.
#
# Deliberately does NOT reinvent Ollama's own installer: it shells out to
# the official https://ollama.com/install.sh, which already handles systemd
# unit creation, a dedicated `ollama` service user, and CPU/GPU detection
# correctly across distros — duplicating that here would be a maintenance
# liability for no benefit. This script's job is just to gate that behind
# root, report progress the Admin UI can poll, and add start/stop/uninstall/
# status on top.
#
# Usage (as root):
#   forensicator-ollama-ctl.sh install
#   forensicator-ollama-ctl.sh uninstall [--purge-models]
#   forensicator-ollama-ctl.sh start
#   forensicator-ollama-ctl.sh stop
#   forensicator-ollama-ctl.sh status
#
# Writes live progress to PROGRESS_FILE (polled by the Admin UI), matching
# the same JSON shape forensicator-update.sh uses.

set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA_DIR="${APP_DIR}/data"
PROGRESS_FILE="${DATA_DIR}/.ollama-progress.json"
OLLAMA_INSTALL_URL="https://ollama.com/install.sh"

if [[ $EUID -ne 0 ]]; then
  echo "Must be run as root." >&2
  exit 1
fi

mkdir -p "$DATA_DIR"

ACTION="${1:-}"
PURGE_MODELS=0
for arg in "$@"; do
  [[ "$arg" == "--purge-models" ]] && PURGE_MODELS=1
done

if [[ -z "$ACTION" ]]; then
  echo "Usage: $0 install|uninstall [--purge-models]|start|stop|status" >&2
  exit 1
fi

# Same shape/convention as forensicator-update.sh's set_progress/clear_progress
# — includes this script's own PID so the Admin UI can distinguish "still
# running" from "died mid-install" (see src/lib/ai/ollama-service.ts).
set_progress() {
  echo "==> [$1] $2"
  PROGRESS_FILE="$PROGRESS_FILE" STAGE="$1" MSG="$2" PID="$$" node -e '
    const fs = require("fs");
    fs.writeFileSync(process.env.PROGRESS_FILE, JSON.stringify({
      stage: process.env.STAGE, message: process.env.MSG, updatedAt: new Date().toISOString(),
      pid: Number(process.env.PID),
    }, null, 2));
  ' 2>/dev/null || true
}

clear_progress() {
  rm -f "$PROGRESS_FILE"
}

write_result() {
  # $1=success(true/false) $2=action $3=message
  RESULT_FILE="${DATA_DIR}/.ollama-last-result.json" SUCCESS="$1" ACTION="$2" MSG="$3" node -e '
    const fs = require("fs");
    fs.writeFileSync(process.env.RESULT_FILE, JSON.stringify({
      success: process.env.SUCCESS === "true", action: process.env.ACTION,
      message: process.env.MSG, completedAt: new Date().toISOString(),
    }, null, 2));
  ' 2>/dev/null || true
}

ollama_installed() {
  command -v ollama >/dev/null 2>&1
}

service_present() {
  systemctl list-unit-files ollama.service --no-legend 2>/dev/null | grep -q ollama.service
}

case "$ACTION" in
  install)
    if ollama_installed && service_present; then
      set_progress "done" "Ollama is already installed."
      clear_progress
      write_result true install "Already installed — nothing to do."
      exit 0
    fi

    set_progress "install" "Downloading and running the official Ollama installer"
    if ! curl -fsSL "$OLLAMA_INSTALL_URL" | sh; then
      set_progress "failed" "Ollama installer failed — see system log (journalctl) for details."
      clear_progress
      write_result false install "Installer script exited non-zero."
      exit 1
    fi

    set_progress "install" "Enabling and starting the Ollama service"
    systemctl enable ollama.service >/dev/null 2>&1 || true
    systemctl start ollama.service

    set_progress "install" "Waiting for Ollama to come up"
    ok=0
    for _ in $(seq 1 30); do
      if curl -sf "http://127.0.0.1:11434/api/tags" >/dev/null 2>&1; then ok=1; break; fi
      sleep 2
    done

    clear_progress
    if [[ "$ok" -eq 1 ]]; then
      write_result true install "Ollama installed and running."
    else
      write_result false install "Ollama installed but did not respond on 127.0.0.1:11434 within 60s — check 'systemctl status ollama'."
      exit 1
    fi
    ;;

  uninstall)
    set_progress "uninstall" "Stopping Ollama service"
    systemctl stop ollama.service 2>/dev/null || true
    systemctl disable ollama.service 2>/dev/null || true

    set_progress "uninstall" "Removing systemd unit"
    rm -f /etc/systemd/system/ollama.service
    systemctl daemon-reload

    set_progress "uninstall" "Removing Ollama binary"
    rm -f "$(command -v ollama 2>/dev/null || echo /usr/local/bin/ollama)"

    if [[ "$PURGE_MODELS" -eq 1 ]]; then
      set_progress "uninstall" "Removing downloaded models"
      rm -rf /usr/share/ollama/.ollama/models 2>/dev/null || true
      rm -rf /root/.ollama/models 2>/dev/null || true
    fi

    clear_progress
    write_result true uninstall "Ollama removed.$( [[ "$PURGE_MODELS" -eq 1 ]] && echo " Downloaded models were also deleted." )"
    ;;

  start)
    if ! service_present; then
      echo "Ollama service is not installed." >&2
      exit 1
    fi
    systemctl start ollama.service
    write_result true start "Ollama service started."
    ;;

  stop)
    if ! service_present; then
      echo "Ollama service is not installed." >&2
      exit 1
    fi
    systemctl stop ollama.service
    write_result true stop "Ollama service stopped."
    ;;

  status)
    installed="false"; ollama_installed && installed="true"
    active="unknown"
    if service_present; then
      active="$(systemctl is-active ollama.service 2>/dev/null || echo inactive)"
    else
      active="not-installed"
    fi
    version=""
    if ollama_installed; then
      version="$(ollama --version 2>/dev/null | head -n1 || true)"
    fi
    INSTALLED="$installed" ACTIVE="$active" VERSION="$version" node -e '
      console.log(JSON.stringify({
        installed: process.env.INSTALLED === "true",
        active: process.env.ACTIVE,
        version: process.env.VERSION || null,
      }));
    '
    ;;

  *)
    echo "Unknown action: $ACTION" >&2
    exit 1
    ;;
esac
