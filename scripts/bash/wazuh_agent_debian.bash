#!/bin/bash
# ============================================================
# Wazuh agent install (offline package)
# OS       : Debian / Ubuntu
# Usage    : Lab / POC / Training
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

require_root

ROLE="Server"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --role)
      ROLE="$2"
      shift 2
      ;;
    --config)
      CONFIG_PATH="$2"
      shift 2
      ;;
    --start-agent)
      START_AGENT="true"
      shift 1
      ;;
    *)
      log_error "Unknown argument: $1"
      exit 1
      ;;
  esac
done

REPO_ROOT="$(get_repo_root)"
CONFIG_PATH="${CONFIG_PATH:-$REPO_ROOT/config/config.json}"
AGENT_PACKAGE="${AGENT_PACKAGE:-$REPO_ROOT/scripts/bash/assets/wazuh/wazuh-agent_4.14.2-1_amd64.deb}"
START_AGENT="${START_AGENT:-false}"

if [[ ! -f "$CONFIG_PATH" ]]; then
  log_error "Config file not found: $CONFIG_PATH"
  exit 1
fi

if [[ ! -f "$AGENT_PACKAGE" ]]; then
  log_error "Wazuh agent package not found: $AGENT_PACKAGE"
  exit 1
fi

case "$ROLE" in
  SIEM|Server)
    ;;
  *)
    log_error "Unsupported role: $ROLE (use SIEM or Server)"
    exit 1
    ;;
esac

WAZUH_MANAGER="$(json_get "$CONFIG_PATH" "SIEM.Networking.IpAddress")"
WAZUH_AGENT_NAME="$(json_get "$CONFIG_PATH" "${ROLE}.Networking.Hostname")"

log_info "Installing Wazuh agent from local package..."
apt-get update
cp "$AGENT_PACKAGE" /tmp/wazuh-agent.deb

WAZUH_MANAGER="$WAZUH_MANAGER" \
WAZUH_AGENT_NAME="$WAZUH_AGENT_NAME" \
apt-get install -y /tmp/wazuh-agent.deb

systemctl daemon-reexec

if [[ "$START_AGENT" == "true" ]]; then
  log_info "Enabling and starting wazuh-agent..."
  systemctl enable wazuh-agent
  systemctl start wazuh-agent
  systemctl status wazuh-agent --no-pager
else
  log_info "Leaving wazuh-agent disabled. Use --start-agent to enable."
  systemctl disable --now wazuh-agent || true
fi

echo "============================================================"
echo "[OK] Wazuh agent installation completed."
echo "Manager    : ${WAZUH_MANAGER}"
echo "Agent name : ${WAZUH_AGENT_NAME}"
echo "============================================================"
