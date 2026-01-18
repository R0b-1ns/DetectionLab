#!/bin/bash
# ============================================================
# Wazuh All-in-One installer (offline script)
# OS       : Ubuntu Server
# Version  : Wazuh 4.14.x
# Mode     : Manager + Indexer + Dashboard
# Usage    : Lab / SOC / Training
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

require_root

REPO_ROOT="$(get_repo_root)"
INSTALLER_SOURCE="${INSTALLER_SOURCE:-$REPO_ROOT/scripts/bash/assets/wazuh/wazuh-install.sh}"
INSTALLER_TARGET="/root/wazuh-install.sh"

if [[ ! -f "$INSTALLER_SOURCE" ]]; then
  log_error "Wazuh installer not found: $INSTALLER_SOURCE"
  exit 1
fi

log_info "Copying Wazuh installer from repo..."
cp "$INSTALLER_SOURCE" "$INSTALLER_TARGET"
chmod +x "$INSTALLER_TARGET"

log_info "Launching Wazuh All-in-One installer..."
bash "$INSTALLER_TARGET" -a

log_info "Checking Wazuh services..."
systemctl status wazuh-manager --no-pager
systemctl status wazuh-indexer --no-pager
systemctl status wazuh-dashboard --no-pager

LOG_FILE="/root/.wazuh-installation.log"

echo ""
echo "============================================================"
echo " Wazuh access information"
echo "============================================================"

if [[ -f "$LOG_FILE" ]]; then
  ADMIN_USER=$(grep -i "User:" "$LOG_FILE" | awk '{print $2}')
  ADMIN_PASS=$(grep -i "Password:" "$LOG_FILE" | awk '{print $2}')
  SERVER_IP=$(hostname -I | awk '{print $1}')

  echo "Dashboard URL : https://$SERVER_IP"
  echo "Username      : $ADMIN_USER"
  echo "Password      : $ADMIN_PASS"
else
  log_error "Log file not found: $LOG_FILE"
  echo "Unable to retrieve the admin password automatically."
fi

echo "============================================================"
echo "[OK] Wazuh All-in-One installation completed."
echo "============================================================"
