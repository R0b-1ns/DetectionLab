#!/bin/bash
# ============================================================
# YARA install and rule deployment
# OS       : Debian / Ubuntu
# Usage    : Lab / POC / Training
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../common/lib/common.sh
source "$SCRIPT_DIR/../common/lib/common.sh"

require_root

REPO_ROOT="$(get_repo_root)"
YARA_RULES_DIR="${YARA_RULES_DIR:-$REPO_ROOT/config/yara}"
YARA_TARGET_DIR="/etc/yara/rules"
YARA_LOG_DIR="/var/log/yara"
YARA_SERVICE="/etc/systemd/system/detectionlab-yara.service"
YARA_TIMER="/etc/systemd/system/detectionlab-yara.timer"
YARA_SCAN_PATH="${YARA_SCAN_PATH:-/var/www}"
YARA_LOG_FILE="$YARA_LOG_DIR/yara.log"

APT_UPDATED="false"

ensure_apt_updated() {
  if [[ "$APT_UPDATED" == "false" ]]; then
    apt-get update
    APT_UPDATED="true"
  fi
}

install_yara() {
  if command -v yara >/dev/null 2>&1; then
    log_info "YARA is already installed."
    return
  fi

  log_info "Installing YARA..."
  ensure_apt_updated
  apt-get install -y yara
}

copy_yara_rules() {
  if [[ ! -d "$YARA_RULES_DIR" ]]; then
    log_error "YARA rules directory not found: $YARA_RULES_DIR"
    exit 1
  fi

  mkdir -p "$YARA_TARGET_DIR"

  shopt -s nullglob
  local rules=("$YARA_RULES_DIR"/*.yar)
  shopt -u nullglob

  if [[ ${#rules[@]} -eq 0 ]]; then
    log_info "No YARA rules found in $YARA_RULES_DIR"
    return
  fi

  for rule in "${rules[@]}"; do
    local dest="$YARA_TARGET_DIR/$(basename "$rule")"
    if [[ -f "$dest" ]]; then
      log_info "YARA rule already present: $dest"
      continue
    fi
    log_info "Installing YARA rule: $dest"
    cp "$rule" "$dest"
    chmod 640 "$dest"
  done
}

configure_yara_scan() {
  mkdir -p "$YARA_LOG_DIR"
  chmod 750 "$YARA_LOG_DIR"

  if [[ ! -f "$YARA_SERVICE" ]]; then
    log_info "Creating YARA systemd service..."
    cat > "$YARA_SERVICE" <<EOF
[Unit]
Description=DetectionLab YARA scan on ${YARA_SCAN_PATH}
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/bin/yara -r ${YARA_TARGET_DIR} ${YARA_SCAN_PATH} >> ${YARA_LOG_FILE}
EOF
  else
    log_info "YARA systemd service already present."
  fi

  if [[ ! -f "$YARA_TIMER" ]]; then
    log_info "Creating YARA systemd timer..."
    cat > "$YARA_TIMER" <<'EOY'
[Unit]
Description=Run DetectionLab YARA scan daily

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
EOY
  else
    log_info "YARA systemd timer already present."
  fi

  systemctl daemon-reload
  systemctl enable --now detectionlab-yara.timer
}

install_yara
log_info "Deploying YARA rules..."
copy_yara_rules
configure_yara_scan

log_info "YARA installation completed."
