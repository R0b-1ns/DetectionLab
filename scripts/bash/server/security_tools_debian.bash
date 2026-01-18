#!/bin/bash
# ============================================================
# Security tooling orchestrator (YARA + auditd)
# OS       : Debian / Ubuntu
# Usage    : Lab / POC / Training
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../common/lib/common.sh
source "$SCRIPT_DIR/../common/lib/common.sh"

require_root

REPO_ROOT="$(get_repo_root)"
AUDITD_RULES_DIR="${AUDITD_RULES_DIR:-$REPO_ROOT/config/auditd}"
AUDITD_TARGET_DIR="/etc/audit/rules.d"

APT_UPDATED="false"

ensure_apt_updated() {
  if [[ "$APT_UPDATED" == "false" ]]; then
    apt-get update
    APT_UPDATED="true"
  fi
}

install_auditd() {
  if dpkg -s auditd >/dev/null 2>&1; then
    log_info "auditd is already installed."
    return
  fi

  log_info "Installing auditd..."
  ensure_apt_updated
  apt-get install -y auditd
}

copy_auditd_rules() {
  if [[ ! -d "$AUDITD_RULES_DIR" ]]; then
    log_error "auditd rules directory not found: $AUDITD_RULES_DIR"
    exit 1
  fi

  mkdir -p "$AUDITD_TARGET_DIR"

  shopt -s nullglob
  local rules=("$AUDITD_RULES_DIR"/*.rules)
  shopt -u nullglob

  if [[ ${#rules[@]} -eq 0 ]]; then
    log_info "No auditd rules found in $AUDITD_RULES_DIR"
    return
  fi

  local updated="false"

  for rule in "${rules[@]}"; do
    local dest="$AUDITD_TARGET_DIR/$(basename "$rule")"
    if [[ -f "$dest" ]]; then
      log_info "auditd rule already present: $dest"
      continue
    fi
    log_info "Installing auditd rule: $dest"
    cp "$rule" "$dest"
    chmod 640 "$dest"
    updated="true"
  done

  if [[ "$updated" == "true" ]]; then
    if command -v augenrules >/dev/null 2>&1; then
      log_info "Reloading auditd rules with augenrules..."
      augenrules --load
    fi
  fi
}

install_auditd

log_info "Launching YARA installer..."
"$SCRIPT_DIR/yara_debian.bash"

log_info "Deploying auditd rules..."
copy_auditd_rules

log_info "Enabling auditd..."
systemctl enable --now auditd
systemctl status auditd --no-pager

log_info "Security tooling installation completed."
